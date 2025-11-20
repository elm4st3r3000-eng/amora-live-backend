// ============================================================
//  AMORA LIVE - BACKEND SERVER (VERSION CORREGIDA COMPLETA)
// ============================================================

import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import fs from "fs";
import admin from "firebase-admin";
import Stripe from "stripe";
import paypal from "@paypal/checkout-server-sdk";
import bodyParser from "body-parser";
const { raw } = bodyParser;
import pkg from "agora-access-token";
const { RtcTokenBuilder, RtcRole } = pkg;

dotenv.config();
const PORT = process.env.PORT || 4000;

// ============================================================
//  FIREBASE ADMIN
// ============================================================

let serviceAccount;

try {
  const localPath = "./serviceAccountKey.json";
  const renderPath = "/etc/secrets/serviceAccountKey.json";
  const pathToUse = fs.existsSync(renderPath) ? renderPath : localPath;

  serviceAccount = JSON.parse(fs.readFileSync(pathToUse, "utf8"));
} catch (e) {
  console.error("❌ Error al cargar credenciales Firebase:", e.message);
  process.exit(1);
}

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});
const db = admin.firestore();

// ============================================================
//  AUTH MIDDLEWARE
// ============================================================

async function verifyAuth(req, res, next) {
  try {
    const authHeader = req.headers.authorization || "";
    if (!authHeader.startsWith("Bearer "))
      return res.status(401).json({ error: "Token no proporcionado" });

    const idToken = authHeader.split("Bearer ")[1];
    const decoded = await admin.auth().verifyIdToken(idToken);

    req.user = decoded;
    next();
  } catch (err) {
    console.error("❌ Error autenticación:", err.message);
    res.status(401).json({ error: "Token inválido o expirado" });
  }
}

// ============================================================
//  ECONOMÍA / STRIPE / PAYPAL
// ============================================================

const stripe = Stripe(process.env.STRIPE_SECRET_KEY);

const paypalEnv =
  process.env.PAYPAL_MODE === "live"
    ? new paypal.core.LiveEnvironment(
        process.env.PAYPAL_CLIENT_ID,
        process.env.PAYPAL_SECRET
      )
    : new paypal.core.SandboxEnvironment(
        process.env.PAYPAL_CLIENT_ID,
        process.env.PAYPAL_SECRET
      );

const paypalClient = new paypal.core.PayPalHttpClient(paypalEnv);

const COINS_PER_USD = Number(process.env.COINS_PER_USD || 8);
const COIN_SECONDS = Number(process.env.COIN_SECONDS || 2);
const HOST_SHARE = Number(process.env.HOST_SHARE || 0.5);

// ============================================================
//  EXPRESS APP
// ============================================================

const app = express();

app.use(
  cors({
    origin: [
      "https://amora-live-famous.netlify.app",
      "http://localhost:3000",
      "https://super-academia-musical.netlify.app"
    ],
    methods: ["GET", "POST"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true,
  })
);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ============================================================
//  RUTA: GET USER INFO PARA COINS.JS
// ============================================================

app.get("/user/me", verifyAuth, async (req, res) => {
  try {
    const uid = req.user.uid;
    const snap = await db.collection("users").doc(uid).get();

    if (!snap.exists)
      return res.status(404).json({ error: "Usuario no encontrado" });

    res.json(snap.data());
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
//  BONO DIARIO
// ============================================================

app.post("/user/claim-daily-bonus", verifyAuth, async (req, res) => {
  try {
    const uid = req.user.uid;
    const userRef = db.collection("users").doc(uid);
    const uSnap = await userRef.get();
    if (!uSnap.exists)
      return res.status(404).json({ error: "Usuario no encontrado" });

    const user = uSnap.data();
    let createdAt = user.createdAt;

    if (!createdAt) {
      await userRef.update({
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
      });
      createdAt = admin.firestore.Timestamp.fromDate(new Date());
    }

    const createdDate =
      createdAt.toDate?.() || new Date(createdAt);
    const now = new Date();

    const diffDays =
      Math.floor((now - createdDate) / (1000 * 60 * 60 * 24)) +
      1;

    if (diffDays > 3)
      return res
        .status(400)
        .json({ error: "Periodo de bonos expirado" });

    if (user.lastBonusDay >= diffDays)
      return res.status(400).json({ error: "Ya reclamado" });

    let bonus = { coins: 0, freeCallSeconds: 0, freeLiveSeconds: 0 };
    if (diffDays === 1)
      bonus = { coins: 5, freeCallSeconds: 20, freeLiveSeconds: 60 };
    if (diffDays === 2)
      bonus = { coins: 3, freeCallSeconds: 10, freeLiveSeconds: 30 };
    if (diffDays === 3)
      bonus = { coins: 1, freeCallSeconds: 5, freeLiveSeconds: 15 };

    const expiry = new Date(
      createdDate.getTime() + 3 * 24 * 60 * 60 * 1000
    );

    await userRef.update({
      coins: admin.firestore.FieldValue.increment(bonus.coins),
      freeCallSeconds:
        admin.firestore.FieldValue.increment(bonus.freeCallSeconds),
      freeLiveSeconds:
        admin.firestore.FieldValue.increment(bonus.freeLiveSeconds),
      lastBonusDay: diffDays,
      bonusExpiry: admin.firestore.Timestamp.fromDate(expiry),
    });

    await db.collection("transactions").add({
      uid,
      type: "daily_bonus",
      bonus,
      day: diffDays,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    res.json({
      ok: true,
      bonus,
      day: diffDays,
      expiresAt: expiry,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
//  STRIPE → CREAR SESIÓN DE CHECKOUT
// ============================================================

app.post("/payment/create-session", verifyAuth, async (req, res) => {
  try {
    const { amount, uid } = req.body;

    if (uid !== req.user.uid)
      return res.status(403).json({ error: "UID inválido" });

    const session = await stripe.checkout.sessions.create({
      payment_method_types: ["card"],
      line_items: [
        {
          price_data: {
            currency: "usd",
            product_data: {
              name: `${amount * COINS_PER_USD} monedas Amora Live`,
            },
            unit_amount: amount * 100,
          },
          quantity: 1,
        },
      ],
      mode: "payment",
      success_url: `${process.env.FRONTEND_URL}/coins?success=true`,
      cancel_url: `${process.env.FRONTEND_URL}/coins?cancel=true`,
      metadata: { uid, amount },
    });

    res.json({ url: session.url });
  } catch (err) {
    console.error("❌ Error Stripe:", err.message);
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
//  AGORA TOKEN
// ============================================================

function numericUidFromFirebase(uid) {
  let hash = 0;
  for (let i = 0; i < uid.length; i++)
    hash = (hash * 31 + uid.charCodeAt(i)) >>> 0;
  return hash % 1000000000;
}

app.all("/agora/token", verifyAuth, (req, res) => {
  try {
    const channel =
      req.body.channel ||
      req.body.channelName ||
      req.query.channel ||
      req.query.channelName;

    if (!channel)
      return res.status(400).json({ error: "Falta channelName" });

    const firebaseUid = req.user.uid;
    const agoraUid = numericUidFromFirebase(firebaseUid);

    const role =
      req.body.role === "host"
        ? RtcRole.PUBLISHER
        : RtcRole.SUBSCRIBER;

    const expiration = Math.floor(Date.now() / 1000) + 3600;

    const token = RtcTokenBuilder.buildTokenWithUid(
      process.env.AGORA_APP_ID,
      process.env.AGORA_APP_CERTIFICATE,
      channel,
      agoraUid,
      role,
      expiration
    );

    res.json({
      ok: true,
      token,
      channel,
      uid: agoraUid,
      firebaseUid,
      role,
    });
  } catch (err) {
    console.error("❌ Agora:", err.message);
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
//  START
// ============================================================

app.get("/", (req, res) => {
  res.send("✅ Servidor Amora Live funcionando.");
});

// ============================================================
//  WEBHOOK STRIPE (RAW BODY REQUIRED)
// ============================================================

app.post("/webhook/stripe", raw({ type: "application/json" }), async (req, res) => {
  try {
    const event = stripe.webhooks.constructEvent(
      req.body,
      req.headers["stripe-signature"],
      process.env.STRIPE_WEBHOOK_SECRET
    );

    if (event.type === "checkout.session.completed") {
      const session = event.data.object;
      const uid = session.metadata.uid;
      const amount = Number(session.metadata.amount);
      const coins = Math.round(amount * COINS_PER_USD);

      const userRef = db.collection("users").doc(uid);

      await db.runTransaction(async (t) => {
        const snap = await t.get(userRef);
        t.update(userRef, {
          coins: (snap.data().coins || 0) + coins,
        });
      });

      await db.collection("transactions").add({
        uid,
        amount,
        coins,
        type: "stripe_topup",
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
      });

      console.log(`💰 Recarga Stripe aplicada a ${uid}`);
    }

    res.json({ received: true });
  } catch (err) {
    console.error("❌ Webhook Stripe:", err.message);
    res.status(400).send(err.message);
  }
});

// ============================================================
//  RUN SERVER
// ============================================================

app.listen(PORT, () =>
  console.log(`🚀 Amora Live corriendo en puerto ${PORT}`)
);
