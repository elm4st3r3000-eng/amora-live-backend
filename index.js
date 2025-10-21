// server/index.js
import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import fs from "fs";
import admin from "firebase-admin";
import Stripe from "stripe";
import pkg from "agora-access-token";
const { RtcTokenBuilder, RtcRole } = pkg;
import paypal from "@paypal/checkout-server-sdk";

dotenv.config();

// ------------------------------------------------------------
// Config básica
// ------------------------------------------------------------
const PORT = process.env.PORT || 4000;
const app = express();

// ------------------------------------------------------------
// Inicializar Firebase Admin
// ------------------------------------------------------------
let serviceAccount = null;
try {
  const localPath = "./serviceAccountKey.json";
  const renderPath = "/etc/secrets/serviceAccountKey.json";
  const pathToUse = fs.existsSync(renderPath) ? renderPath : localPath;

  if (!fs.existsSync(pathToUse)) {
    throw new Error(`No se encontró serviceAccountKey en ${pathToUse}`);
  }

  const raw = fs.readFileSync(pathToUse, "utf8");
  serviceAccount = JSON.parse(raw);

  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
  });

  console.log("✅ Firebase Admin inicializado desde:", pathToUse);
} catch (e) {
  console.error("❌ Error al cargar credenciales Firebase:", e.message || e);
  serviceAccount = null;
  console.warn("⚠️ Firebase admin no inicializado: algunas rutas requerirán Firestore.");
}

const db = admin.firestore ? admin.firestore() : null;

// ------------------------------------------------------------
// Middlewares
// ------------------------------------------------------------
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(
  cors({
    origin: [
      "https://amora-live-famous.netlify.app",
      "http://localhost:3000",
    ],
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true,
  })
);

app.options("*", (req, res) => res.sendStatus(200));

// ------------------------------------------------------------
// Middleware: verificar idToken de Firebase
// ------------------------------------------------------------
async function verifyAuth(req, res, next) {
  try {
    const authHeader = req.headers.authorization || "";
    if (!authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ error: "Token no proporcionado" });
    }
    const idToken = authHeader.split("Bearer ")[1];
    if (!admin.apps.length) {
      return res.status(500).json({ error: "Servicio de autenticación no disponible" });
    }
    const decoded = await admin.auth().verifyIdToken(idToken);
    req.user = decoded;
    next();
  } catch (error) {
    console.error("❌ Error de autenticación:", error.message || error);
    return res.status(401).json({ error: "Token inválido o expirado" });
  }
}

// ------------------------------------------------------------
// Stripe / PayPal / Constantes
// ------------------------------------------------------------
const stripe = Stripe(process.env.STRIPE_SECRET_KEY || "");

const paypalEnv =
  process.env.PAYPAL_MODE === "live"
    ? new paypal.core.LiveEnvironment(process.env.PAYPAL_CLIENT_ID, process.env.PAYPAL_SECRET)
    : new paypal.core.SandboxEnvironment(process.env.PAYPAL_CLIENT_ID, process.env.PAYPAL_SECRET);

const paypalClient = new paypal.core.PayPalHttpClient(paypalEnv);

const COINS_PER_USD = Number(process.env.COINS_PER_USD || 8);
const COIN_SECONDS = Number(process.env.COIN_SECONDS || 2);
const HOST_SHARE = Number(process.env.HOST_SHARE || 0.5);
const AMORA_SHARE = Number(process.env.AMORA_SHARE || 0.5);

function coinsCostForSeconds(seconds) {
  return Math.ceil(seconds / COIN_SECONDS);
}

// ------------------------------------------------------------
// RUTAS
// ------------------------------------------------------------

// Root health
app.get("/", (req, res) => {
  res.send("✅ Servidor Amora Live está funcionando correctamente.");
});

// ------------------------------------------------------------
// Bono diario
app.post("/user/claim-daily-bonus", verifyAuth, async (req, res) => {
  try {
    if (!db) return res.status(500).json({ error: "Firestore no inicializado" });

    const uid = req.user.uid;
    const userRef = db.collection("users").doc(uid);
    const uSnap = await userRef.get();
    if (!uSnap.exists) return res.status(404).json({ error: "Usuario no encontrado" });
    const user = uSnap.data();

    let createdAt = user.createdAt;
    if (!createdAt) {
      await userRef.update({ createdAt: admin.firestore.FieldValue.serverTimestamp() });
      createdAt = admin.firestore.Timestamp.fromDate(new Date());
    }

    const createdDate = createdAt.toDate ? createdAt.toDate() : new Date(createdAt);
    const now = new Date();
    const diffDays = Math.floor((now - createdDate) / (1000 * 60 * 60 * 24)) + 1;

    if (diffDays > 3) return res.status(400).json({ error: "Periodo de bonos expirado (3 días)" });
    if (user.lastBonusDay && user.lastBonusDay >= diffDays) return res.status(400).json({ error: "Bono ya reclamado hoy" });

    let bonus = { coins: 0, freeCallSeconds: 0, freeLiveSeconds: 0 };
    if (diffDays === 1) bonus = { coins: 5, freeCallSeconds: 20, freeLiveSeconds: 60 };
    else if (diffDays === 2) bonus = { coins: 3, freeCallSeconds: 10, freeLiveSeconds: 30 };
    else if (diffDays === 3) bonus = { coins: 1, freeCallSeconds: 5, freeLiveSeconds: 15 };

    const expiry = new Date(createdDate.getTime() + 3 * 24 * 60 * 60 * 1000);
    await userRef.update({
      coins: admin.firestore.FieldValue.increment(bonus.coins),
      freeCallSeconds: admin.firestore.FieldValue.increment(bonus.freeCallSeconds),
      freeLiveSeconds: admin.firestore.FieldValue.increment(bonus.freeLiveSeconds),
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

    res.json({ ok: true, bonus, day: diffDays, expiresAt: expiry });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

// ------------------------------------------------------------
// Bono inicial
app.post("/user/grant-initial-bonus", verifyAuth, async (req, res) => {
  try {
    if (!db) return res.status(500).json({ error: "Firestore no inicializado" });

    const uid = req.user.uid;
    const userRef = db.collection("users").doc(uid);
    const uSnap = await userRef.get();
    if (!uSnap.exists) return res.status(404).json({ error: "Usuario no encontrado" });
    const user = uSnap.data();

    if (user.initialBonusGranted) return res.status(400).json({ error: "Bono inicial ya otorgado" });

    const initialCoins = Number(process.env.INITIAL_BONUS_COINS || 0);
    const initialFreeCallSeconds = Number(process.env.INITIAL_FREE_CALL_SECONDS || 0);
    const initialFreeLiveSeconds = Number(process.env.INITIAL_FREE_LIVE_SECONDS || 0);

    if (initialCoins === 0 && initialFreeCallSeconds === 0 && initialFreeLiveSeconds === 0) {
      return res.status(200).json({ ok: true, message: "No hay bono inicial configurado." });
    }

    const updates = {};
    if (initialCoins > 0) updates.coins = admin.firestore.FieldValue.increment(initialCoins);
    if (initialFreeCallSeconds > 0) updates.freeCallSeconds = admin.firestore.FieldValue.increment(initialFreeCallSeconds);
    if (initialFreeLiveSeconds > 0) updates.freeLiveSeconds = admin.firestore.FieldValue.increment(initialFreeLiveSeconds);

    await userRef.update({
      ...updates,
      initialBonusGranted: true,
      initialBonusAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    await db.collection("transactions").add({
      uid,
      type: "initial_bonus",
      coins: initialCoins,
      freeCallSeconds: initialFreeCallSeconds,
      freeLiveSeconds: initialFreeLiveSeconds,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    res.json({
      ok: true,
      granted: { coins: initialCoins, freeCallSeconds: initialFreeCallSeconds, freeLiveSeconds: initialFreeLiveSeconds },
    });
  } catch (e) {
    console.error("❌ Error en /user/grant-initial-bonus:", e);
    res.status(500).json({ error: e.message });
  }
});

// ------------------------------------------------------------
// Llamadas 1 a 1
app.post("/call/use", verifyAuth, async (req, res) => {
  try {
    if (!db) return res.status(500).json({ error: "Firestore no inicializado" });

    const { callerId, calleeId, secondsUsed } = req.body;
    if (!callerId || !calleeId || !secondsUsed)
      return res.status(400).json({ error: "Faltan parámetros" });

    if (callerId !== req.user.uid)
      return res.status(403).json({ error: "callerId no coincide con usuario autenticado" });

    const callerRef = db.collection("users").doc(callerId);
    const callerSnap = await callerRef.get();
    if (!callerSnap.exists) return res.status(404).json({ error: "Caller no encontrado" });
    const caller = callerSnap.data();

    if (caller.bonusExpiry && caller.bonusExpiry.toDate && new Date() > caller.bonusExpiry.toDate()) {
      await callerRef.update({
        freeCallSeconds: 0,
        freeLiveSeconds: 0,
        bonusExpiry: admin.firestore.FieldValue.delete(),
      });
    }

    let remaining = secondsUsed;
    let freeConsumed = 0;
    let coinsCharged = 0;

    const availableFree = caller.freeCallSeconds || 0;
    if (availableFree > 0) {
      const useFree = Math.min(availableFree, remaining);
      await callerRef.update({ freeCallSeconds: admin.firestore.FieldValue.increment(-useFree) });
      remaining -= useFree;
      freeConsumed = useFree;
    }

    if (remaining > 0) {
      coinsCharged = coinsCostForSeconds(remaining);
      if ((caller.coins || 0) < coinsCharged) {
        return res.status(400).json({ error: "Saldo insuficiente", required: coinsCharged });
      }

      await callerRef.update({ coins: (caller.coins || 0) - coinsCharged });

      const calleeRef = db.collection("users").doc(calleeId);
      const calleeSnap = await calleeRef.get();
      if (calleeSnap.exists) {
        const hostEarn = Math.round(coinsCharged * HOST_SHARE);
        await calleeRef.update({
          earnedCoins: (calleeSnap.data().earnedCoins || 0) + hostEarn,
        });
      }

      await db.collection("transactions").add({
        uid: callerId,
        calleeId,
        type: "call_charge",
        secondsCharged: remaining,
        coinsCharged,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
      });
    }

    res.json({ ok: true, freeConsumed, coinsCharged });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

// ------------------------------------------------------------
// Confirmar pago
app.post("/payment/confirm", verifyAuth, async (req, res) => {
  try {
    if (!db) return res.status(500).json({ error: "Firestore no inicializado" });

    const { uid, amount, method } = req.body;
    if (!uid || !amount || !method) {
      return res.status(400).json({ error: "Faltan parámetros" });
    }

    if (uid !== req.user.uid) return res.status(403).json({ error: "UID no coincide" });

    const coinsToAdd = Number(amount) * COINS_PER_USD;
    const userRef = db.collection("users").doc(uid);
    await userRef.update({ coins: admin.firestore.FieldValue.increment(coinsToAdd) });

    await db.collection("transactions").add({
      uid,
      amount,
      coins: coinsToAdd,
      type: `${method}_topup`,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    res.json({ ok: true, coinsToAdd });
  } catch (e) {
    console.error("❌ Error en /payment/confirm:", e);
    res.status(500).json({ error: e.message });
  }
});

// ------------------------------------------------------------
// Stripe y PayPal
app.post("/payment/create-session", verifyAuth, async (req, res) => {
  try {
    const { amount, uid } = req.body;
    if (!amount || !uid) return res.status(400).json({ error: "Faltan parámetros" });
    if (uid !== req.user.uid) return res.status(403).json({ error: "UID no coincide" });

    const session = await stripe.checkout.sessions.create({
      payment_method_types: ["card"],
      line_items: [
        {
          price_data: {
            currency: "usd",
            product_data: {
              name: `${amount * COINS_PER_USD} monedas Amora Live`,
              description: "Recarga de monedas para llamadas y salas en vivo",
            },
            unit_amount: amount * 100,
          },
          quantity: 1,
        },
      ],
      mode: "payment",
      success_url: `${process.env.FRONTEND_URL}/coins?success=true&uid=${uid}&amount=${amount}`,
      cancel_url: `${process.env.FRONTEND_URL}/coins?cancel=true`,
      metadata: { uid, amount },
    });

    res.json({ url: session.url });
  } catch (e) {
    console.error("❌ Error creando sesión Stripe:", e.message || e);
    res.status(500).json({ error: e.message });
  }
});

app.post("/payment/create-order", verifyAuth, async (req, res) => {
  try {
    const { amount, uid } = req.body;
    if (!amount || !uid) return res.status(400).json({ error: "Faltan parámetros" });
    if (uid !== req.user.uid) return res.status(403).json({ error: "UID no coincide" });

    const request = new paypal.orders.OrdersCreateRequest();
    request.prefer("return=representation");
    request.requestBody({
      intent: "CAPTURE",
      purchase_units: [
        {
          amount: { currency_code: "USD", value: amount.toString() },
          description: `${amount * COINS_PER_USD} monedas Amora Live`,
        },
      ],
      application_context: {
        return_url: `${process.env.FRONTEND_URL}/coins?paypal_success=true&uid=${uid}&amount=${amount}`,
        cancel_url: `${process.env.FRONTEND_URL}/coins?paypal_cancel=true`,
      },
    });

    const order = await paypalClient.execute(request);
    res.json({ id: order.result.id, links: order.result.links });
  } catch (e) {
    console.error("❌ Error creando orden PayPal:", e.message || e);
    res.status(500).json({ error: e.message });
  }
});

// ------------------------------------------------------------
// NUEVA RUTA: /charge (compatible frontend antiguo)
app.post("/charge", verifyAuth, async (req, res) => {
  try {
    const { amount, uid, method } = req.body;
    if (!amount || !uid || !method) return res.status(400).json({ error: "Faltan parámetros" });
    if (uid !== req.user.uid) return res.status(403).json({ error: "UID no coincide" });

    if (method === "stripe") {
      const session = await stripe.checkout.sessions.create({
        payment_method_types: ["card"],
        line_items: [
          {
            price_data: {
              currency: "usd",
              product_data: { name: `${amount*COINS_PER_USD} monedas` },
              unit_amount: amount*100,
            },
            quantity: 1
          }
        ],
        mode: "payment",
        success_url: `${process.env.FRONTEND_URL}/coins?success=true&uid=${uid}&amount=${amount}`,
        cancel_url: `${process.env.FRONTEND_URL}/coins?cancel=true`
      });
      return res.json({ url: session.url });
    }

    if (method === "paypal") {
      const request = new paypal.orders.OrdersCreateRequest();
      request.prefer("return=representation");
      request.requestBody({
        intent: "CAPTURE",
        purchase_units: [{ amount: { currency_code: "USD", value: amount.toString() } }],
        application_context: {
          return_url: `${process.env.FRONTEND_URL}/coins?paypal_success=true&uid=${uid}&amount=${amount}`,
          cancel_url: `${process.env.FRONTEND_URL}/coins?paypal_cancel=true`
        }
      });
      const order = await paypalClient.execute(request);
      return res.json({ id: order.result.id, links: order.result.links });
    }

    res.status(400).json({ error: "Método de pago inválido" });

  } catch (e) {
    console.error("❌ Error en /charge:", e.message || e);
    res.status(500).json({ error: e.message });
  }
});

// ------------------------------------------------------------
// Agora Token
app.get("/agora/token", async (req, res) => {
  try {
    const channel = req.query.channelName || req.query.channel;
    const uid = req.query.uid;

    if (!channel) return res.status(400).json({ error: "Falta parámetro channelName (o channel)" });
    if (!uid) return res.status(400).json({ error: "Falta parámetro uid" });

    const appID = process.env.AGORA_APP_ID;
    const appCertificate = process.env.AGORA_APP_CERT || process.env.AGORA_APP_CERTIFICATE;

    if (!appID || !appCertificate) return res.status(500).json({ error: "Faltan credenciales de Agora" });

    const role = RtcRole.PUBLISHER;
    const expirationTimeInSeconds = Number(process.env.AGORA_TOKEN_EXPIRES || 3600);
    const currentTimestamp = Math.floor(Date.now() / 1000);
    const privilegeExpiredTs = currentTimestamp + expirationTimeInSeconds;

    let token;
    const maybeNum = Number(uid);
    if (!Number.isNaN(maybeNum) && String(maybeNum) === String(uid)) {
      token = RtcTokenBuilder.buildTokenWithUid(appID, appCertificate, channel, parseInt(uid, 10), role, privilegeExpiredTs);
    } else if (typeof RtcTokenBuilder.buildTokenWithUserAccount === "function") {
      token = RtcTokenBuilder.buildTokenWithUserAccount(appID, appCertificate, channel, uid, role, privilegeExpiredTs);
    } else {
      return res.status(400).json({ error: "UID no numérico y buildTokenWithUserAccount no disponible" });
    }

    return res.json({ token, expiresAt: privilegeExpiredTs });
  } catch (e) {
    console.error("❌ Error en /agora/token:", e.message || e);
    return res.status(500).json({ error: e.message || "Error interno" });
  }
});

// ------------------------------------------------------------
// Live Rooms
app.get("/liveRooms", async (req, res) => {
  try {
    if (!db) return res.json([]);
    const snaps = await db.collection("liveRooms").where("isActive", "==", true).get();
    const rooms = [];
    snaps.forEach((s) => rooms.push({ id: s.id, ...s.data() }));
    res.json(rooms);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post("/live/create", verifyAuth, async (req, res) => {
  try {
    if (!db) return res.status(500).json({ error: "Firestore no inicializado" });

    const { hostId, hostName, hostGender, entryPrice } = req.body;
    if (hostId !== req.user.uid) return res.status(403).json({ error: "hostId no coincide" });

    const docRef = await db.collection("liveRooms").add({
      hostId, hostName, hostGender, entryPrice,
      viewers: [],
      startTime: admin.firestore.FieldValue.serverTimestamp(),
      isActive: true,
    });

    res.json({ id: docRef.id });
  } catch (e) {
    console.error("❌ Error al crear sala:", e);
    res.status(500).json({ error: e.message });
  }
});

app.post("/live/enter", verifyAuth, async (req, res) => {
  try {
    if (!db) return res.status(500).json({ error: "Firestore no inicializado" });

    const { roomId } = req.body;
    const uid = req.user.uid;
    if (!roomId) return res.status(400).json({ error: "roomId requerido" });

    const roomRef = db.collection("liveRooms").doc(roomId);
    const snap = await roomRef.get();
    if (!snap.exists) return res.status(404).json({ error: "Sala no existe" });
    const room = snap.data();

    if ((room.entryPrice || 0) > 0) {
      const userRef = db.collection("users").doc(uid);
      const uSnap = await userRef.get();
      if (!uSnap.exists) return res.status(400).json({ error: "Usuario no existe" });
      const user = uSnap.data();
      if ((user.coins || 0) < (room.entryPrice || 0)) return res.status(400).json({ error: "Saldo insuficiente" });

      await userRef.update({ coins: (user.coins || 0) - (room.entryPrice || 0) });

      const hostRef = db.collection("users").doc(room.hostId);
      const hostSnap = await hostRef.get();
      const hostEarn = Math.round((room.entryPrice || 0) * HOST_SHARE);
      const amoraEarn = (room.entryPrice || 0) - hostEarn;

      await hostRef.update({ earnedCoins: (hostSnap.data().earnedCoins || 0) + hostEarn });

      await db.collection("transactions").add({
        uid,
        amount: room.entryPrice,
        hostEarn,
        amoraEarn,
        type: "enter_live_50_50",
        roomId,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
      });
    }

    const viewers = room.viewers || [];
    if (!viewers.includes(uid)) viewers.push(uid);
    await roomRef.update({ viewers });

    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

// ------------------------------------------------------------
// START
app.listen(PORT, () => {
  console.log(`✅ Servidor Amora Live ejecutándose en el puerto ${PORT}`);
});
