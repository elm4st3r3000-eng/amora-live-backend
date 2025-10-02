






/* ============================================================
   🚀 START SERVER
============================================================ */
app.listen(PORT, () => console.log("✅ Amora Live server running on port", PORT));



// server/index.js
import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import admin from "firebase-admin";
import Stripe from "stripe";
import bodyParser from "body-parser";
import fs from "fs";
import pkg from "agora-access-token";
const { RtcTokenBuilder, RtcRole } = pkg;
import paypal from "@paypal/checkout-server-sdk";

dotenv.config();
const PORT = process.env.PORT || 4000;

/* ============================================================
   🔥 FIREBASE ADMIN
============================================================ */
const servicePath = process.env.FIREBASE_SERVICE_ACCOUNT_PATH || "./serviceAccountKey.json";
if (!fs.existsSync(servicePath)) {
  console.warn("⚠️ serviceAccountKey.json not found.");
}
const serviceAccount = JSON.parse(fs.readFileSync(servicePath, "utf8"));
admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
const db = admin.firestore();

/* ============================================================
   🛡️ Middleware: verificar idToken de Firebase
============================================================ */
async function verifyAuth(req, res, next) {
  try {
    const authHeader = req.headers.authorization || "";
    if (!authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ error: "Token no proporcionado" });
    }
    const idToken = authHeader.split("Bearer ")[1];
    const decoded = await admin.auth().verifyIdToken(idToken);
    req.user = decoded;
    next();
  } catch (error) {
    console.error("❌ Error de autenticación:", error.message);
    return res.status(401).json({ error: "Token inválido o expirado" });
  }
}

/* ============================================================
   💳 STRIPE
============================================================ */
const stripe = Stripe(process.env.STRIPE_SECRET_KEY);

/* ============================================================
   💳 PAYPAL
============================================================ */
const paypalEnv = process.env.PAYPAL_MODE === "live"
  ? new paypal.core.LiveEnvironment(process.env.PAYPAL_CLIENT_ID, process.env.PAYPAL_SECRET)
  : new paypal.core.SandboxEnvironment(process.env.PAYPAL_CLIENT_ID, process.env.PAYPAL_SECRET);
const paypalClient = new paypal.core.PayPalHttpClient(paypalEnv);

/* ============================================================
   💰 MODELO ECONÓMICO
============================================================ */
const COINS_PER_USD = 8;   // 1 USD = 8 coins
const COIN_SECONDS = 2;    // 1 coin = 2 segundos
const HOST_SHARE = 0.5;
const AMORA_SHARE = 0.5;

function coinsCostForSeconds(seconds) {
  return Math.ceil(seconds / COIN_SECONDS);
}

const app = express();
app.use(cors());
app.use(bodyParser.json());

/* ============================================================
   🎁 BONO DIARIO
============================================================ */
app.post("/user/claim-daily-bonus", verifyAuth, async (req, res) => {
  try {
    const { uid } = req.body;
    if (!uid) return res.status(400).json({ error: "UID requerido" });

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

    if (diffDays > 3) {
      return res.status(400).json({ error: "Periodo de bonos expirado (3 días)" });
    }
    if (user.lastBonusDay && user.lastBonusDay >= diffDays) {
      return res.status(400).json({ error: "Bono ya reclamado hoy" });
    }

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
      bonusExpiry: admin.firestore.Timestamp.fromDate(expiry)
    });

    await db.collection("transactions").add({
      uid,
      type: "daily_bonus",
      bonus,
      day: diffDays,
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    });

    res.json({ ok: true, bonus, day: diffDays, expiresAt: expiry });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

/* ============================================================
   📞 Llamadas 1 a 1
============================================================ */
app.post("/call/use", verifyAuth, async (req, res) => {
  try {
    const { callerId, calleeId, secondsUsed } = req.body;
    if (!callerId || !calleeId || !secondsUsed)
      return res.status(400).json({ error: "Faltan parámetros" });

    const callerRef = db.collection("users").doc(callerId);
    const callerSnap = await callerRef.get();
    if (!callerSnap.exists) return res.status(404).json({ error: "Caller no encontrado" });
    const caller = callerSnap.data();

    if (caller.bonusExpiry && caller.bonusExpiry.toDate && new Date() > caller.bonusExpiry.toDate()) {
      await callerRef.update({
        freeCallSeconds: 0,
        freeLiveSeconds: 0,
        bonusExpiry: admin.firestore.FieldValue.delete()
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
          earnedCoins: (calleeSnap.data().earnedCoins || 0) + hostEarn
        });
      }

      await db.collection("transactions").add({
        uid: callerId,
        calleeId,
        type: "call_charge",
        secondsCharged: remaining,
        coinsCharged,
        createdAt: admin.firestore.FieldValue.serverTimestamp()
      });
    }

    res.json({ ok: true, freeConsumed, coinsCharged });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

/* ============================================================
   💳 Confirmar pago unificado (Stripe o PayPal)
============================================================ */
app.post("/payment/confirm", verifyAuth, async (req, res) => {
  try {
    const { uid, amount, method } = req.body;
    if (!uid || !amount || !method) {
      return res.status(400).json({ error: "Faltan parámetros" });
    }

    const coinsToAdd = amount * COINS_PER_USD;
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

/* ============================================================
   🎥 AGORA: Generar token
============================================================ */
app.post("/agora/token", verifyAuth, (req, res) => {
  const channelName = req.body.channelName || req.body.channel;
  const uid = req.body.uid;

  if (!channelName || !uid) {
    return res.status(400).json({ error: "Faltan parámetros (channelName o channel, uid)" });
  }

  const appID = process.env.AGORA_APP_ID;
  const appCertificate = process.env.AGORA_APP_CERT;
  const role = RtcRole.PUBLISHER;
  const expirationTimeInSeconds = 3600;
  const currentTimestamp = Math.floor(Date.now() / 1000);
  const privilegeExpiredTs = currentTimestamp + expirationTimeInSeconds;

  const token = RtcTokenBuilder.buildTokenWithUid(
    appID,
    appCertificate,
    channelName,
    uid,
    role,
    privilegeExpiredTs
  );

  res.json({ token, expiresAt: privilegeExpiredTs });
});

/* ============================================================
   📡 Live rooms
============================================================ */
app.get("/liveRooms", async (req, res) => {
  try {
    const snaps = await db.collection("liveRooms").where("isActive", "==", true).get();
    const rooms = [];
    snaps.forEach(s => rooms.push({ id: s.id, ...s.data() }));
    res.json(rooms);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post("/live/create", async (req, res) => {
  try {
    const { hostId, hostName, hostGender, entryPrice } = req.body;
    const docRef = await db.collection("liveRooms").add({
      hostId, hostName, hostGender, entryPrice,
      viewers: [],
      startTime: admin.firestore.FieldValue.serverTimestamp(),
      isActive: true
    });
    res.json({ id: docRef.id });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post("/live/enter", async (req, res) => {
  try {
    const { roomId, uid } = req.body;
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
      const hostEarn = Math.round((room.entryPrice || 0) * 0.7);
      await hostRef.update({ earnedCoins: (hostSnap.data().earnedCoins || 0) + hostEarn });

      await db.collection("transactions").add({
        uid, amount: room.entryPrice, type: "enter_live", roomId,
        createdAt: admin.firestore.FieldValue.serverTimestamp()
      });
    }

    const viewers = room.viewers || [];
    if (!viewers.includes(uid)) viewers.push(uid);
    await roomRef.update({ viewers });

    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/* ============================================================
   🚀 START SERVER
============================================================ */
app.listen(PORT, () => console.log("✅ Amora Live server running on port", PORT));







