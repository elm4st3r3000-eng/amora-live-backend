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
  console.error("❌ Error al cargar credenciales Firebase:", e && e.message ? e.message : e);
  serviceAccount = null;
  console.warn("⚠️ Firebase admin no inicializado: serviceAccountKey no disponible. Algunas rutas requerirán Firestore.");
}

const db = admin.firestore ? admin.firestore() : null;

// ------------------------------------------------------------
// Middlewares: body parsing y CORS
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
      console.error("Firebase admin no inicializado - verifyAuth falla.");
      return res.status(500).json({ error: "Servicio de autenticación no disponible" });
    }
    const decoded = await admin.auth().verifyIdToken(idToken);
    req.user = decoded;
    next();
  } catch (error) {
    console.error("❌ Error de autenticación:", error && error.message ? error.message : error);
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
// RUTAS (como tu versión original completa)
// ------------------------------------------------------------

// root health
app.get("/", (req, res) => {
  res.send("✅ Servidor Amora Live está funcionando correctamente.");
});

// bono diario
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

// bono inicial
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
      return res.status(200).json({ ok: true, message: "No hay bono inicial configurado en el servidor." });
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

// ... (el resto de tus rutas originales, tal como estaban: llamadas, pagos, agora, live rooms)

app.listen(PORT, () => {
  console.log(`✅ Servidor Amora Live ejecutándose en el puerto ${PORT}`);
});
