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
const PORT = process.env.PORT || 4000;

/* ============================================================
   FIREBASE ADMIN
============================================================ */
let serviceAccount;

try {
  const localPath = "./serviceAccountKey.json"; // archivo local
  const renderPath = "/etc/secrets/serviceAccountKey.json"; // ruta en Render
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

/* ============================================================
   Middleware: verificar idToken de Firebase
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
   Stripe / PayPal / Modelo económico
============================================================ */
const stripe = Stripe(process.env.STRIPE_SECRET_KEY);

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

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors({
  origin: [
    "https://amora-live-famous.netlify.app",
    "https://amora-live.netlify.app",
    "https://super-academia-musical.netlify.app",
    "http://localhost:3000"    
  ],
  methods: ["GET", "POST"],
  allowedHeaders: ["Content-Type", "Authorization"],
  credentials: true,
}));



/* ============================================================
   RUTA: bono diario
============================================================ */
app.post("/user/claim-daily-bonus", verifyAuth, async (req, res) => {
  try {
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

/* ============================================================
   RUTA: bono inicial controlado
============================================================ */
app.post("/user/grant-initial-bonus", verifyAuth, async (req, res) => {
  try {
    const uid = req.user.uid;
    const userRef = db.collection("users").doc(uid);
    const uSnap = await userRef.get();
    if (!uSnap.exists) return res.status(404).json({ error: "Usuario no encontrado" });
    const user = uSnap.data();

    if (user.initialBonusGranted) {
      return res.status(400).json({ error: "Bono inicial ya otorgado" });
    }

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

/* ============================================================
   📞 Llamadas 1 a 1
============================================================ */
app.post("/call/use", verifyAuth, async (req, res) => {
  try {
    const { callerId, calleeId, secondsUsed } = req.body;
    if (!callerId || !calleeId || !secondsUsed)
      return res.status(400).json({ error: "Faltan parámetros" });

    // seguridad: callerId debe ser quien hace la petición
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

/* ============================================================
   💳 Crear sesión Stripe 
============================================================ */
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
    console.error("❌ Error creando sesión de pago Stripe:", e.message);
    res.status(500).json({ error: e.message });
  }
});

app.post("/payment/paypal/create", verifyAuth, async (req, res) => {
  try {
    const { usd } = req.body;
    const uid = req.user.uid;

    if (!usd) return res.status(400).json({ error: "Monto requerido" });

    const request = new paypal.orders.OrdersCreateRequest();
    request.prefer("return=representation");
    request.requestBody({
      intent: "CAPTURE",
      purchase_units: [{
        amount: { currency_code: "USD", value: usd.toString() },
        description: `${usd * COINS_PER_USD} monedas Amora`,
      }],
      application_context: {
        return_url: `${process.env.FRONTEND_URL}/paypal/success`,
        cancel_url: `${process.env.FRONTEND_URL}/coins`,
      },
    });

    const order = await paypalClient.execute(request);

    // 🔐 Guardar orden pendiente
    await db.collection("paypalOrders").doc(order.result.id).set({
      uid,
      usd,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      status: "created",
    });

    const approveUrl = order.result.links.find(l => l.rel === "approve")?.href;

    res.json({ approveUrl });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});


app.post("/payment/paypal/capture", verifyAuth, async (req, res) => {
  try {
    const { orderId } = req.body;
    const uid = req.user.uid;
	
    const orderSnap = await db.collection("paypalOrders").doc(orderId).get();
    if (!orderSnap.exists) return res.status(404).json({ error: "Orden no encontrada" });

    const orderData = orderSnap.data();
    if (orderData.uid !== uid) return res.status(403).json({ error: "Orden no pertenece al usuario" });
	if (orderData.status === "completed")
  return res.status(400).json({ error: "Orden ya procesada" });
   const request = new paypal.orders.OrdersCaptureRequest(orderId);
const capture = await paypalClient.execute(request);

if (capture.result.status !== "COMPLETED") {
  return res.status(400).json({ error: "Pago no completado" });
}

// 🔒 VALIDAR MONTO REAL COBRADO
const paidUsd =
  capture.result.purchase_units[0].payments.captures[0].amount.value;

if (Number(paidUsd) !== Number(orderData.usd)) {
  return res.status(400).json({ error: "Monto no coincide" });
}

    const coinsToAdd = orderData.usd * COINS_PER_USD;

    await db.collection("users").doc(uid).update({
      coins: admin.firestore.FieldValue.increment(coinsToAdd),
    });

    await db.collection("paypalOrders").doc(orderId).update({
      status: "completed",
      completedAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    await db.collection("transactions").add({
      uid,
      usd: orderData.usd,
      coins: coinsToAdd,
      type: "paypal_topup",
      orderId,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    res.json({ ok: true, coinsAdded: coinsToAdd });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});






app.post("/store/checkout", verifyAuth, async (req, res) => {
  try {
    const uid = req.user.uid;
    const { cart } = req.body;

    if (!cart || cart.length === 0) {
      return res.status(400).json({ error: "Carrito vacío" });
    }

    const userRef = db.collection("users").doc(uid);
    const userSnap = await userRef.get();

    if (!userSnap.exists) {
      return res.status(404).json({ error: "Usuario no existe" });
    }

    const user = userSnap.data();

    const totalCoins = cart.reduce(
      (sum, p) => sum + Number(p.priceCoins),
      0
    );

    if ((user.coins || 0) < totalCoins) {
      return res.status(400).json({
        error: "Saldo insuficiente",
        required: totalCoins,
        available: user.coins || 0,
      });
    }

    // 🔻 Descontar monedas
    await userRef.update({
      coins: (user.coins || 0) - totalCoins,
      ownedProducts: admin.firestore.FieldValue.arrayUnion(
        ...cart.map((p) => p.id)
      ),
    });

    // 🧾 Registrar transacción
    await db.collection("transactions").add({
      uid,
      type: "store_purchase",
      coinsSpent: totalCoins,
      products: cart.map((p) => ({
        id: p.id,
        title: p.title,
        priceCoins: p.priceCoins,
      })),
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    res.json({ ok: true });
  } catch (e) {
    console.error("❌ Error store checkout:", e);
    res.status(500).json({ error: e.message });
  }
});







/* ============================================================
   🎥 AGORA TOKEN 
============================================================ */


// 🔢 Conversor: Firebase UID (string) → UID numérico reproducible
function numericUidFromFirebase(uid) {
  let hash = 0;
  for (let i = 0; i < uid.length; i++) {
    hash = (hash * 31 + uid.charCodeAt(i)) >>> 0;
  }
  return hash % 1000000000; // uid < 1e9
}

app.all("/agora/token", verifyAuth, (req, res) => {
  try {
    const channelName =
      req.body.channelName ||
      req.body.channel ||
      req.query.channelName ||
      req.query.channel;

    if (!channelName) {
      return res.status(400).json({ error: "Falta channelName" });
    }

    const firebaseUid = req.user.uid;
    const uid = numericUidFromFirebase(firebaseUid);

    const roleParam = req.body.role || req.query.role || "audience";
    const appID = process.env.AGORA_APP_ID;
    const appCertificate = process.env.AGORA_APP_CERTIFICATE;
    if (!appID || !appCertificate) {
      return res.status(500).json({
        error: "Faltan credenciales de Agora (AGORA_APP_ID o AGORA_APP_CERT)",
      });
    }

    // ✅ Asignar rol correcto
    const agoraRole =
      roleParam === "host" ? RtcRole.PUBLISHER : RtcRole.SUBSCRIBER;

    // Expiración: 1 hora (3600s)
    const expirationTimeInSeconds = 3600;
    const currentTimestamp = Math.floor(Date.now() / 1000);
    const privilegeExpiredTs = currentTimestamp + expirationTimeInSeconds;

    const token = RtcTokenBuilder.buildTokenWithUid(
      appID,
      appCertificate,
      channelName,
      uid,
      agoraRole,
      privilegeExpiredTs
    );

    res.json({
      ok: true,
      token,
      channelName,
      uid, // numérico, usado por Agora
      firebaseUid, // real de Firebase
      role: roleParam,
      expiresAt: privilegeExpiredTs,
    });
  } catch (e) {
    console.error("❌ Error en /agora/token:", e);
    res.status(500).json({ error: e.message });
  }
});




/* ============================================================
   📡 Live Rooms 
============================================================ */
app.get("/liveRooms", async (req, res) => {
  try {
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
    const { hostId, hostName, hostGender, entryPrice } = req.body;
    // hostId must match authenticated user
    if (hostId !== req.user.uid)
      return res.status(403).json({ error: "hostId no coincide con usuario autenticado" });

    const docRef = await db.collection("liveRooms").add({
      hostId,
      hostName,
      hostGender,
      entryPrice,
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
      if ((user.coins || 0) < (room.entryPrice || 0))
        return res.status(400).json({ error: "Saldo insuficiente" });

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

/* ============================================================
   ❤️ MATCHMAKING ALEATORIO 
============================================================ */
app.post("/match/cancel", verifyAuth, async (req, res) => {
  try {
    const uid = req.user.uid;
    const { genderPreference } = req.body; // "male", "female" o "any"

    const userRef = db.collection("users").doc(uid);
    const uSnap = await userRef.get();
    if (!uSnap.exists) return res.status(404).json({ error: "Usuario no encontrado" });
    const user = uSnap.data();

    // 🔒 Actualizamos estado del usuario
    await userRef.update({
      isSearching: true,
      searchGender: genderPreference || "any",
      searchStartedAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    // ⏳ Buscar otro usuario libre que cumpla los criterios
    let query = db
      .collection("users")
      .where("isSearching", "==", true)
      .where(admin.firestore.FieldPath.documentId(), "!=", uid);

    if (genderPreference && genderPreference !== "any") {
      query = query.where("gender", "==", genderPreference);
    }

    const snap = await query.get();
    const matches = [];
    snap.forEach((d) => matches.push({ id: d.id, ...d.data() }));

    // ❌ Si no hay nadie disponible, esperar al siguiente intento
    if (matches.length === 0) {
      return res.json({
        ok: true,
        found: false,
        message: "Buscando pareja...",
      });
    }

    // ✅ Elegir uno al azar
    const match = matches[Math.floor(Math.random() * matches.length)];

    // Crear un canal compartido único
    const channelName = `call_${uid}_${match.id}_${Date.now()}`;

    // Marcar ambos como ocupados
    await userRef.update({ isSearching: false, activeCallWith: match.id });
    await db.collection("users").doc(match.id).update({
      isSearching: false,
      activeCallWith: uid,
    });

    // Registrar sesión
    await db.collection("callMatches").add({
      userA: uid,
      userB: match.id,
      channelName,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      active: true,
    });

    res.json({
      ok: true,
      found: true,
      match: {
        uid: match.id,
        name: match.name || match.displayName || "User",
        gender: match.gender || "unknown",
      },
      channelName,
    });
  } catch (e) {
    console.error("❌ Error en /match/find:", e);
    res.status(500).json({ error: e.message });
  }
});

/* ============================================================
   📴 Terminar búsqueda o emparejamiento
============================================================ */
app.post("/live/match/cancel", verifyAuth, async (req, res) => {
  try {
    const uid = req.user.uid;
    await db.collection("users").doc(uid).update({
      isSearching: false,
      activeCallWith: admin.firestore.FieldValue.delete(),
      searchGender: admin.firestore.FieldValue.delete(),
      searchStartedAt: admin.firestore.FieldValue.delete(),
    });
    res.json({ ok: true, cancelled: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});





/* ============================================================
   START
============================================================ */
app.get("/", (req, res) => {
  res.send("✅ Servidor Amora Live está funcionando correctamente.");
});

app.listen(PORT, () => console.log("✅ Amora Live server running on port", PORT));