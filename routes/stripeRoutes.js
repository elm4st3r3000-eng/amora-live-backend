import express from "express";
import Stripe from "stripe";
import dotenv from "dotenv";
import admin from "firebase-admin";

dotenv.config();
const router = express.Router();
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

router.post("/create-checkout-session", async (req, res) => {
  const { userId, amount, coins } = req.body;

  try {
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ["card"],
      mode: "payment",
      line_items: [
        {
          price_data: {
            currency: "usd",
            product_data: { name: `${coins} Monedas Amora Live` },
            unit_amount: amount * 100, // en centavos
          },
          quantity: 1,
        },
      ],
      success_url: `${process.env.CLIENT_URL}/success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${process.env.CLIENT_URL}/cancel`,
      metadata: { userId, coins },
    });

    res.json({ url: session.url });
  } catch (error) {
    console.error("Error creating checkout session:", error);
    res.status(500).json({ error: "Error creating checkout session" });
  }
});

// Webhook de Stripe para confirmar pagos y entregar monedas
router.post("/webhook", express.raw({ type: "application/json" }), async (req, res) => {
  const sig = req.headers["stripe-signature"];
  let event;

  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.log("Webhook signature verification failed:", err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  if (event.type === "checkout.session.completed") {
    const session = event.data.object;
    const { userId, coins } = session.metadata;

    if (userId && coins) {
      const userRef = admin.firestore().collection("users").doc(userId);
      await admin.firestore().runTransaction(async (t) => {
        const userDoc = await t.get(userRef);
        const currentCoins = userDoc.exists ? userDoc.data().coins || 0 : 0;
        t.update(userRef, { coins: currentCoins + parseInt(coins) });
      });
    }
  }

  res.status(200).send();
});

export default router;
