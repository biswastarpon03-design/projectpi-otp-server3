const express = require("express");
const crypto = require("crypto");
const nodemailer = require("nodemailer");
const admin = require("firebase-admin");
const { getFirestore } = require("firebase-admin/firestore");

const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_JSON);
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const db = getFirestore(
  process.env.FIRESTORE_DATABASE_ID ||
    "ai-studio-android-project-4845f50c-3c8e-4dd9-8886-2cc02b8c9fc7"
);

const mailer = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.GMAIL_USER,
    pass: process.env.GMAIL_APP_PASSWORD,
  },
});

const app = express();
app.use(express.json({ limit: "64kb" }));

const OTP_TTL_MS = 5 * 60 * 1000;
const RESEND_COOLDOWN_MS = 45 * 1000;
const MAX_OTP_ATTEMPTS = 5;

function normalizeEmail(email) {
  return String(email || "").trim().toLowerCase();
}

function normalizePhone(phone) {
  return String(phone || "").replace(/[^\d+]/g, "").trim();
}

function hashOtp(email, purpose, otp, salt) {
  return crypto
    .createHash("sha256")
    .update(`${email}|${purpose}|${otp}|${salt}`)
    .digest("hex");
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const derived = crypto.scryptSync(password, salt, 64).toString("hex");
  return `${salt}:${derived}`;
}

function verifyPassword(password, stored) {
  const [salt, key] = String(stored || "").split(":");
  if (!salt || !key) return false;
  const derived = crypto.scryptSync(password, salt, 64);
  const keyBuf = Buffer.from(key, "hex");
  if (derived.length !== keyBuf.length) return false;
  return crypto.timingSafeEqual(derived, keyBuf);
}

async function verifyAndConsumeOtp(email, purpose, otp) {
  const docId = `${purpose}_${Buffer.from(email).toString("base64url")}`;
  const ref = db.collection("otp_challenges").doc(docId);
  const snap = await ref.get();
  if (!snap.exists) {
    return { ok: false, error: "OTP not found or expired. Please request a new code." };
  }
  const data = snap.data();
  if (Date.now() > data.expiresAt) {
    await ref.delete();
    return { ok: false, error: "OTP expired. Please request a new code." };
  }
  if ((data.attempts || 0) >= MAX_OTP_ATTEMPTS) {
    await ref.delete();
    return { ok: false, error: "Too many wrong attempts. Request a new OTP." };
  }
  const expected = Buffer.from(data.otpHash, "hex");
  const actual = Buffer.from(hashOtp(email, purpose, String(otp || "").trim(), data.salt), "hex");
  if (expected.length !== actual.length || !crypto.timingSafeEqual(expected, actual)) {
    await ref.update({ attempts: (data.attempts || 0) + 1 });
    return { ok: false, error: "Invalid OTP code." };
  }
  await ref.delete();
  return { ok: true };
}

app.get("/", (_req, res) => {
  res.json({ ok: true, service: "Project Pi OTP Auth" });
});

app.post("/auth/send-otp", async (req, res) => {
  try {
    const email = normalizeEmail(req.body?.email);
    const purpose = String(req.body?.purpose || "signup").trim();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ error: "Please enter a valid email address." });
    }
    if (!["signup", "reset"].includes(purpose)) {
      return res.status(400).json({ error: "Invalid OTP purpose." });
    }

    const existingUser = await db.collection("auth_accounts").where("email", "==", email).limit(1).get();
    if (purpose === "signup" && !existingUser.empty) {
      return res.status(409).json({ error: "An account with this email already exists." });
    }
    if (purpose === "reset" && existingUser.empty) {
      return res.status(404).json({ error: "No account found for this email." });
    }

    const docId = `${purpose}_${Buffer.from(email).toString("base64url")}`;
    const ref = db.collection("otp_challenges").doc(docId);
    const prev = await ref.get();
    if (prev.exists && Date.now() - (prev.data().sentAt || 0) < RESEND_COOLDOWN_MS) {
      return res.status(429).json({ error: "Please wait 45 seconds before requesting another OTP." });
    }

    const otp = String(crypto.randomInt(100000, 1000000));
    const salt = crypto.randomBytes(16).toString("hex");
    await ref.set({
      email,
      purpose,
      salt,
      otpHash: hashOtp(email, purpose, otp, salt),
      sentAt: Date.now(),
      expiresAt: Date.now() + OTP_TTL_MS,
      attempts: 0,
    });

    await mailer.sendMail({
      from: `Project π <${process.env.GMAIL_USER}>`,
      to: email,
      subject: `Project π Verification Code: ${otp}`,
      text: `Your Project π verification OTP is: ${otp}\n\nThis code expires in 5 minutes. Do not share it with anyone.`,
      html: `<div style="font-family:sans-serif;padding:16px"><h2>Project π Verification</h2><p>Your verification code is:</p><p style="font-size:28px;font-weight:bold;letter-spacing:4px">${otp}</p><p>This code expires in 5 minutes.</p></div>`,
    });

    res.json({ ok: true, message: "OTP sent to your email." });
  } catch (err) {
    console.error("send-otp error:", err);
    res.status(500).json({ error: "Failed to send OTP email." });
  }
});

app.post("/auth/register", async (req, res) => {
  try {
    const email = normalizeEmail(req.body?.email);
    const phone = normalizePhone(req.body?.phone);
    const username = String(req.body?.username || "").trim();
    const password = String(req.body?.password || "");
    const otp = String(req.body?.otp || "").trim();

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ error: "Valid email is required." });
    }
    if (username.length < 3 || username.length > 30) {
      return res.status(400).json({ error: "Username must be 3 to 30 characters." });
    }
    if (password.length < 8) {
      return res.status(400).json({ error: "Password must be at least 8 characters." });
    }

    const otpCheck = await verifyAndConsumeOtp(email, "signup", otp);
    if (!otpCheck.ok) {
      return res.status(400).json({ error: otpCheck.error });
    }

    const existingEmail = await db.collection("auth_accounts").where("email", "==", email).limit(1).get();
    if (!existingEmail.empty) {
      return res.status(409).json({ error: "Account already exists." });
    }

    let fbUser;
    try {
      fbUser = await admin.auth().getUserByEmail(email);
    } catch (_e) {
      fbUser = await admin.auth().createUser({ email, displayName: username });
    }

    await db.collection("auth_accounts").doc(fbUser.uid).set({
      uid: fbUser.uid,
      email,
      phone,
      username,
      passwordHash: hashPassword(password),
      createdAt: Date.now(),
    });

    const customToken = await admin.auth().createCustomToken(fbUser.uid);
    res.json({ ok: true, customToken, username });
  } catch (err) {
    console.error("register error:", err);
    res.status(500).json({ error: "Could not complete registration." });
  }
});

app.post("/auth/login", async (req, res) => {
  try {
    const email = normalizeEmail(req.body?.email);
    const phone = normalizePhone(req.body?.phone);
    const password = String(req.body?.password || "");

    if ((!email && !phone) || !password) {
      return res.status(400).json({ error: "Enter your email or phone and password." });
    }

    let snap;
    if (email) {
      snap = await db.collection("auth_accounts").where("email", "==", email).limit(1).get();
    } else {
      snap = await db.collection("auth_accounts").where("phone", "==", phone).limit(1).get();
    }

    if (snap.empty) {
      return res.status(401).json({ error: "Invalid credentials." });
    }
    const account = snap.docs[0].data();
    if (!verifyPassword(password, account.passwordHash)) {
      return res.status(401).json({ error: "Invalid credentials." });
    }

    const customToken = await admin.auth().createCustomToken(account.uid);
    res.json({ ok: true, customToken, username: account.username });
  } catch (err) {
    console.error("login error:", err);
    res.status(500).json({ error: "Login failed." });
  }
});

app.post("/auth/reset-password", async (req, res) => {
  try {
    const email = normalizeEmail(req.body?.email);
    const otp = String(req.body?.otp || "").trim();
    const newPassword = String(req.body?.newPassword || "");

    if (newPassword.length < 8) {
      return res.status(400).json({ error: "New password must be at least 8 characters." });
    }

    const otpCheck = await verifyAndConsumeOtp(email, "reset", otp);
    if (!otpCheck.ok) {
      return res.status(400).json({ error: otpCheck.error });
    }

    const snap = await db.collection("auth_accounts").where("email", "==", email).limit(1).get();
    if (snap.empty) {
      return res.status(404).json({ error: "Account not found." });
    }

    const accountDoc = snap.docs[0];
    await accountDoc.ref.update({ passwordHash: hashPassword(newPassword) });
    const customToken = await admin.auth().createCustomToken(accountDoc.id);
    res.json({ ok: true, customToken });
  } catch (err) {
    console.error("reset-password error:", err);
    res.status(500).json({ error: "Could not reset password." });
  }
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Project Pi OTP server running on ${port}`));