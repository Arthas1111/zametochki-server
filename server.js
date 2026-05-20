import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import AWS from "aws-sdk";
import admin from "firebase-admin";
import helmet from "helmet";
import rateLimit from "express-rate-limit";

dotenv.config();

const app = express();
app.use(express.json({ limit: "1mb" }));
app.use(helmet());

const globalLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 180,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(globalLimiter);

const presignLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
});

const aiChatLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
});

const allowedOrigins = (process.env.CORS_ORIGINS || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

app.use(
  cors({
    origin: (origin, cb) => {
      if (!origin) return cb(null, true);
      if (allowedOrigins.length === 0) return cb(null, true);
      if (allowedOrigins.includes(origin)) return cb(null, true);
      return cb(new Error("Not allowed by CORS"));
    },
    credentials: true,
  })
);

app.use((err, req, res, next) => {
  if (err && err.message === "Not allowed by CORS") {
    return res.status(403).json({ error: "CORS: origin запрещен" });
  }
  return next(err);
});

let firebaseReady = false;

if (!process.env.FIREBASE_SERVICE_ACCOUNT_JSON) {
  console.warn("FIREBASE_SERVICE_ACCOUNT_JSON не задан. Auth middleware работать не будет.");
} else {
  admin.initializeApp({
    credential: admin.credential.cert(JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_JSON)),
  });
  firebaseReady = true;
}

async function authMiddleware(req, res, next) {
  try {
    if (!firebaseReady) {
      return res.status(500).json({ error: "Firebase Admin не настроен на сервере" });
    }

    const hdr = req.headers.authorization || "";
    const m = hdr.match(/^Bearer (.+)$/);
    if (!m) return res.status(401).json({ error: "Нет токена (Authorization: Bearer ...)" });

    const decoded = await admin.auth().verifyIdToken(m[1]);
    req.user = decoded;
    next();
  } catch {
    return res.status(401).json({ error: "Неверный или просроченный токен" });
  }
}

AWS.config.update({
  accessKeyId: process.env.S3_ACCESS_KEY,
  secretAccessKey: process.env.S3_SECRET_KEY,
  region: "ru-1",
  endpoint: "https://s3.ru1.storage.beget.cloud",
  s3ForcePathStyle: true,
  signatureVersion: "v4",
});

const s3 = new AWS.S3();
const BUCKET = process.env.S3_BUCKET;
const MAX_FILE_BYTES = 5 * 1024 * 1024 * 1024;

function safeFileName(name) {
  return String(name || "file").replace(/[^\w.\-() ]+/g, "_");
}

function validateUpload({ fileSize }) {
  if (!BUCKET) {
    return { ok: false, status: 500, error: "S3_BUCKET не задан на сервере" };
  }
  if (typeof fileSize !== "number" || !Number.isFinite(fileSize)) {
    return { ok: false, status: 400, error: "Не указан корректный размер файла" };
  }
  if (fileSize <= 0) {
    return { ok: false, status: 400, error: "Некорректный размер файла" };
  }
  if (fileSize > MAX_FILE_BYTES) {
    return { ok: false, status: 413, error: "Файл больше 5 ГБ. Это превышает лимит." };
  }
  return { ok: true };
}

function normalizeAiRequest(body) {
  if (Array.isArray(body?.messages)) {
    return body.messages
      .filter((msg) => msg && typeof msg === "object")
      .map((msg) => ({
        role: msg.role === "assistant" ? "assistant" : msg.role === "system" ? "system" : "user",
        content: String(msg.content || "").trim(),
      }))
      .filter((msg) => msg.content);
  }

  const messages = [];

  if (Array.isArray(body?.history)) {
    for (const msg of body.history) {
      const content = String(msg?.content || "").trim();
      if (!content) continue;
      messages.push({
        role: msg.role === "assistant" ? "assistant" : "user",
        content,
      });
    }
  }

  const message = String(body?.message || "").trim();
  if (message) messages.push({ role: "user", content: message });

  return messages;
}

app.post("/get-presigned-url", authMiddleware, presignLimiter, async (req, res) => {
  try {
    const { fileName, fileType, fileSize } = req.body || {};
    if (!fileName || !fileType) {
      return res.status(400).json({ error: "Не указано имя или тип файла" });
    }

    const v = validateUpload({ fileSize });
    if (!v.ok) return res.status(v.status).json({ error: v.error });

    const uid = req.user.uid;
    const key = `uploads/${uid}/${Date.now()}-${safeFileName(fileName)}`;

    const params = {
      Bucket: BUCKET,
      Key: key,
      ContentType: fileType,
      Expires: 60,
    };

    const uploadUrl = await s3.getSignedUrlPromise("putObject", params);
    res.json({ uploadUrl, fileKey: key });
  } catch (err) {
    console.error("Ошибка при создании uploadUrl:", err);
    res.status(500).json({ error: "Ошибка при создании presigned URL" });
  }
});

app.get("/get-file-url", authMiddleware, async (req, res) => {
  try {
    const { key } = req.query;
    if (!key) return res.status(400).json({ error: "Не указан ключ файла" });

    const uid = req.user.uid;
    if (!String(key).startsWith(`uploads/${uid}/`)) {
      return res.status(403).json({ error: "Нет доступа к файлу" });
    }

    const params = {
      Bucket: BUCKET,
      Key: key,
      Expires: 60,
    };

    const url = await s3.getSignedUrlPromise("getObject", params);
    res.json({ url });
  } catch (err) {
    console.error("Ошибка при создании ссылки на скачивание:", err);
    res.status(500).json({ error: "Ошибка создания ссылки на скачивание" });
  }
});

app.delete("/delete-file", authMiddleware, async (req, res) => {
  try {
    const { key } = req.query;
    if (!key) return res.status(400).json({ error: "Не указан ключ файла" });

    const uid = req.user.uid;
    if (!String(key).startsWith(`uploads/${uid}/`)) {
      return res.status(403).json({ error: "Нет доступа к файлу" });
    }

    await s3
      .deleteObject({
        Bucket: BUCKET,
        Key: key,
      })
      .promise();

    res.json({ ok: true });
  } catch (err) {
    console.error("Ошибка удаления файла:", err);
    res.status(500).json({ error: "Ошибка удаления файла" });
  }
});

async function handleAiChat(req, res) {
  try {
    const messages = normalizeAiRequest(req.body || {});
    if (!messages.length) {
      return res.status(400).json({ error: "Нет сообщения" });
    }

    const apiKey = process.env.OPENROUTER_API_KEY;
    const baseUrl = (process.env.OPENROUTER_BASE_URL || "https://openrouter.ai/api/v1").replace(/\/+$/, "");
    const model = process.env.OPENROUTER_MODEL || "deepseek/deepseek-chat-v3-0324:free";

    if (!apiKey) {
      return res.status(500).json({ error: "OPENROUTER_API_KEY не настроен" });
    }

    const upstream = await fetch(`${baseUrl}/chat/completions`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${apiKey}`,
        "HTTP-Referer": process.env.OPENROUTER_SITE_URL || "https://zametochki.online",
        "X-OpenRouter-Title": process.env.OPENROUTER_APP_NAME || "Zametochki AI",
      },
      body: JSON.stringify({
        model,
        stream: false,
        temperature: 0.7,
        messages,
      }),
    });

    const data = await upstream.json().catch(() => ({}));

    if (!upstream.ok) {
      console.error("OpenRouter API error:", data);
      return res.status(upstream.status).json({
        error: data?.error?.message || data?.message || "Ошибка запроса к OpenRouter",
      });
    }

    const reply = data?.choices?.[0]?.message?.content?.trim();
    if (!reply) {
      return res.status(502).json({ error: "OpenRouter вернул пустой ответ" });
    }

    res.json({ reply });
  } catch (err) {
    console.error("AI chat error:", err);
    res.status(500).json({ error: "Внутренняя ошибка сервера" });
  }
}

app.post("/ai/chat", authMiddleware, aiChatLimiter, handleAiChat);
app.post("/ai-chat", authMiddleware, aiChatLimiter, handleAiChat);

app.get("/", (req, res) => res.send("Zametochki server работает"));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Сервер запущен на порту ${PORT}`));
