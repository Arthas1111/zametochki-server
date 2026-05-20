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

function normalizeChatMessages(messages) {
  if (!Array.isArray(messages)) return [];

  return messages
    .filter((item) => item && typeof item === "object")
    .map((item) => ({
      role: item.role === "assistant" ? "assistant" : "user",
      content: String(item.content || "").trim(),
    }))
    .filter((item) => item.content)
    .slice(-20);
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

// ---- AI Chat (DeepSeek via OpenRouter - free) ----
app.post("/ai-chat", authMiddleware, async (req, res) => {
  try {
    const { message, history } = req.body || {};
    if (!message) return res.status(400).json({ error: "Нет сообщения" });

    const OPENROUTER_API_KEY = process.env.OPENROUTER_API_KEY;
    if (!OPENROUTER_API_KEY) return res.status(500).json({ error: "OPENROUTER_API_KEY не настроен" });

    const messages = [
      {
        role: "system",
        content: "Ты умный ассистент для приложения заметок zametochki.online. Помогай пользователям с их заметками, идеями и задачами. Отвечай на языке пользователя."
      }
    ];

    if (Array.isArray(history)) {
      for (const msg of history) {
        messages.push({ role: msg.role, content: msg.content });
      }
    }

    messages.push({ role: "user", content: message });

    const deepseekRes = await fetch("https://openrouter.ai/api/v1/chat/completions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${OPENROUTER_API_KEY}`,
        "HTTP-Referer": "https://zametochki.online",
        "X-Title": "Zametochki",
      },
      body: JSON.stringify({
        model: "deepseek/deepseek-v3-base:free",
        messages,
        max_tokens: 1024,
      }),
    });

    if (!deepseekRes.ok) {
      const err = await deepseekRes.json().catch(() => ({}));
      console.error("DeepSeek error:", err);
      return res.status(502).json({ error: "Ошибка DeepSeek: " + (err?.error?.message || deepseekRes.status) });
    }

    const data = await deepseekRes.json();
    const reply = data?.choices?.[0]?.message?.content || "Нет ответа";
    res.json({ reply });
  } catch (err) {
    console.error("AI chat error:", err);
    res.status(500).json({ error: "Внутренняя ошибка сервера" });
  }
});

app.get("/", (req, res) => res.send("Zametochki server работает"));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Сервер запущен на порту ${PORT}`));
