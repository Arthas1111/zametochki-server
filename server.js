import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import AWS from "aws-sdk";
import admin from "firebase-admin";
import helmet from "helmet";
import rateLimit from "express-rate-limit";

dotenv.config();

const app = express();
app.use(express.json());
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
    return res.status(403).json({ error: "CORS: origin запрещён" });
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
  } catch (e) {
    return res.status(401).json({ error: "Неверный/просроченный токен" });
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

function safeFileName(name) {
  return String(name || "file").replace(/[^\w.\-() ]+/g, "_");
}

const MAX_FILE_BYTES = 5 * 1024 * 1024 * 1024;

const ALLOWED_MIME = new Set([
  "image/png",
  "image/jpeg",
  "image/webp",
  "image/gif",
  "application/pdf",
  "text/plain",
  "audio/mpeg",
  "audio/wav",
  "audio/ogg",
  "audio/mp4",
  "application/msword",
  "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  "application/vnd.ms-excel",
  "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  "application/vnd.ms-powerpoint",
  "application/vnd.openxmlformats-officedocument.presentationml.presentation",
]);

function validateUpload({ fileType, fileSize }) {
  if (!BUCKET) {
    return { ok: false, status: 500, error: "S3_BUCKET не задан на сервере" };
  }
  if (!fileType || !ALLOWED_MIME.has(fileType)) {
    return { ok: false, status: 400, error: "Тип файла запрещён" };
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

app.post("/get-presigned-url", authMiddleware, presignLimiter, async (req, res) => {
  try {
    const { fileName, fileType, fileSize } = req.body || {};
    if (!fileName || !fileType) {
      return res.status(400).json({ error: "Не указано имя или тип файла" });
    }

    const v = validateUpload({ fileType, fileSize });
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

app.get("/", (req, res) => res.send("Zametochki S3 server работает"));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Сервер запущен на порту ${PORT}`));
