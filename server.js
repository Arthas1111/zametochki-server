import express from "express";
import cors from "cors";
import AWS from "aws-sdk";

const app = express();
app.use(cors());
app.use(express.json());

// === Конфигурация S3 ===
AWS.config.update({
  accessKeyId: process.env.S3_ACCESS_KEY,
  secretAccessKey: process.env.S3_SECRET_KEY,
  region: "ru-1", // у Beget регион обычно "ru-1"
  endpoint: "https://s3.ru1.storage.beget.cloud",
  s3ForcePathStyle: true,
  signatureVersion: "v4"
});

const s3 = new AWS.S3();
const BUCKET = process.env.S3_BUCKET;

// === 1️⃣ Генерация presigned URL для загрузки файла ===
app.post("/get-presigned-url", async (req, res) => {
  try {
    const { fileName, fileType } = req.body;

    if (!fileName || !fileType) {
      return res.status(400).json({ error: "Не указано имя или тип файла" });
    }

    // уникальное имя (чтобы не было конфликтов)
    const key = `uploads/${Date.now()}-${fileName}`;

    const params = {
      Bucket: BUCKET,
      Key: key,
      ContentType: fileType,
      Expires: 60 // ссылка действует 60 секунд
      // ACL: "public-read" — не добавляем, чтобы файл был приватным
    };

    // URL для загрузки (PUT)
    const uploadUrl = await s3.getSignedUrlPromise("putObject", params);

    // Мы возвращаем ключ файла (чтобы потом получить GET ссылку)
    res.json({
      uploadUrl,
      fileKey: key
    });
  } catch (err) {
    console.error("Ошибка при создании ссылки:", err);
    res.status(500).json({ error: "Ошибка при создании presigned URL" });
  }
});

// === 2️⃣ Генерация presigned URL для скачивания файла ===
app.get("/get-file-url", async (req, res) => {
  try {
    const { key } = req.query;
    if (!key) return res.status(400).json({ error: "Не указан ключ файла" });

    const params = {
      Bucket: BUCKET,
      Key: key,
      Expires: 60 // 1 минута для скачивания
    };

    const url = await s3.getSignedUrlPromise("getObject", params);
    res.json({ url });
  } catch (err) {
    console.error("Ошибка при создании ссылки на скачивание:", err);
    res.status(500).json({ error: "Ошибка создания ссылки на скачивание" });
  }
});

// === 3️⃣ Проверка работы сервера ===
app.get("/", (req, res) => {
  res.send("✅ Zametochki S3 server работает");
});

// === 4️⃣ Запуск сервера ===
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Сервер запущен на порту ${PORT}`));
