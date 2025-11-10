import express from "express";
import cors from "cors";
import AWS from "aws-sdk";
import dotenv from "dotenv";

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

const s3 = new AWS.S3({
  accessKeyId: process.env.AWS_ACCESS_KEY_ID,
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  region: process.env.AWS_REGION,
  endpoint: "https://s3.ru1.storage.beget.cloud",
  s3ForcePathStyle: true,
  signatureVersion: "v4"
});

app.post("/get-presigned-url", async (req, res) => {
  try {
    const { fileName, fileType } = req.body;

    if (!fileName || !fileType) {
      return res.status(400).json({ error: "Неверные параметры" });
    }

    const key = `uploads/${Date.now()}-${fileName}`;
    const params = {
      Bucket: process.env.S3_BUCKET,
      Key: key,
      ContentType: fileType,
      Expires: 60
    };

    const url = await s3.getSignedUrlPromise("putObject", params);

    res.json({
      uploadUrl: url,
      fileUrl: `https://${process.env.S3_BUCKET}.s3.ru1.storage.beget.cloud/${key}`
    });
  } catch (err) {
    console.error("Ошибка при создании ссылки:", err);
    res.status(500).json({ error: "Ошибка при создании ссылки" });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ Сервер запущен на порту ${PORT}`));
