require("dotenv").config();
const express = require('express');
const cors = require('cors');
const fileUpload = require("express-fileupload");
const path = require("path");
const fs = require("fs");
const uuid = require("uuid");
const sharp = require('sharp');
const crypto = require('crypto');
const { Client, Account, OAuthProvider } = require('node-appwrite');

const adminClient = new Client()
    .setEndpoint(process.env.APPWRITE_ENDPOINT)
    .setProject(process.env.APPWRITE_PROJECT_ID)
    .setKey(process.env.APPWRITE_API_KEY);

const app = express();
app.use(cors());
app.use(express.json());
const PORT = process.env.PORT || 3000;

const settingsBufferSize = 32; // 32 bytes for settings
const authorBufferSize = 128; // 128 bytes for settings

// Middleware to handle file uploads
app.use(fileUpload());

// Ensure uploads folder exists
const uploadDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true }); // creates folder if missing
}

app.get('/oauth', async (req, res) => {
    const account = new Account(adminClient);

    console.log(process.env.APPWRITE_REDIRECT_URI);
    console.log(process.env.APPWRITE_REDIRECT_URI_ERROR);

    const redirectUrl = await account.createOAuth2Token(
        OAuthProvider.Discord,
        process.env.APPWRITE_REDIRECT_URI,
        process.env.APPWRITE_REDIRECT_URI_ERROR
    );

    res.redirect(redirectUrl);
});

app.get('/oauth/success', async (req, res) => {
    const account = new Account(adminClient);

    // Get the userId and secret from the URL parameters
    const { userId, secret } = req.query;

    try {
        // Create the session using the Appwrite client
        const session = await account.createSession(userId, secret);

        // Set the session cookie
        res.cookie('a_session_' + process.env.APPWRITE_PROJECT_ID, session.secret, { // Use the session secret as the cookie value
            httpOnly: true,
            secure: true,
            sameSite: 'strict',
            expires: new Date(session.expire),
            path: '/'
        });

        res.redirect(process.env.REDIRECT_URI);
    } catch (e) {
        res.redirect(process.env.REDIRECT_URI_ERROR + `error=${encodeURIComponent(e.message)}`);
    }
});

app.get('/oauth/failure', (req, res) => {
    const errorMessage = req.query.error || "OAuth failed";
    res.redirect(process.env.REDIRECT_URI_ERROR + `error=${encodeURIComponent(errorMessage)}`);
});

// Upload a file
app.post('/f/upload', async (req, res) => {
    try {
        if (!req.files || !req.files.file) {
            return res.status(400).send("No file uploaded.");
        }

        let file = req.files.file;
        const filename = uuid.v4() + ".jpg";
        const uploadPath = path.join(__dirname, "uploads", filename);

        // Move the file to uploads folder
        file.mv(uploadPath, async (err) => {
            if (err) {
                return res.status(500).send(err);
            }
            try {
                const filePath = await compress(file.data, uploadPath);

                const encryptKey = crypto.randomBytes(16); // 16 bytes for AES-128
                const iv = crypto.randomBytes(12); // 12 bytes for GCM

                // Encrypt the compressed file using AES-128-GCM
                const compressedBuffer = fs.readFileSync(filePath);
                const cipher = crypto.createCipheriv('aes-128-gcm', encryptKey, iv);
                const encrypted = Buffer.concat([cipher.update(compressedBuffer), cipher.final()]);
                const authTag = cipher.getAuthTag();

                // Settings
                const expire = req.query.expire ? 1 : 0;
                const limitedTime = req.query.limitedTime ? 1 : 0;

                const settingsBuffer = Buffer.alloc(settingsBufferSize);
                settingsBuffer[0] = expire;
                settingsBuffer[1] = limitedTime;

                // Store timestamp (8 bytes) at offset 2
                const uploadTime = BigInt(Date.now());
                settingsBuffer.writeBigUInt64BE(uploadTime, 2);

                // Author info
                const authorBuffer = Buffer.alloc(authorBufferSize);
                const author = req.query.author || "Anonymous";
                const authorBytes = Buffer.from(author, 'utf8');
                authorBytes.copy(authorBuffer, 0, 0, Math.min(authorBytes.length, authorBufferSize));
                
                // The rest remain zero
                const encryptedData = Buffer.concat([settingsBuffer, authorBuffer, iv, authTag, encrypted]);
                fs.writeFileSync(filePath, encryptedData);

                let keyBase64 = encryptKey.toString('base64');
                keyBase64 = keyBase64.replace(/=+$/, ''); // Remove trailing '='
                res.json({
                    filename: filename,
                    key: keyBase64,
                    url: `https://${req.get('host')}/f/${filename}?c=${encodeURIComponent(keyBase64)}`
                });
            }
            catch (error) {
                return res.status(500).send("Error compressing file: " + error.message);
            }
        });
    }
    catch (error) {
        console.error("Error in file upload:", error);
        res.status(500).send("Error uploading file: " + error.message);
    }
});

// Read a file
app.get('/f/:filename', (req, res) => {
    const filename = req.params.filename;
    const filePath = path.join(uploadDir, filename);

    if (!fs.existsSync(filePath)) {
        res.setHeader('Cache-Control', 'no-store');
        const notFoundFileBuffer = fs.readFileSync("404.jpg");
        res.setHeader('Content-Type', 'image/jpeg');
        return res.send(notFoundFileBuffer);
    }

    try {
        const fileBuffer = fs.readFileSync(filePath);
        const decryptedData = decrypt(fileBuffer, req.query.c, res);

        const settings = decryptedData.settings;
        const limitedTime = settings[1];
        const uploadTime = Number(settings.readBigUInt64BE(2));

        res.setHeader('X-Author', decryptedData.author.toString('utf8').replace(/\0/g, '')); // Set author header

        if (limitedTime === 1) {
            res.setHeader('Cache-Control', 'no-store, max-age=0, must-revalidate');
            const fileAge = Date.now() - uploadTime;
            if (fileAge > 10000) { // 10 seconds
                // Remove the image data from the file but keep the settings
                const newFileBuffer = Buffer.concat([decryptedData.settings, decryptedData.author]);
                fs.writeFileSync(filePath, newFileBuffer);

                const expiredFileBuffer = fs.readFileSync("expired.jpg");
                res.setHeader('Content-Type', 'image/jpeg');
                return res.send(expiredFileBuffer);
            }
        }

        res.setHeader('Content-Type', 'image/jpeg');
        res.send(decryptedData.data);
    } catch (error) {
        console.error("Error reading file:", error);
        const notFoundFileBuffer = fs.readFileSync("404.jpg");
        res.setHeader('Content-Type', 'image/jpeg');
        return res.send(notFoundFileBuffer);
    }
});

// Decrypt file encrypted with AES-128-GCM (iv + authTag + encrypted)
function decrypt(encryptedBuffer, keyBase64, res) {
    if (!keyBase64) throw new Error("Missing decryption key");
    const key = Buffer.from(keyBase64, 'base64');
    const settings = encryptedBuffer.slice(0, settingsBufferSize);
    const author = encryptedBuffer.slice(settingsBufferSize, settingsBufferSize + authorBufferSize);
    const iv = encryptedBuffer.slice(0 + settingsBufferSize + authorBufferSize, 12 + settingsBufferSize + authorBufferSize);
    const authTag = encryptedBuffer.slice(12 + settingsBufferSize + authorBufferSize, 28 + settingsBufferSize + authorBufferSize);
    const encrypted = encryptedBuffer.slice(28 + settingsBufferSize + authorBufferSize);
    const decipher = crypto.createDecipheriv('aes-128-gcm', key, iv);
    decipher.setAuthTag(authTag);
    return {
        data: Buffer.concat([decipher.update(encrypted), decipher.final()]),
        settings: settings,
        author: author
    };
}

// Compress image to 200 KB and convert to JPEG
async function compress(fileBuffer, filePath) {
    try {
        await sharp(fileBuffer)
            .resize({ height: 2160, withoutEnlargement: true }) // Resize to a maximum width of 800px
            .jpeg({ quality: 75 }) // Set JPEG quality to 80%
            .toFile(filePath);
        return filePath;
    } catch (error) {
        console.error("Error compressing image:", error);
        throw error;
    }
}

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});