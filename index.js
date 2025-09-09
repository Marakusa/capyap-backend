require("dotenv").config();
const express = require('express');
const cors = require('cors');
const fileUpload = require("express-fileupload");
const path = require("path");
const fs = require("fs");
const { readdir, stat } = require('fs/promises');
const uuid = require("uuid");
const sharp = require('sharp');
const crypto = require('crypto');
const { Client, Account, OAuthProvider, Databases, ID, Query, Users } = require('node-appwrite');
const { Server } = require('socket.io');
const rateLimit = require('express-rate-limit');

const adminClient = new Client()
    .setEndpoint(process.env.APPWRITE_ENDPOINT)
    .setProject(process.env.APPWRITE_PROJECT_ID)
    .setKey(process.env.APPWRITE_API_KEY);

const app = express();
app.use(cors());
app.use(express.json());
const PORT = process.env.PORT || 3000;

const server = app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});

var io;

if (process.env.ENV === "dev") {
    io = new Server(server, {
        cors: {
            origin: 'http://localhost:5891'
        }
    });
} else {
    io = new Server(server, {
        cors: {
            origin: 'https://sc.marakusa.me'
        }
    });
}

const connectedSockets = new Map();

io.on('connection', (socket) => {
    connectedSockets.set(socket.id, {
        socket: socket,
        userId: null
    });

    let userId;
    socket.on('userLogin', async (jwtToken) => {
        if (!jwtToken) {
            return;
        }

        const userClient = new Client()
            .setEndpoint(process.env.APPWRITE_ENDPOINT)
            .setProject(process.env.APPWRITE_PROJECT_ID)
            .setJWT(jwtToken);

        const account = new Account(userClient);

        const user = await account.get();
        if (!user) {
            return;
        }
        userId = user.$id;
        connectedSockets.set(socket.id, {
            socket: socket,
            userId: userId
        });
    });
    socket.on('disconnect', () => {
        connectedSockets.delete(socket.id);
    });
});

// Max allowed file size
const MAX_FILE_SIZE = 5 * 1024 * 1024;

// Allowed extensions
const ALLOWED_EXTS = ["jpg", "jpeg", "png", "gif"];

const settingsBufferSize = 32; // 32 bytes for settings
const authorBufferSize = 128; // 128 bytes for settings

// Middleware to limit repeated requests to public APIs and/or endpoints
const limiter = rateLimit({
	windowMs: 60 * 1000, // 1 minute
	limit: 30, // Limit each IP to 100 requests per `window` (here, per a minute).
	standardHeaders: 'draft-8', // draft-6: `RateLimit-*` headers; draft-7 & draft-8: combined `RateLimit` header
	legacyHeaders: false, // Disable the `X-RateLimit-*` headers.
	ipv6Subnet: 58, // Set to 60 or 64 to be less aggressive, or 52 or 48 to be more aggressive
});
app.use((req, res, next) => {
    if (req.path.startsWith('/f/u') || req.path.startsWith('/f/upload')) {
        return next(); // skip global limiter for uploads
    }
    limiter(req, res, next);
});

// Middleware to handle file uploads
app.use(fileUpload());

// Ensure uploads folder exists
const uploadDir = process.env.UPLOADS_FOLDER || path.join(__dirname, "uploads");

if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true }); // creates folder if missing
}

app.get('/oauth', async (req, res) => {
    const isDesktop = req.query["desktop"] != null;

    const account = new Account(adminClient);

    const redirectUrl = await account.createOAuth2Token(
        OAuthProvider.Discord,
        !isDesktop ? process.env.APPWRITE_REDIRECT_URI : process.env.APPWRITE_REDIRECT_URI_DESKTOP,
        !isDesktop ? process.env.APPWRITE_REDIRECT_URI_ERROR : process.env.APPWRITE_REDIRECT_URI_ERROR_DESKTOP
    );

    res.redirect(redirectUrl + "&prompt=none");
});

app.get('/oauth/success', async (req, res) => {
    // Get the userId and secret from the URL parameters
    const { userId, secret } = req.query;

    try {
        res.redirect(process.env.REDIRECT_URI + `userId=${encodeURIComponent(userId)}&secret=${encodeURIComponent(secret)}`);
    } catch (e) {
        res.redirect(process.env.REDIRECT_URI_ERROR + `error=${encodeURIComponent(e.message)}`);
    }
});

app.get('/oauth/failure', (req, res) => {
    const errorMessage = req.query.error || "OAuth failed";
    res.redirect(process.env.REDIRECT_URI_ERROR + `error=${encodeURIComponent(errorMessage)}`);
});

app.post('/user/getUploadKey', async (req, res) => {
    try {
        const data = req.body;

        if (!data || !data.sessionKey) {
            return res.status(403).send("Unauthorized, please try to log in again.");
        }

        const userClient = new Client()
            .setEndpoint(process.env.APPWRITE_ENDPOINT)
            .setProject(process.env.APPWRITE_PROJECT_ID)
            .setJWT(data.sessionKey);

        const account = new Account(userClient);

        const user = await account.get();
        if (!user) {
            return res.status(403).send("Unauthorized, please try to log in again.");
        }
        
        const uploadKeysDatabase = new Databases(adminClient);
        const uploadKey = await uploadKeysDatabase.listDocuments(
            process.env.APPWRITE_DATABASE_ID,
            process.env.APPWRITE_UPLOADKEYS_ID,
            [
                Query.equal("userId", user.$id)
            ]);

        if (uploadKey.documents.length > 0) {
            return res.json({
                uploadKey: uploadKey.documents[0].key
            });
        }

        const newUploadKey = crypto.randomBytes(128).toString("base64");

        await uploadKeysDatabase.createDocument(
            process.env.APPWRITE_DATABASE_ID,
            process.env.APPWRITE_UPLOADKEYS_ID,
            ID.unique(),
            {
                key: newUploadKey,
                userId: user.$id,
                username: user.name
            });
            
        return res.json({
            uploadKey: newUploadKey
        });
    } catch (error) {
        console.error("Error when fetching upload key:", error);
        res.status(500).send("Error while fetching upload key.");
    }
});

// Delete account
app.post('/user/delete', async (req, res) => {
    try {
        const data = req.body;

        if (!data || !data.sessionKey) {
            return res.status(403).send("Unauthorized, please try to log in again.");
        }

        const userClient = new Client()
            .setEndpoint(process.env.APPWRITE_ENDPOINT)
            .setProject(process.env.APPWRITE_PROJECT_ID)
            .setJWT(data.sessionKey);

        const account = new Account(userClient);

        const user = await account.get();
        if (!user) {
            return res.status(403).send("Unauthorized, please try to log in again.");
        }

        const keysDatabase = new Databases(adminClient);

        const keys = await keysDatabase.listDocuments(
            process.env.APPWRITE_DATABASE_ID,
            process.env.APPWRITE_KEYS_ID,
            [
                Query.equal('userId', user.$id)
            ]);
        for (let key of keys.documents) {
            await keysDatabase.deleteDocument(
                process.env.APPWRITE_DATABASE_ID,
                process.env.APPWRITE_KEYS_ID,
                key.$id
            );
        }

        const uploadFolder = safeJoin(process.env.UPLOADS_FOLDER, user.$id);
        if (fs.existsSync(uploadFolder)) {
            fs.rmdirSync(uploadFolder, { recursive: true, force: true });
        }
        
        const users = new Users(adminClient);

        await users.delete(
            user.$id
        );

        res.json({success: true});
    }
    catch (error) {
        console.error("Error in file deletion:", error);
        res.status(500).send("Failed to delete account.");
    }
});

function humanFileSize(bytes, si = true, dp = 1) {
    const thresh = si ? 1000 : 1024;

    if (Math.abs(bytes) < thresh) {
        return bytes + ' B';
    }

    const units = si 
        ? ['kB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB'] 
        : ['KiB', 'MiB', 'GiB', 'TiB', 'PiB', 'EiB', 'ZiB', 'YiB'];
    let u = -1;
    const r = 10**dp;

    do {
        bytes /= thresh;
        ++u;
    } while (Math.round(Math.abs(bytes) * r) / r >= thresh && u < units.length - 1);


    return bytes.toFixed(dp) + ' ' + units[u];
}

// Fetch statistics
app.post('/f/all/stats', async (req, res) => {
    try {
        const data = req.body;

        if (!data || !data.sessionKey) {
            return res.status(403).send("Unauthorized, please try to log in again.");
        }

        const userClient = new Client()
            .setEndpoint(process.env.APPWRITE_ENDPOINT)
            .setProject(process.env.APPWRITE_PROJECT_ID)
            .setJWT(data.sessionKey);

        const account = new Account(userClient);

        const user = await account.get();
        if (!user) {
            return res.status(403).send("Unauthorized, please try to log in again.");
        }

        // Save key in database
        const keysDatabase = new Databases(adminClient);

        let pictures = await keysDatabase.listDocuments(
            process.env.APPWRITE_DATABASE_ID,
            process.env.APPWRITE_KEYS_ID,
            [
                Query.equal('userId', user.$id),
                Query.select(['views']),
                Query.limit(9999999)
            ]);

        var date7DaysAgo = new Date();
        date7DaysAgo.setDate(new Date().getDate() - 7);
        let picturesLast7Days = await keysDatabase.listDocuments(
            process.env.APPWRITE_DATABASE_ID,
            process.env.APPWRITE_KEYS_ID,
            [
                Query.equal('userId', user.$id),
                Query.select(['views']),
                Query.greaterThan('\$createdAt', date7DaysAgo.toISOString()),
                Query.limit(9999999)
            ]);
        
        const uploadFolder = safeJoin(process.env.UPLOADS_FOLDER, user.$id);

        // If directory doesnt exist create it
        if (!fs.existsSync(uploadFolder)) {
            fs.mkdirSync(uploadFolder);
        }
        
        let allSize = await dirSize(uploadFolder);

        let totalViews = 0;
        for (let i = 0; i < pictures.documents.length; i++) {
            totalViews += pictures.documents[i].views ?? 0;
        }
        
        res.json({
            spaceUsed: humanFileSize(allSize, true),
            views: totalViews,
            files7Days: picturesLast7Days.documents.length,
            totalFiles: pictures.total
        });
    }
    catch (error) {
        console.error("Error in fetching statistics:", error);
        res.status(500).send("Failed to fetch statistics.");
    }
});

const dirSize = async directory => {
  const files = await readdir( directory );
  const stats = files.map( file => stat( safeJoin( directory, file ) ) );

  return ( await Promise.all( stats ) ).reduce( ( accumulator, { size } ) => accumulator + size, 0 );
};

// Fetch gallery
app.post('/f/fetchGallery', async (req, res) => {
    try {
        const data = req.body;
        const fetchFrom = req.query["from"];
        const page = req.query["page"];
        const limit = req.query["limit"];

        if (!data || !data.sessionKey) {
            return res.status(403).send("Unauthorized, please try to log in again.");
        }

        if (limit > 100) {
            return res.status(400).send("Page limit cannot be higher than 100.");
        }

        const userClient = new Client()
            .setEndpoint(process.env.APPWRITE_ENDPOINT)
            .setProject(process.env.APPWRITE_PROJECT_ID)
            .setJWT(data.sessionKey);

        const account = new Account(userClient);

        const user = await account.get();
        if (!user) {
            return res.status(403).send("Unauthorized, please try to log in again.");
        }

        // Save key in database
        const keysDatabase = new Databases(adminClient);

        let pictures;

        if (fetchFrom) {
            pictures = await keysDatabase.listDocuments(
                process.env.APPWRITE_DATABASE_ID,
                process.env.APPWRITE_KEYS_ID,
                [
                    Query.equal('userId', user.$id),
                    Query.orderDesc('\$createdAt'),
                    Query.greaterThan('\$createdAt', fetchFrom)
                ]);
        } else if (page != null) {
            pictures = await keysDatabase.listDocuments(
                process.env.APPWRITE_DATABASE_ID,
                process.env.APPWRITE_KEYS_ID,
                [
                    Query.equal('userId', user.$id),
                    Query.orderDesc('\$createdAt'),
                    Query.limit(limit ?? 25),
                    Query.offset((page - 1) * (limit ?? 25))
                ]);
        } else {
            pictures = await keysDatabase.listDocuments(
                process.env.APPWRITE_DATABASE_ID,
                process.env.APPWRITE_KEYS_ID,
                [
                    Query.equal('userId', user.$id),
                    Query.orderDesc('\$createdAt'),
                    Query.limit(25),
                    Query.offset(0)
                ]);
        }
        
        const uploadFolder = safeJoin(process.env.UPLOADS_FOLDER, user.$id);

        // If directory doesnt exist create it
        if (!fs.existsSync(uploadFolder)) {
            fs.mkdirSync(uploadFolder);
        }
        
        let output = [];
        
        for (let picture of pictures.documents) {
            const key = picture.encryptionKey;
            output.push(`${req.get('host').includes("localhost") ? "http" : "https"}://${req.get('host')}/f/${picture.file}?c=${encodeURIComponent(key)}`);
        }
        res.json({
            total: pictures.total,
            limit: limit ?? 25,
            page: page ?? 1,
            totalPages: Math.ceil(pictures.total / (limit ?? 25)),
            documents: output
        });
    }
    catch (error) {
        console.error("Error in fetching gallery:", error);
        res.status(500).send("Failed to fetch gallery.");
    }
});

// Delete cap
app.post('/f/delete', async (req, res) => {
    try {
        const data = req.body;

        if (!data || !data.sessionKey) {
            return res.status(403).send("Unauthorized, please try to log in again.");
        }

        if (!data.file) {
            return res.status(400).send("File not included.");
        }

        const userClient = new Client()
            .setEndpoint(process.env.APPWRITE_ENDPOINT)
            .setProject(process.env.APPWRITE_PROJECT_ID)
            .setJWT(data.sessionKey);

        const account = new Account(userClient);

        const user = await account.get();
        if (!user) {
            return res.status(403).send("Unauthorized, please try to log in again.");
        }

        if (!/^[\w-]+\.(jpg|jpeg|png|gif)$/i.test(data.file)) {
            return res.status(400).send("Invalid file name.");
        }

        const filePath = safeJoin(process.env.UPLOADS_FOLDER, user.$id + "/" + data.file);
        
        try {
            // Remove key in database
            const keysDatabase = new Databases(adminClient);

            let fileKeys = await keysDatabase.listDocuments(
                process.env.APPWRITE_DATABASE_ID,
                process.env.APPWRITE_KEYS_ID,
                [
                    Query.equal('file', user.$id + "/" + data.file),
                    Query.equal('userId', user.$id)
                ]);
            
            for (let f of fileKeys.documents) {
                await keysDatabase.deleteDocument(
                    process.env.APPWRITE_DATABASE_ID,
                    process.env.APPWRITE_KEYS_ID,
                    f.$id);
            }

            // Delete file
            if (fs.existsSync(filePath)) {
                await fs.promises.rm(filePath);
            }
            
            res.json({success: true});
        }
        catch (error) {
            console.error("Error deleting files:", error);
            res.status(500).send("Failed to delete file.");
        }
    }
    catch (error) {
        console.error("Error in file deletion:", error);
        res.status(500).send("Failed to delete file.");
    }
});

// Upload limiter
const uploadLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 7, // max 7 uploads per minute per IP
    message: "Too many uploads, try later."
});
// Upload a file (directLink)
app.post('/f/u', uploadLimiter, async (req, res) => {
    try {
        const query = req.query;

        if (!query["k"]) {
            return res.status(400).send("Upload key not included.");
        }

        // Fetch key data
        const uploadKeysDatabase = new Databases(adminClient);
        const uploadKeys = await uploadKeysDatabase.listDocuments(
            process.env.APPWRITE_DATABASE_ID,
            process.env.APPWRITE_UPLOADKEYS_ID,
            [
                Query.equal("key", query["k"])
            ]);

        if (uploadKeys.documents.length <= 0) {
            return res.status(500).send("Failed to verify upload key. Please try to log in again.");
        }

        const userId = uploadKeys.documents[0].userId;
        const username = uploadKeys.documents[0].username;

        if (!req.files || !req.files.file) {
            return res.status(400).send("No file uploaded.");
        }

        const file = req.files.file;
        const allowedMimes = ["image/jpeg", "image/png", "image/gif"];

        if (!allowedMimes.includes(file.mimetype)) {
            return res.status(400).send("Invalid file type.");
        }

        let type = null;
        try {
            type = await validateFile(file);
        } catch (err) {
            console.error("File type:", type);
            return res.status(400).send("Invalid file type.");
        }

        if (file.size > MAX_FILE_SIZE) {
            return res.status(400).send("File too large.");
        }

        await uploadImage(userId, username, file, req ,res);
    }
    catch (error) {
        console.error("Error in file upload:", error);
        res.status(500).send("Failed to upload file.");
    }
});

// Upload a file
app.post('/f/upload', uploadLimiter, async (req, res) => {
    try {
        const data = req.body;

        if (!data || !data.sessionKey) {
            return res.status(403).send("Unauthorized, please try to log in again.");
        }

        const userClient = new Client()
            .setEndpoint(process.env.APPWRITE_ENDPOINT)
            .setProject(process.env.APPWRITE_PROJECT_ID)
            .setJWT(data.sessionKey);

        const account = new Account(userClient);

        const user = await account.get();
        if (!user) {
            return res.status(403).send("Unauthorized, please try to log in again.");
        }

        if (!req.files || !req.files.file) {
            return res.status(400).send("No file uploaded.");
        }

        const file = req.files.file;

        if (file.size > MAX_FILE_SIZE) {
            return res.status(400).send("File too large.");
        }
        
        uploadImage(user.$id, user.name, file, req ,res);
    }
    catch (error) {
        console.error("Error in file upload:", error);
        res.status(500).send("Failed to upload file.");
    }
});

async function uploadImage(userId, username, file, req, res) {
  try {
    // Validate size
    if (file.size > MAX_FILE_SIZE) {
      return res.status(400).send("File too large (max 5MB).");
    }

    // Validate type from buffer
    const type = await detectFileType(file.data);

    if (!type || !ALLOWED_EXTS.includes(type.ext)) {
        console.error("Invalid or unsupported file type: " + (type ? type.ext : "unknown"));
        return res.status(400).send("Invalid or unsupported file type.");
    }

    // Filename and extension
    const filename = uuid.v4() + ".jpg";
    const uploadFolder = safeJoin(process.env.UPLOADS_FOLDER, userId);
    const uploadPath = safeJoin(uploadFolder, filename);

    if (!fs.existsSync(uploadFolder)) {
      fs.mkdirSync(uploadFolder, { recursive: true });
    }

    // Compress image
    await sharp(file.data)
        .resize({ height: 2160, width: 2160, fit: "inside", withoutEnlargement: true })
        .jpeg({ quality: 92 })
        .toFile(uploadPath);

    // Encrypt compressed file
    const encryptKey = crypto.randomBytes(16); // AES-128
    const iv = crypto.randomBytes(12);         // 12-byte IV for GCM
    const compressedBuffer = fs.readFileSync(uploadPath);

    const cipher = crypto.createCipheriv("aes-128-gcm", encryptKey, iv);
    const encrypted = Buffer.concat([cipher.update(compressedBuffer), cipher.final()]);
    const authTag = cipher.getAuthTag();

    // Metadata buffers
    const expire = req.query.expire ? 1 : 0;
    const limitedTime = req.query.limitedTime ? 1 : 0;

    const settingsBuffer = Buffer.alloc(settingsBufferSize);
    settingsBuffer[0] = expire;
    settingsBuffer[1] = limitedTime;
    settingsBuffer.writeBigUInt64BE(BigInt(Date.now()), 2);

    const authorBuffer = Buffer.alloc(authorBufferSize);
    const author = `(${userId}) ${username}`;
    Buffer.from(author, "utf8").copy(authorBuffer, 0, 0, Math.min(author.length, authorBufferSize));

    // Write encrypted file
    const encryptedData = Buffer.concat([settingsBuffer, authorBuffer, iv, authTag, encrypted]);
    await fs.promises.writeFile(uploadPath, encryptedData);

    // Save encryption key
    let imageKeyBase64 = encryptKey.toString("base64").replace(/=+$/, "");
    const keysDatabase = new Databases(adminClient);
    await keysDatabase.createDocument(
        process.env.APPWRITE_DATABASE_ID,
        process.env.APPWRITE_KEYS_ID,
        ID.unique(),
        {
            file: `${userId}/${filename}`,
            encryptionKey: imageKeyBase64,
            userId: userId
        }
    );

    // Notify sockets
    const sockets = Array.from(connectedSockets.values())
      .filter((data) => data.userId === userId)
      .map((data) => data.socket);

    sockets.forEach((socket) => {
      try {
        socket.emit("addImage");
      } catch (error) {
        console.error(error);
      }
    });

    // Response
    res.json({
      filename,
      key: imageKeyBase64,
      url: `${req.get("host").includes("localhost") ? "http" : "https"}://${req.get("host")}/f/${userId}/${filename}?c=${encodeURIComponent(imageKeyBase64)}`
    });
  } catch (error) {
    console.error("Upload failed for userId:", userId, error.message);
    return res.status(500).send("Error uploading file.");
  }
}

// Read a file
app.get('/f/:userId/:filename', async (req, res) => {
    const filename = req.params.userId + "/" + req.params.filename;
    await handleReadFile(req, res, filename);
});

async function handleReadFile(req, res, filename) {
    const filePath = safeJoin(uploadDir, filename);
    const noView = req.query["noView"];

    if (!filename.endsWith(".jpg") || !fs.existsSync(filePath)) {
        res.setHeader('Cache-Control', 'no-store');
        const notFoundFileBuffer = fs.readFileSync("404.jpg");
        res.setHeader('Content-Type', 'image/jpeg');
        return res.send(notFoundFileBuffer);
    }
    
    try {
        const key = req.query.c || req.headers['x-file-key'];
        const fileBuffer = fs.readFileSync(filePath);
        const decryptedData = decrypt(fileBuffer, key, res);

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
                await fs.promises.writeFile(filePath, newFileBuffer);

                const expiredFileBuffer = fs.readFileSync("expired.jpg");
                res.setHeader('Content-Type', 'image/jpeg');
                return res.send(expiredFileBuffer);
            }
        }

        res.setHeader('Content-Type', 'image/jpeg');
        res.send(decryptedData.data);
        
        if (noView) {
            return;
        }

        // Save key in database
        const keysDatabase = new Databases(adminClient);

        let files = await keysDatabase.listDocuments(
            process.env.APPWRITE_DATABASE_ID,
            process.env.APPWRITE_KEYS_ID,
            [
                Query.equal('file', filename)
            ]);
        let fileId = files.documents[0].$id;
        let views = files.documents[0].views ?? 0;
        views++;
        await keysDatabase.updateDocument(
            process.env.APPWRITE_DATABASE_ID,
            process.env.APPWRITE_KEYS_ID,
            fileId,
            {
                views
            });
    } catch (error) {
        console.error("Error reading file:", error);
        const notFoundFileBuffer = fs.readFileSync("404.jpg");
        res.setHeader('Content-Type', 'image/jpeg');
        return res.send(notFoundFileBuffer);
    }
}

// Decrypt file encrypted with AES-128-GCM (iv + authTag + encrypted)
function decrypt(encryptedBuffer, keyBase64, res) {
    if (!keyBase64) throw new Error("Missing decryption key");

    const key = Buffer.from(keyBase64, 'base64');
    if (key.length !== 16) throw new Error("Invalid key length");

    try {
        const settings = encryptedBuffer.slice(0, settingsBufferSize);
        const author = encryptedBuffer.slice(settingsBufferSize, settingsBufferSize + authorBufferSize);
        const iv = encryptedBuffer.slice(settingsBufferSize + authorBufferSize, 12 + settingsBufferSize + authorBufferSize);
        const authTag = encryptedBuffer.slice(12 + settingsBufferSize + authorBufferSize, 28 + settingsBufferSize + authorBufferSize);
        const encrypted = encryptedBuffer.slice(28 + settingsBufferSize + authorBufferSize);

        const decipher = crypto.createDecipheriv('aes-128-gcm', key, iv);
        decipher.setAuthTag(authTag);

        return {
            data: Buffer.concat([decipher.update(encrypted), decipher.final()]),
            settings,
            author
        };
    } catch {
        throw new Error("Decryption failed");
    }
}

async function detectFileType(buffer) {
    const { fileTypeFromBuffer } = await import("file-type");
    return fileTypeFromBuffer(buffer);
}

function safeJoin(base, target) {
    const resolvedBase = path.resolve(base);
    const resolvedTarget = path.resolve(resolvedBase, target);

    // Allow exact match or subpath
    if (!resolvedTarget.startsWith(resolvedBase + path.sep) && resolvedTarget !== resolvedBase) {
        throw new Error("Invalid path.");
    }

    return resolvedTarget;
}
