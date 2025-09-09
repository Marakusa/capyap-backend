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
        res.status(500).send(error.message);
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

        const uploadFolder = path.join(__dirname, "uploads", user.$id);
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
        res.status(500).send(error.message);
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
        
        const uploadFolder = path.join(__dirname, "uploads", user.$id);

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
        console.error("Error in file upload:", error);
        res.status(500).send(error.message);
    }
});

const dirSize = async directory => {
  const files = await readdir( directory );
  const stats = files.map( file => stat( path.join( directory, file ) ) );

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
        
        const uploadFolder = path.join(__dirname, "uploads", user.$id);

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
        console.error("Error in file upload:", error);
        res.status(500).send(error.message);
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

        const filePath = path.join(__dirname, "uploads", data.file);

        // Delete file
        fs.rm(filePath, async (err, files) => {
            if (err) {
                return res.status(500).send(err);
            }
            try {
                // Remove key in database
                const keysDatabase = new Databases(adminClient);

                let fileKeys = await keysDatabase.listDocuments(
                    process.env.APPWRITE_DATABASE_ID,
                    process.env.APPWRITE_KEYS_ID,
                    [
                        Query.equal('file', data.file),
                        Query.equal('userId', user.$id)
                    ]);
                
                for (let f of fileKeys.documents) {
                    await keysDatabase.deleteDocument(
                        process.env.APPWRITE_DATABASE_ID,
                        process.env.APPWRITE_KEYS_ID,
                        f.$id);
                }
                res.json({success: true});
            }
            catch (error) {
                return res.status(500).send("Error deleting files: " + error.message);
            }
        });
    }
    catch (error) {
        console.error("Error in file deletion:", error);
        res.status(500).send(error.message);
    }
});

// Upload a file (directLink)
app.post('/f/u', async (req, res) => {
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

        let file = req.files.file;
        await uploadImage(userId, username, file, req ,res);
    }
    catch (error) {
        console.error("Error in file upload:", error);
        res.status(500).send(error.message);
    }
});

// Upload a file
app.post('/f/upload', async (req, res) => {
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

        let file = req.files.file;
        uploadImage(user.$id, user.name, file, req ,res);
    }
    catch (error) {
        console.error("Error in file upload:", error);
        res.status(500).send(error.message);
    }
});

async function uploadImage(userId, username, file, req ,res) {
    const filename = uuid.v4() + ".jpg";
    const uploadFolder = path.join(__dirname, "uploads", userId);
    const uploadPath = path.join(uploadFolder, filename);

    // If directory doesnt exist create it
    if (!fs.existsSync(uploadFolder)) {
        fs.mkdirSync(uploadFolder);
    }

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
            const author = `(${userId}) ${username}`;
            const authorBytes = Buffer.from(author, 'utf8');
            authorBytes.copy(authorBuffer, 0, 0, Math.min(authorBytes.length, authorBufferSize));
            
            // The rest remain zero
            const encryptedData = Buffer.concat([settingsBuffer, authorBuffer, iv, authTag, encrypted]);
            fs.writeFileSync(filePath, encryptedData);

            let imageKeyBase64 = encryptKey.toString('base64');
            imageKeyBase64 = imageKeyBase64.replace(/=+$/, ''); // Remove trailing '='

            // Save key in database
            const keysDatabase = new Databases(adminClient);

            keysDatabase.createDocument(
                process.env.APPWRITE_DATABASE_ID,
                process.env.APPWRITE_KEYS_ID,
                ID.unique(),
                {
                    file: `${userId}/${filename}`,
                    encryptionKey: imageKeyBase64,
                    userId: userId
                });
            
            const sockets = Array.from(connectedSockets.entries())
                .filter(([_, data]) => data.userId === userId)
                .map(([_, data]) => (data.socket));
            sockets.forEach((socket) => {
                try {
                    socket.emit('addImage');
                } catch (error) {
                    console.error(error);
                }
            });

            res.json({
                filename: filename,
                key: imageKeyBase64,
                url: `${req.get('host').includes("localhost") ? "http" : "https"}://${req.get('host')}/f/${userId}/${filename}?c=${encodeURIComponent(imageKeyBase64)}`
            });
        }
        catch (error) {
            return res.status(500).send("Error compressing file: " + error.message);
        }
    });
}

// Read a file
app.get('/f/:filename', async (req, res) => {
    const filename = req.params.filename;
    await handleReadFile(req, res, filename);
});

// Read a file
app.get('/f/:userId/:filename', async (req, res) => {
    const filename = req.params.userId + "/" + req.params.filename;
    await handleReadFile(req, res, filename);
});

async function handleReadFile(req, res, filename) {
    const filePath = path.join(uploadDir, filename);
    const noView = req.query["noView"];

    if (!filename.endsWith(".jpg") || !fs.existsSync(filePath)) {
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
            .jpeg({ quality: 92 }) // Set JPEG quality to 92%
            .toFile(filePath);
        return filePath;
    } catch (error) {
        console.error("Error compressing image:", error);
        throw error;
    }
}
