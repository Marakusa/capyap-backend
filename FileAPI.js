const axios = require('axios');
const path = require('path');
const FormData = require('form-data');

const API_BASE = process.env.CAPYAP_API_BASE;
const API_KEY = process.env.CAPYAP_API_KEY;

function joinPath(folder, file = '') {
    return path.posix.join(folder, file);
}

const FileAPI = {
    resolvePath: (folder, file = '') => joinPath(folder, file),

    exists: async (filePath) => {
        try {
            const res = await axios.head(`${API_BASE}/${filePath}`, {
                headers: { 'X-Api-Key': API_KEY }
            });
            return res.status === 200;
        } catch {
            return false;
        }
    },

    readFile: async (filePath) => {
        const res = await axios.get(`${API_BASE}/${filePath}`, {
            headers: { 'X-Api-Key': API_KEY },
            responseType: 'arraybuffer'
        });
        return Buffer.from(res.data);
    },

    listFiles: async (folder) => {
        const res = await axios.get(`${API_BASE}/${folder}`, {
            headers: { 'X-Api-Key': API_KEY }
        });
        return res.data.files;
    },

    getStats: async (filePath) => {
        const res = await axios.head(`${API_BASE}/${filePath}`, {
            headers: { 'X-Api-Key': API_KEY }
        });
        return {
            size: parseInt(res.headers['content-length'], 10),
            createdAt: new Date(res.headers['created-at']),
            modifiedAt: new Date(res.headers['last-modified'])
        };
    },

    writeFile: async (filePath, buffer) => {
        const formData = new FormData();
        formData.append('file', buffer, { filename: path.basename(filePath) });

        const res = await axios.post(`${API_BASE}/${filePath}`, formData, {
            headers: {
                'X-Api-Key': API_KEY,
                ...formData.getHeaders()
            }
        });
        return res.data;
    },

    mkdir: async (dirPath) => {
        const res = await axios.post(`${API_BASE}/${dirPath}`, null, {
            headers: { 'X-Api-Key': API_KEY }
        });
        return res.data;
    },

    deleteFile: async (filePath) => {
        await axios.delete(`${API_BASE}/${filePath}`, {
            headers: { 'X-Api-Key': API_KEY }
        });
    },

    deleteDirectory: async (folder) => {
        await axios.delete(`${API_BASE}/${folder}`, {
            headers: { 'X-Api-Key': API_KEY }
        });
    },

    fileExists: async (filePath) => {
        try {
            const res = await axios.head(`${API_BASE}/${filePath}`, {
                headers: { 'X-Api-Key': API_KEY }
            });
            return res.status === 200;
        } catch {
            return false;
        }
    },

    dirExists: async (folder) => {
        try {
            const res = await axios.get(`${API_BASE}/${folder}`, {
                headers: { 'X-Api-Key': API_KEY }
            });
            return res.status === 200;
        } catch {
            return false;
        }
    }
};

module.exports = FileAPI;
