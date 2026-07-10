const jwt = require('jsonwebtoken');
require('dotenv').config();

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
    console.error('[FATAL] Falta JWT_SECRET en el archivo .env. Copia .env.example a .env y rellénalo.');
    process.exit(1);
}

function signSession(uuid, username) {
    return jwt.sign({ sub: uuid, username }, JWT_SECRET, { expiresIn: '30d' });
}

function requireAuth(req, res, next) {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : null;
    if (!token) return res.status(401).json({ error: 'Falta token de autenticación.' });
    try {
        const payload = jwt.verify(token, JWT_SECRET);
        req.user = { uuid: payload.sub, username: payload.username };
        next();
    } catch (err) {
        return res.status(401).json({ error: 'Token inválido o caducado. Vuelve a iniciar sesión.' });
    }
}

module.exports = { signSession, requireAuth };
