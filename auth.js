const jwt = require('jsonwebtoken');
const db = require('./db');
require('dotenv').config();

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
    console.error('[FATAL] Falta JWT_SECRET en el archivo .env. Copia .env.example a .env y rellénalo.');
    process.exit(1);
}

// El JWT lleva embebido el token_version vigente en el momento de firmarlo
// ("tv"). Si el usuario hace logout explícito, token_version sube en la BD
// y todos los tokens firmados antes (con un "tv" más bajo) dejan de ser
// válidos de inmediato, aunque todavía no hayan caducado por fecha.
function signSession(uuid, username, tokenVersion) {
    return jwt.sign({ sub: uuid, username, tv: tokenVersion || 0 }, JWT_SECRET, { expiresIn: '30d' });
}

// Se aprovecha esta misma consulta (por uuid, clave primaria) para adjuntar
// también si la cuenta es premium: así requirePremium en las rutas no
// necesita otra consulta aparte.
function requireAuth(req, res, next) {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : null;
    if (!token) return res.status(401).json({ error: 'Falta token de autenticación.' });
    try {
        const payload = jwt.verify(token, JWT_SECRET);
        const user = db.prepare('SELECT username, premium, token_version FROM users WHERE uuid = ?').get(payload.sub);
        if (!user || (payload.tv || 0) !== user.token_version) {
            return res.status(401).json({ error: 'Token inválido o caducado. Vuelve a iniciar sesión.' });
        }
        req.user = { uuid: payload.sub, username: user.username, premium: !!user.premium };
        next();
    } catch (err) {
        return res.status(401).json({ error: 'Token inválido o caducado. Vuelve a iniciar sesión.' });
    }
}

function requirePremium(req, res, next) {
    if (!req.user.premium) {
        return res.status(403).json({
            error: 'Compartir modpacks requiere una cuenta de Minecraft premium (verificada con Microsoft). Puedes seguir creando modpacks propios y uniéndote a los que te compartan.'
        });
    }
    next();
}

module.exports = { signSession, requireAuth, requirePremium };
