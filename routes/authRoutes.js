const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const db = require('../db');
const { signSession, requireAuth } = require('../auth');

// Mismo algoritmo que usan los servidores de Minecraft en modo offline:
// UUID v3 (basado en nombre, MD5) de "OfflinePlayer:<username>". Es
// determinista y puramente una función del nombre, así que el servidor lo
// recalcula por su cuenta a partir del username recibido en vez de fiarse
// de un uuid que mande el cliente (evita que alguien pueda "elegir" el uuid
// que le apetezca).
function offlineUuidFromUsername(username) {
    const hash = crypto.createHash('md5').update(`OfflinePlayer:${username}`, 'utf8').digest();
    hash[6] = (hash[6] & 0x0f) | 0x30;
    hash[8] = (hash[8] & 0x3f) | 0x80;
    const hex = hash.toString('hex');
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

// El cliente nos manda el access_token que "msmc" obtuvo al iniciar sesión
// con Microsoft/Xbox. Lo verificamos directamente contra la API oficial de
// Mojang: si el token es válido, esa API nos devuelve el uuid y el username
// REALES asociados a él. Así nadie puede hacerse pasar por otro jugador
// inventándose un uuid a mano.
router.post('/verify', async (req, res) => {
    const { access_token } = req.body;
    if (!access_token) return res.status(400).json({ error: 'Falta access_token.' });

    try {
        const profileRes = await fetch('https://api.minecraftservices.com/minecraft/profile', {
            headers: { Authorization: `Bearer ${access_token}` }
        });

        if (!profileRes.ok) {
            return res.status(401).json({ error: 'El access_token no es válido según Mojang.' });
        }

        const profile = await profileRes.json();
        const uuid = profile.id;
        const username = profile.name;

        db.prepare(`
            INSERT INTO users (uuid, username, last_seen, premium) VALUES (?, ?, ?, 1)
            ON CONFLICT(uuid) DO UPDATE SET username = excluded.username, last_seen = excluded.last_seen, premium = 1
        `).run(uuid, username, Date.now());

        const row = db.prepare('SELECT token_version FROM users WHERE uuid = ?').get(uuid);
        const token = signSession(uuid, username, row.token_version);
        res.json({ token, uuid, username, premium: true });
    } catch (err) {
        console.error('[ERROR] /auth/verify:', err);
        res.status(500).json({ error: 'No se pudo verificar la cuenta con Mojang.' });
    }
});

// Cuentas offline ("no premium"): no hay ninguna identidad real que
// verificar contra Mojang, así que simplemente registramos el uuid
// determinista de ese username como cuenta premium=0. Pueden crear y
// unirse a modpacks igual que una cuenta Microsoft, pero requirePremium les
// bloquea generar invitaciones (ver modpackRoutes.js).
const OFFLINE_USERNAME_RE = /^[A-Za-z0-9_]{3,16}$/;
router.post('/verify-offline', (req, res) => {
    const username = typeof req.body.username === 'string' ? req.body.username.trim() : '';
    if (!OFFLINE_USERNAME_RE.test(username)) {
        return res.status(400).json({ error: 'Nombre de usuario no válido (3-16 caracteres: letras, números o guion bajo).' });
    }
    const uuid = offlineUuidFromUsername(username);

    const existing = db.prepare('SELECT premium FROM users WHERE uuid = ?').get(uuid);
    if (existing && existing.premium) {
        // Colisión prácticamente imposible con una cuenta Microsoft real (los
        // UUID offline son v3 y los de Microsoft v4), pero por si acaso no
        // dejamos que el flujo offline "reclame" una cuenta ya premium.
        return res.status(409).json({ error: 'Ese nombre de usuario ya está asociado a una cuenta premium.' });
    }

    db.prepare(`
        INSERT INTO users (uuid, username, last_seen, premium) VALUES (?, ?, ?, 0)
        ON CONFLICT(uuid) DO UPDATE SET username = excluded.username, last_seen = excluded.last_seen
    `).run(uuid, username, Date.now());

    const row = db.prepare('SELECT token_version FROM users WHERE uuid = ?').get(uuid);
    const token = signSession(uuid, username, row.token_version);
    res.json({ token, uuid, username, premium: false });
});

// Invalida de inmediato todos los JWT ya emitidos para este usuario
// (subiendo token_version, que requireAuth compara contra el "tv" del
// token). Antes "cerrar sesión" solo borraba la config local; un token
// copiado/filtrado seguía siendo válido en el servidor hasta caducar solo
// a los 30 días.
router.post('/logout', requireAuth, (req, res) => {
    db.prepare('UPDATE users SET token_version = token_version + 1 WHERE uuid = ?').run(req.user.uuid);
    res.json({ ok: true });
});

module.exports = router;
