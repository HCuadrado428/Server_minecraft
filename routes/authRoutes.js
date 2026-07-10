const express = require('express');
const router = express.Router();
const db = require('../db');
const { signSession } = require('../auth');

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
            INSERT INTO users (uuid, username, last_seen) VALUES (?, ?, ?)
            ON CONFLICT(uuid) DO UPDATE SET username = excluded.username, last_seen = excluded.last_seen
        `).run(uuid, username, Date.now());

        const token = signSession(uuid, username);
        res.json({ token, uuid, username });
    } catch (err) {
        console.error('[ERROR] /auth/verify:', err);
        res.status(500).json({ error: 'No se pudo verificar la cuenta con Mojang.' });
    }
});

module.exports = router;
