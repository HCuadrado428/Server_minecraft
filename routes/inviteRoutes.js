const express = require('express');
const router = express.Router();
const db = require('../db');
const { requireAuth } = require('../auth');

router.use(requireAuth);

// Canjear un link de invitación: da acceso al modpack al usuario autenticado.
router.post('/:token/redeem', (req, res) => {
    const invite = db.prepare('SELECT * FROM invites WHERE token = ?').get(req.params.token);
    if (!invite) return res.status(404).json({ error: 'El link de invitación no existe o ya no es válido.' });

    if (invite.expires_at && Date.now() > invite.expires_at) {
        return res.status(410).json({ error: 'Esta invitación ha caducado.' });
    }
    if (invite.max_uses && invite.uses >= invite.max_uses) {
        return res.status(410).json({ error: 'Esta invitación ya se ha usado el máximo de veces permitido.' });
    }

    const pack = db.prepare('SELECT * FROM modpacks WHERE id = ?').get(invite.modpack_id);
    if (!pack) return res.status(404).json({ error: 'El modpack de esta invitación ya no existe.' });

    db.prepare(`
        INSERT INTO access (modpack_id, user_uuid, granted_at) VALUES (?, ?, ?)
        ON CONFLICT(modpack_id, user_uuid) DO NOTHING
    `).run(invite.modpack_id, req.user.uuid, Date.now());

    db.prepare('UPDATE invites SET uses = uses + 1 WHERE token = ?').run(invite.token);

    res.json({ modpack: { id: pack.id, name: pack.name, mc_version: pack.mc_version } });
});

module.exports = router;
