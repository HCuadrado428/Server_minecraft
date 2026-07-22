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

    const pack = db.prepare('SELECT * FROM modpacks WHERE id = ?').get(invite.modpack_id);
    if (!pack) return res.status(404).json({ error: 'El modpack de esta invitación ya no existe.' });

    // Si el usuario ya tiene acceso (p.ej. reabre el mismo link, o un doble
    // click en el botón de unirse) esto es un no-op y no debe ni gastar
    // cupo de max_uses ni bloquearse aunque el invite ya esté agotado: no se
    // está concediendo ningún acceso nuevo, así que no cuenta como un "uso"
    // más. Antes el aforo se comprobaba antes de saber esto, así que
    // redimir dos veces el mismo invite gastaba cupo real sin añadir a
    // nadie nuevo, pudiendo rechazar a gente real más tarde.
    const alreadyHasAccess = db.prepare('SELECT 1 FROM access WHERE modpack_id = ? AND user_uuid = ?')
        .get(invite.modpack_id, req.user.uuid);

    if (!alreadyHasAccess) {
        if (invite.max_uses && invite.uses >= invite.max_uses) {
            return res.status(410).json({ error: 'Esta invitación ya se ha usado el máximo de veces permitido.' });
        }
        db.prepare('INSERT INTO access (modpack_id, user_uuid, granted_at) VALUES (?, ?, ?)')
            .run(invite.modpack_id, req.user.uuid, Date.now());
        db.prepare('UPDATE invites SET uses = uses + 1 WHERE token = ?').run(invite.token);
    }

    res.json({ modpack: { id: pack.id, name: pack.name, mc_version: pack.mc_version } });
});

module.exports = router;
