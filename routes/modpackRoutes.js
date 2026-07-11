const express = require('express');
const router = express.Router();
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const db = require('../db');
const { requireAuth } = require('../auth');

const STORAGE_DIR = process.env.STORAGE_DIR || path.join(__dirname, '..', 'storage');

function modpackDir(id) {
    return path.join(STORAGE_DIR, id);
}

function ensureDir(dir) {
    fs.mkdirSync(dir, { recursive: true });
}

const MOD_TYPES = ['mod', 'resourcepack'];
const EXTENSION_BY_TYPE = { mod: '.jar', resourcepack: '.zip' };

const upload = multer({
    storage: multer.diskStorage({
        destination: (req, file, cb) => {
            const dir = modpackDir(req.params.id);
            ensureDir(dir);
            cb(null, dir);
        },
        filename: (req, file, cb) => {
            // Conservamos el nombre original del archivo, quitando caracteres raros
            const safe = file.originalname.replace(/[^a-zA-Z0-9._-]/g, '_');
            cb(null, Date.now() + '-' + safe);
        }
    }),
    fileFilter: (req, file, cb) => {
        const type = MOD_TYPES.includes(req.body.type) ? req.body.type : 'mod';
        const expectedExt = EXTENSION_BY_TYPE[type];
        if (!file.originalname.toLowerCase().endsWith(expectedExt)) {
            return cb(new Error(`Se esperaba un archivo ${expectedExt} para el tipo "${type}".`));
        }
        cb(null, true);
    },
    limits: { fileSize: 512 * 1024 * 1024 } // 512MB por archivo, de sobra para un mod o resource pack
});

function sha1File(filePath) {
    return new Promise((resolve, reject) => {
        const hash = crypto.createHash('sha1');
        const stream = fs.createReadStream(filePath);
        stream.on('data', (chunk) => hash.update(chunk));
        stream.on('end', () => resolve(hash.digest('hex')));
        stream.on('error', reject);
    });
}

// El "version_hash" es lo que el launcher de cada jugador compara para saber
// si el modpack ha cambiado desde la última vez. Se recalcula cada vez que
// se añade o se quita un mod.
function recomputeVersionHash(modpackId) {
    const mods = db.prepare('SELECT id, sha1 FROM mods WHERE modpack_id = ? ORDER BY id').all(modpackId);
    const combined = mods.map(m => `${m.id}:${m.sha1}`).join('|');
    const hash = crypto.createHash('sha256').update(combined).digest('hex');
    db.prepare('UPDATE modpacks SET version_hash = ?, updated_at = ? WHERE id = ?')
        .run(hash, Date.now(), modpackId);
    return hash;
}

// Distinguimos "el modpack no existe" (404, p.ej. porque el creador lo
// borró) de "el modpack existe pero no tienes acceso" (403). Esto es lo que
// permite a los launchers detectar un borrado real cuando sincronizan.
function requireAccess(req, res, next) {
    const pack = db.prepare('SELECT owner_uuid FROM modpacks WHERE id = ?').get(req.params.id);
    if (!pack) return res.status(404).json({ error: 'Modpack no encontrado.' });
    if (pack.owner_uuid !== req.user.uuid) {
        const row = db.prepare('SELECT 1 FROM access WHERE modpack_id = ? AND user_uuid = ?').get(req.params.id, req.user.uuid);
        if (!row) return res.status(403).json({ error: 'No tienes acceso a este modpack. Pide un link de invitación al creador.' });
    }
    next();
}

function requireOwner(req, res, next) {
    const pack = db.prepare('SELECT owner_uuid FROM modpacks WHERE id = ?').get(req.params.id);
    if (!pack) return res.status(404).json({ error: 'Modpack no encontrado.' });
    if (pack.owner_uuid !== req.user.uuid) {
        return res.status(403).json({ error: 'Solo el creador del modpack puede hacer esto.' });
    }
    next();
}

router.use(requireAuth);

const LOADERS = ['vanilla', 'forge', 'fabric'];

// --- Crear modpack ---
router.post('/', (req, res) => {
    const { name, mc_version } = req.body;
    const loader = LOADERS.includes(req.body.loader) ? req.body.loader : 'vanilla';
    // La versión del loader es opcional: si no se manda (o el loader es
    // vanilla), el launcher resolverá la recomendada automáticamente al
    // sincronizar.
    const loaderVersion = loader !== 'vanilla' && typeof req.body.loader_version === 'string'
        ? req.body.loader_version.trim()
        : '';
    if (!name || !mc_version) return res.status(400).json({ error: 'Faltan "name" o "mc_version".' });

    const id = crypto.randomUUID();
    const now = Date.now();
    db.prepare(`
        INSERT INTO modpacks (id, name, mc_version, loader, loader_version, owner_uuid, version_hash, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, '', ?, ?)
    `).run(id, name, mc_version, loader, loaderVersion, req.user.uuid, now, now);

    db.prepare('INSERT INTO access (modpack_id, user_uuid, granted_at) VALUES (?, ?, ?)')
        .run(id, req.user.uuid, now);

    res.json({ id, name, mc_version, loader, loader_version: loaderVersion, owner_uuid: req.user.uuid, version_hash: '' });
});

// --- Mis modpacks (los que creé + los que me han compartido) ---
router.get('/mine', (req, res) => {
    const owned = db.prepare('SELECT * FROM modpacks WHERE owner_uuid = ?').all(req.user.uuid);
    const shared = db.prepare(`
        SELECT m.* FROM modpacks m
        INNER JOIN access a ON a.modpack_id = m.id
        WHERE a.user_uuid = ? AND m.owner_uuid != ?
    `).all(req.user.uuid, req.user.uuid);

    res.json({
        owned: owned.map(p => ({ ...p, is_owner: true })),
        shared: shared.map(p => ({ ...p, is_owner: false }))
    });
});

// --- Manifiesto (lista de mods + hash de versión) de un modpack ---
router.get('/:id/manifest', requireAccess, (req, res) => {
    const pack = db.prepare('SELECT * FROM modpacks WHERE id = ?').get(req.params.id);
    if (!pack) return res.status(404).json({ error: 'Modpack no encontrado.' });
    const mods = db.prepare('SELECT id, filename, filesize, sha1, type, source, download_url FROM mods WHERE modpack_id = ?').all(pack.id);
    res.json({
        id: pack.id,
        name: pack.name,
        mc_version: pack.mc_version,
        loader: pack.loader,
        loader_version: pack.loader_version || '',
        version_hash: pack.version_hash,
        mods
    });
});

// --- Añadir mod o resource pack (solo el dueño) ---
// El campo "type" debe ir ANTES del archivo en el FormData: multer procesa
// el multipart en orden y solo los campos ya vistos están en req.body
// cuando se ejecuta fileFilter.
router.post('/:id/mods', requireOwner, upload.single('mod'), async (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'Falta el archivo del mod (campo "mod").' });
    const type = MOD_TYPES.includes(req.body.type) ? req.body.type : 'mod';

    try {
        const sha1 = await sha1File(req.file.path);
        const modId = crypto.randomUUID();
        db.prepare(`
            INSERT INTO mods (id, modpack_id, filename, filesize, sha1, type, added_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        `).run(modId, req.params.id, req.file.filename, req.file.size, sha1, type, Date.now());

        const versionHash = recomputeVersionHash(req.params.id);
        res.json({ id: modId, filename: req.file.filename, filesize: req.file.size, sha1, type, version_hash: versionHash });
    } catch (err) {
        console.error('[ERROR] al procesar el mod subido:', err);
        res.status(500).json({ error: 'No se pudo procesar el archivo subido.' });
    }
});

// --- Añadir mod/resource pack desde Modrinth (solo el dueño) ---
// El cliente solo manda IDs; nunca confiamos en nombre/tamaño/hash que venga
// del launcher. Volvemos a pedirle los datos reales a la API de Modrinth
// (pública, sin key) y guardamos eso.
router.post('/:id/mods/from-modrinth', requireOwner, async (req, res) => {
    const { project_id, version_id } = req.body || {};
    const type = MOD_TYPES.includes(req.body.type) ? req.body.type : 'mod';
    if (!project_id || !version_id) return res.status(400).json({ error: 'Faltan "project_id" o "version_id".' });

    let version;
    try {
        const modrinthRes = await fetch(`https://api.modrinth.com/v2/version/${encodeURIComponent(version_id)}`, {
            headers: { 'User-Agent': 'EmberLauncher/1.0 (github.com/HCuadrado428/Launcher)' }
        });
        if (!modrinthRes.ok) return res.status(400).json({ error: `Modrinth respondió con estado ${modrinthRes.status} al consultar la versión.` });
        version = await modrinthRes.json();
    } catch (err) {
        console.error('[ERROR] al consultar Modrinth:', err);
        return res.status(502).json({ error: 'No se pudo contactar con Modrinth.' });
    }

    if (version.project_id !== project_id) {
        return res.status(400).json({ error: 'El project_id no coincide con la versión indicada.' });
    }
    const file = version.files.find((f) => f.primary) || version.files[0];
    if (!file) return res.status(400).json({ error: 'Esa versión de Modrinth no tiene ningún archivo descargable.' });

    const existing = db.prepare('SELECT id FROM mods WHERE modpack_id = ? AND external_project_id = ? AND source = ?')
        .get(req.params.id, project_id, 'modrinth');
    if (existing) return res.status(409).json({ error: 'Ese mod de Modrinth ya está en el modpack.' });

    const modId = crypto.randomUUID();
    db.prepare(`
        INSERT INTO mods (id, modpack_id, filename, filesize, sha1, type, source, download_url, external_project_id, external_version_id, added_at)
        VALUES (?, ?, ?, ?, ?, ?, 'modrinth', ?, ?, ?, ?)
    `).run(modId, req.params.id, file.filename, file.size, file.hashes.sha1, type, file.url, project_id, version_id, Date.now());

    const versionHash = recomputeVersionHash(req.params.id);
    res.json({ id: modId, filename: file.filename, filesize: file.size, sha1: file.hashes.sha1, type, source: 'modrinth', version_hash: versionHash });
});

// --- Quitar mod (solo el dueño) ---
router.delete('/:id/mods/:modId', requireOwner, (req, res) => {
    const mod = db.prepare('SELECT * FROM mods WHERE id = ? AND modpack_id = ?').get(req.params.modId, req.params.id);
    if (!mod) return res.status(404).json({ error: 'Mod no encontrado.' });

    const filePath = path.join(modpackDir(req.params.id), mod.filename);
    fs.unlink(filePath, () => {}); // si ya no está en disco, no pasa nada

    db.prepare('DELETE FROM mods WHERE id = ?').run(mod.id);
    const versionHash = recomputeVersionHash(req.params.id);
    res.json({ ok: true, version_hash: versionHash });
});

// --- Descargar un mod (cualquiera con acceso al modpack) ---
router.get('/:id/mods/:modId/download', requireAccess, (req, res) => {
    const mod = db.prepare('SELECT * FROM mods WHERE id = ? AND modpack_id = ?').get(req.params.modId, req.params.id);
    if (!mod) return res.status(404).json({ error: 'Mod no encontrado.' });
    const filePath = path.join(modpackDir(req.params.id), mod.filename);
    res.download(filePath, mod.filename);
});

// --- Crear link de invitación (solo el dueño) ---
router.post('/:id/invite', requireOwner, (req, res) => {
    const { max_uses, expires_in_hours } = req.body || {};
    const token = crypto.randomBytes(16).toString('hex');
    const now = Date.now();
    const expiresAt = expires_in_hours ? now + expires_in_hours * 3600 * 1000 : null;

    db.prepare(`
        INSERT INTO invites (token, modpack_id, created_by, max_uses, uses, expires_at, created_at)
        VALUES (?, ?, ?, ?, 0, ?, ?)
    `).run(token, req.params.id, req.user.uuid, max_uses || null, expiresAt, now);

    res.json({ token, url: `milauncher://invite/${token}` });
});

// --- Eliminar modpack (solo el dueño) ---
// Borra en cascada mods/invitaciones/accesos y los archivos en disco. A
// partir de aquí, cualquier launcher que intente sincronizar este modpack
// recibirá un 404 (ver requireAccess) y limpiará su instalación local.
router.delete('/:id', requireOwner, (req, res) => {
    const id = req.params.id;
    db.prepare('DELETE FROM mods WHERE modpack_id = ?').run(id);
    db.prepare('DELETE FROM invites WHERE modpack_id = ?').run(id);
    db.prepare('DELETE FROM access WHERE modpack_id = ?').run(id);
    db.prepare('DELETE FROM modpacks WHERE id = ?').run(id);
    fs.rm(modpackDir(id), { recursive: true, force: true }, () => {});
    res.json({ ok: true });
});

module.exports = router;
