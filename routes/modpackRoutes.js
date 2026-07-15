const express = require('express');
const router = express.Router();
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const AdmZip = require('adm-zip');
const db = require('../db');
const { requireAuth, requirePremium } = require('../auth');

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

// Sin esto, cualquier cuenta autenticada podía subir archivos de hasta
// 512MB sin límite de cantidad ni de total acumulado, llenando el disco del
// servidor Railway. MAX_MODS_PER_MODPACK evita además manifiestos gigantes
// que tardarían cada vez más en sincronizar en cada launcher.
const MAX_BYTES_PER_OWNER = 5 * 1024 * 1024 * 1024; // 5GB en total, sumando todos los modpacks de un mismo creador
const MAX_MODS_PER_MODPACK = 300;

// Los mods con source='modrinth' nunca se suben a STORAGE_DIR (solo se
// guarda su download_url, el archivo real vive en la CDN de Modrinth), así
// que no deben contar contra la cuota de disco del servidor. Antes sí se
// sumaban, lo que podía bloquear subidas reales a alguien que solo hubiera
// añadido mods grandes desde Modrinth sin haber ocupado nada de verdad.
function getOwnerStorageBytes(ownerUuid) {
    const row = db.prepare(`
        SELECT COALESCE(SUM(mo.filesize), 0) AS total
        FROM mods mo
        INNER JOIN modpacks mp ON mp.id = mo.modpack_id
        WHERE mp.owner_uuid = ? AND mo.source != 'modrinth'
    `).get(ownerUuid);
    return row.total;
}

function enforceModCountLimit(req, res, next) {
    const modCount = db.prepare('SELECT COUNT(*) AS c FROM mods WHERE modpack_id = ?').get(req.params.id).c;
    if (modCount >= MAX_MODS_PER_MODPACK) {
        return res.status(413).json({ error: `Este modpack ya tiene el máximo de ${MAX_MODS_PER_MODPACK} archivos.` });
    }
    next();
}

function enforceUploadQuota(req, res, next) {
    if (getOwnerStorageBytes(req.user.uuid) >= MAX_BYTES_PER_OWNER) {
        return res.status(413).json({ error: 'Has alcanzado tu límite de almacenamiento (5GB en total entre todos tus modpacks). Borra algún mod para liberar espacio.' });
    }
    enforceModCountLimit(req, res, next);
}

// Intenta leer el identificador real del mod (modid) desde los metadatos que
// trae el propio .jar, para poder avisar si dos mods del mismo modpack
// proveen el mismo mod (p.ej. el mismo mod subido dos veces con nombres de
// archivo distintos, o una versión vieja y una nueva sin borrar la anterior).
// Si el jar no tiene ninguno de los formatos conocidos o está corrupto, no
// bloqueamos la subida: simplemente no se guarda identificador.
function extractModId(jarPath) {
    try {
        const zip = new AdmZip(jarPath);

        const fabricEntry = zip.getEntry('fabric.mod.json');
        if (fabricEntry) {
            const json = JSON.parse(zip.readAsText(fabricEntry));
            if (json && typeof json.id === 'string' && json.id) return json.id;
        }

        const forgeEntry = zip.getEntry('META-INF/mods.toml');
        if (forgeEntry) {
            const text = zip.readAsText(forgeEntry);
            const match = text.match(/modId\s*=\s*"([^"]+)"/);
            if (match) return match[1];
        }

        const oldForgeEntry = zip.getEntry('mcmod.info');
        if (oldForgeEntry) {
            const parsed = JSON.parse(zip.readAsText(oldForgeEntry));
            const list = Array.isArray(parsed) ? parsed : parsed.modList;
            if (Array.isArray(list) && list[0] && typeof list[0].modid === 'string') return list[0].modid;
        }
    } catch (err) {
        // Jar corrupto o formato de metadatos no reconocido: no es un error fatal.
    }
    return null;
}

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

// Guarda una "foto" de la lista de mods tal cual está justo ANTES de
// aplicar un cambio (añadir/quitar un mod), para poder volver a ese estado
// si una edición posterior rompe el modpack para todos los que sincronizan.
// Se limita a las últimas MAX_VERSION_SNAPSHOTS por modpack para no crecer
// sin límite.
const MAX_VERSION_SNAPSHOTS = 15;
function snapshotModpackVersion(modpackId) {
    const pack = db.prepare('SELECT version_hash FROM modpacks WHERE id = ?').get(modpackId);
    if (!pack) return;
    const mods = db.prepare(`
        SELECT id, filename, filesize, sha1, type, optional, source, download_url,
               external_project_id, external_version_id, mod_identifier
        FROM mods WHERE modpack_id = ?
    `).all(modpackId);

    db.prepare(`
        INSERT INTO modpack_versions (id, modpack_id, version_hash, mods_json, created_at)
        VALUES (?, ?, ?, ?, ?)
    `).run(crypto.randomUUID(), modpackId, pack.version_hash, JSON.stringify(mods), Date.now());

    const excess = db.prepare(`
        SELECT id FROM modpack_versions WHERE modpack_id = ? ORDER BY created_at DESC LIMIT -1 OFFSET ?
    `).all(modpackId, MAX_VERSION_SNAPSHOTS);
    for (const row of excess) {
        db.prepare('DELETE FROM modpack_versions WHERE id = ?').run(row.id);
    }
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

// --- Cuánto espacio ocupa el usuario, para mostrar una barra de uso en el
// launcher antes de que se tope con el 413 al subir algo. ---
router.get('/storage', (req, res) => {
    res.json({ used_bytes: getOwnerStorageBytes(req.user.uuid), limit_bytes: MAX_BYTES_PER_OWNER });
});

const LOADERS = ['vanilla', 'forge', 'fabric'];

// Cubre versiones release ("1.21.1"), pre-release/candidate ("1.21-pre1",
// "1.21-rc1") y snapshots ("24w14a"). No es exhaustivo al 100% frente al
// manifiesto real de Mojang, pero rechaza de entrada la basura obvia (vacío,
// con espacios, con HTML, etc.) en vez de que el error aparezca mucho más
// tarde y de forma confusa dentro del instalador del launcher.
const MC_VERSION_RE = /^([0-9]+\.[0-9]+(\.[0-9]+)?(-(pre|rc)[0-9]+)?|[0-9]{2}w[0-9]{2}[a-z])$/i;
const MAX_MODPACK_NAME_LENGTH = 80;

// --- Crear modpack ---
router.post('/', (req, res) => {
    const name = typeof req.body.name === 'string' ? req.body.name.trim() : '';
    const mc_version = typeof req.body.mc_version === 'string' ? req.body.mc_version.trim() : '';
    const loader = LOADERS.includes(req.body.loader) ? req.body.loader : 'vanilla';
    // La versión del loader es opcional: si no se manda (o el loader es
    // vanilla), el launcher resolverá la recomendada automáticamente al
    // sincronizar.
    const loaderVersion = loader !== 'vanilla' && typeof req.body.loader_version === 'string'
        ? req.body.loader_version.trim()
        : '';
    if (!name || !mc_version) return res.status(400).json({ error: 'Faltan "name" o "mc_version".' });
    if (name.length > MAX_MODPACK_NAME_LENGTH) {
        return res.status(400).json({ error: `El nombre no puede superar los ${MAX_MODPACK_NAME_LENGTH} caracteres.` });
    }
    if (!MC_VERSION_RE.test(mc_version)) {
        return res.status(400).json({ error: `"${mc_version}" no parece una versión válida de Minecraft (ej: 1.21.1, 24w14a).` });
    }

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
// MAX_MODPACKS_PER_SIDE limita el peor caso (una cuenta con cientos de
// modpacks propios/compartidos) sin necesitar que el launcher mande
// limit/offset: es un techo de seguridad, no paginación completa.
const MAX_MODPACKS_PER_SIDE = 200;
router.get('/mine', (req, res) => {
    const owned = db.prepare('SELECT * FROM modpacks WHERE owner_uuid = ? ORDER BY updated_at DESC LIMIT ?')
        .all(req.user.uuid, MAX_MODPACKS_PER_SIDE);
    const shared = db.prepare(`
        SELECT m.* FROM modpacks m
        INNER JOIN access a ON a.modpack_id = m.id
        WHERE a.user_uuid = ? AND m.owner_uuid != ?
        ORDER BY m.updated_at DESC LIMIT ?
    `).all(req.user.uuid, req.user.uuid, MAX_MODPACKS_PER_SIDE);

    res.json({
        owned: owned.map(p => ({ ...p, is_owner: true })),
        shared: shared.map(p => ({ ...p, is_owner: false }))
    });
});

// --- Manifiesto (lista de mods + hash de versión) de un modpack ---
router.get('/:id/manifest', requireAccess, (req, res) => {
    const pack = db.prepare('SELECT * FROM modpacks WHERE id = ?').get(req.params.id);
    if (!pack) return res.status(404).json({ error: 'Modpack no encontrado.' });
    const mods = db.prepare('SELECT id, filename, filesize, sha1, type, source, download_url, optional FROM mods WHERE modpack_id = ?').all(pack.id);
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
router.post('/:id/mods', requireOwner, enforceUploadQuota, upload.single('mod'), async (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'Falta el archivo del mod (campo "mod").' });
    const type = MOD_TYPES.includes(req.body.type) ? req.body.type : 'mod';
    const optional = req.body.optional === 'true' || req.body.optional === '1' ? 1 : 0;

    try {
        const sha1 = await sha1File(req.file.path);
        const modIdentifier = type === 'mod' ? extractModId(req.file.path) : null;

        if (modIdentifier) {
            const conflict = db.prepare('SELECT filename FROM mods WHERE modpack_id = ? AND mod_identifier = ?')
                .get(req.params.id, modIdentifier);
            if (conflict) {
                fs.unlink(req.file.path, () => {});
                return res.status(409).json({
                    error: `Este modpack ya tiene un mod con el mismo modid ("${modIdentifier}"): ${conflict.filename}. Quítalo antes de añadir este.`
                });
            }
        }

        snapshotModpackVersion(req.params.id);
        const modId = crypto.randomUUID();
        db.prepare(`
            INSERT INTO mods (id, modpack_id, filename, filesize, sha1, type, optional, mod_identifier, added_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).run(modId, req.params.id, req.file.filename, req.file.size, sha1, type, optional, modIdentifier || '', Date.now());

        const versionHash = recomputeVersionHash(req.params.id);
        res.json({ id: modId, filename: req.file.filename, filesize: req.file.size, sha1, type, optional: !!optional, version_hash: versionHash });
    } catch (err) {
        console.error('[ERROR] al procesar el mod subido:', err);
        res.status(500).json({ error: 'No se pudo procesar el archivo subido.' });
    }
});

// --- Añadir mod/resource pack desde Modrinth (solo el dueño) ---
// El cliente solo manda IDs; nunca confiamos en nombre/tamaño/hash que venga
// del launcher. Volvemos a pedirle los datos reales a la API de Modrinth
// (pública, sin key) y guardamos eso.
router.post('/:id/mods/from-modrinth', requireOwner, enforceModCountLimit, async (req, res) => {
    const { project_id, version_id } = req.body || {};
    const type = MOD_TYPES.includes(req.body.type) ? req.body.type : 'mod';
    const optional = req.body.optional === true || req.body.optional === 'true' ? 1 : 0;
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

    // Modrinth incluye las dependencias de cada versión (p.ej. Sodium
    // necesita Fabric API). Antes esto no se comprobaba: el mod se añadía
    // igualmente y el fallo solo se veía al lanzar el juego, sin ninguna
    // pista de qué faltaba. Aquí solo avisamos (no bloqueamos ni añadimos
    // nada automáticamente) de las dependencias obligatorias que falten.
    let missingDependencies = [];
    const requiredDeps = (version.dependencies || []).filter((d) => d.dependency_type === 'required' && d.project_id);
    if (requiredDeps.length) {
        const existingProjectIds = new Set(
            db.prepare('SELECT external_project_id FROM mods WHERE modpack_id = ?').all(req.params.id).map((m) => m.external_project_id)
        );
        const missingDeps = requiredDeps.filter((d) => !existingProjectIds.has(d.project_id));
        missingDependencies = await Promise.all(missingDeps.map(async (d) => {
            try {
                const r = await fetch(`https://api.modrinth.com/v2/project/${encodeURIComponent(d.project_id)}`, {
                    headers: { 'User-Agent': 'EmberLauncher/1.0 (github.com/HCuadrado428/Launcher)' }
                });
                if (!r.ok) return d.project_id;
                const p = await r.json();
                return p.title || d.project_id;
            } catch (err) {
                return d.project_id;
            }
        }));
    }

    snapshotModpackVersion(req.params.id);
    const modId = crypto.randomUUID();
    db.prepare(`
        INSERT INTO mods (id, modpack_id, filename, filesize, sha1, type, optional, source, download_url, external_project_id, external_version_id, added_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, 'modrinth', ?, ?, ?, ?)
    `).run(modId, req.params.id, file.filename, file.size, file.hashes.sha1, type, optional, file.url, project_id, version_id, Date.now());

    const versionHash = recomputeVersionHash(req.params.id);
    res.json({
        id: modId, filename: file.filename, filesize: file.size, sha1: file.hashes.sha1, type,
        optional: !!optional, source: 'modrinth', version_hash: versionHash, missing_dependencies: missingDependencies
    });
});

// --- Comprobar si hay una versión más nueva en Modrinth (solo el dueño) ---
// Solo tiene sentido para mods añadidos desde Modrinth (source='modrinth');
// los subidos a mano no tienen forma de saber si hay una versión nueva.
router.get('/:id/mods/:modId/check-update', requireOwner, async (req, res) => {
    const mod = db.prepare('SELECT * FROM mods WHERE id = ? AND modpack_id = ?').get(req.params.modId, req.params.id);
    if (!mod) return res.status(404).json({ error: 'Mod no encontrado.' });
    if (mod.source !== 'modrinth' || !mod.external_project_id) {
        return res.status(400).json({ error: 'Este mod no se añadió desde Modrinth, no se puede comprobar su versión.' });
    }

    const pack = db.prepare('SELECT mc_version, loader FROM modpacks WHERE id = ?').get(req.params.id);

    try {
        const versionsRes = await fetch(
            `https://api.modrinth.com/v2/project/${encodeURIComponent(mod.external_project_id)}/version?game_versions=["${encodeURIComponent(pack.mc_version)}"]&loaders=["${encodeURIComponent(pack.loader)}"]`,
            { headers: { 'User-Agent': 'EmberLauncher/1.0 (github.com/HCuadrado428/Launcher)' } }
        );
        if (!versionsRes.ok) return res.status(502).json({ error: `Modrinth respondió con estado ${versionsRes.status}.` });
        const versions = await versionsRes.json();
        const latest = versions[0]; // Modrinth los devuelve ordenados de más reciente a más antiguo
        if (!latest) {
            return res.json({ has_update: false, reason: 'No hay ninguna versión de este mod compatible con la versión de Minecraft/loader del modpack.' });
        }
        res.json({
            has_update: latest.id !== mod.external_version_id,
            current_version_id: mod.external_version_id,
            latest_version_id: latest.id,
            latest_version_number: latest.version_number
        });
    } catch (err) {
        console.error('[ERROR] al comprobar actualización en Modrinth:', err);
        res.status(502).json({ error: 'No se pudo contactar con Modrinth.' });
    }
});

// --- Quitar mod (solo el dueño) ---
router.delete('/:id/mods/:modId', requireOwner, (req, res) => {
    const mod = db.prepare('SELECT * FROM mods WHERE id = ? AND modpack_id = ?').get(req.params.modId, req.params.id);
    if (!mod) return res.status(404).json({ error: 'Mod no encontrado.' });

    snapshotModpackVersion(req.params.id);
    const filePath = path.join(modpackDir(req.params.id), mod.filename);
    fs.unlink(filePath, () => {}); // si ya no está en disco, no pasa nada

    db.prepare('DELETE FROM mods WHERE id = ?').run(mod.id);
    const versionHash = recomputeVersionHash(req.params.id);
    res.json({ ok: true, version_hash: versionHash });
});

// --- Historial de versiones (solo el dueño) ---
router.get('/:id/versions', requireOwner, (req, res) => {
    const versions = db.prepare(`
        SELECT id, version_hash, created_at, mods_json FROM modpack_versions
        WHERE modpack_id = ? ORDER BY created_at DESC
    `).all(req.params.id);
    res.json(versions.map((v) => ({
        id: v.id,
        version_hash: v.version_hash,
        created_at: v.created_at,
        mod_count: JSON.parse(v.mods_json).length
    })));
});

// --- Restaurar una versión anterior (solo el dueño) ---
// Reemplaza la lista de mods actual por la guardada en el snapshot. Los
// mods de Modrinth siempre se pueden restaurar (se resuelven por su
// download_url externa), pero un mod subido a mano cuyo archivo ya se borró
// físicamente de STORAGE_DIR (porque se quitó del modpack después de este
// snapshot) no se puede traer de vuelta: no hay ninguna copia guardada del
// binario, solo sus metadatos. Antes se reinsertaba igualmente la fila y el
// launcher de cada jugador fallaba al intentar descargarlo, sin ningún
// aviso de qué había pasado. Ahora esos mods se saltan y se informa cuáles.
router.post('/:id/versions/:versionId/restore', requireOwner, (req, res) => {
    const snapshot = db.prepare('SELECT * FROM modpack_versions WHERE id = ? AND modpack_id = ?').get(req.params.versionId, req.params.id);
    if (!snapshot) return res.status(404).json({ error: 'Esa versión del historial no existe.' });

    snapshotModpackVersion(req.params.id);
    const mods = JSON.parse(snapshot.mods_json);
    const skipped = [];
    const restorable = mods.filter((m) => {
        if (m.source === 'modrinth') return true;
        const exists = fs.existsSync(path.join(modpackDir(req.params.id), m.filename));
        if (!exists) skipped.push(m.filename);
        return exists;
    });

    // Los mods actuales (no los del snapshot) que no vayan a seguir
    // existiendo después de restaurar se borran también de disco. Si no,
    // el archivo se queda huérfano en STORAGE_DIR para siempre: ni cuenta
    // para la cuota (se calcula sobre la tabla "mods", que ya no lo
    // referencia) ni hay ningún otro sitio que lo limpie.
    const restorableFilenames = new Set(restorable.filter((m) => m.source !== 'modrinth').map((m) => m.filename));
    const currentUploads = db.prepare("SELECT filename FROM mods WHERE modpack_id = ? AND source != 'modrinth'").all(req.params.id);
    for (const { filename } of currentUploads) {
        if (!restorableFilenames.has(filename)) {
            fs.unlink(path.join(modpackDir(req.params.id), filename), () => {});
        }
    }

    db.prepare('DELETE FROM mods WHERE modpack_id = ?').run(req.params.id);
    for (const m of restorable) {
        db.prepare(`
            INSERT INTO mods (id, modpack_id, filename, filesize, sha1, type, optional, source, download_url, external_project_id, external_version_id, mod_identifier, added_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).run(
            m.id, req.params.id, m.filename, m.filesize, m.sha1, m.type, m.optional ? 1 : 0,
            m.source || 'upload', m.download_url || '', m.external_project_id || '', m.external_version_id || '',
            m.mod_identifier || '', Date.now()
        );
    }

    const versionHash = recomputeVersionHash(req.params.id);
    res.json({ ok: true, version_hash: versionHash, restored_mod_count: restorable.length, skipped_files: skipped });
});

// --- Descargar un mod (cualquiera con acceso al modpack) ---
router.get('/:id/mods/:modId/download', requireAccess, (req, res) => {
    const mod = db.prepare('SELECT * FROM mods WHERE id = ? AND modpack_id = ?').get(req.params.modId, req.params.id);
    if (!mod) return res.status(404).json({ error: 'Mod no encontrado.' });
    const filePath = path.join(modpackDir(req.params.id), mod.filename);
    res.download(filePath, mod.filename);
});

// --- Cambiar la portada de un modpack (solo el dueño) ---
// Se manda como data URI base64 dentro del JSON (nada de subida de archivo
// aparte): más simple de servir después, ya que "SELECT *" ya la incluye en
// /mine y /manifest sin tener que montar una ruta estática nueva.
router.put('/:id/cover', requireOwner, (req, res) => {
    const { cover_image } = req.body || {};
    if (typeof cover_image !== 'string') {
        return res.status(400).json({ error: 'Falta "cover_image".' });
    }
    if (cover_image && !cover_image.startsWith('data:image/')) {
        return res.status(400).json({ error: 'La portada debe ser una imagen.' });
    }
    if (cover_image.length > 350000) {
        return res.status(413).json({ error: 'La imagen es demasiado grande. Prueba con una más pequeña.' });
    }

    db.prepare('UPDATE modpacks SET cover_image = ?, updated_at = ? WHERE id = ?')
        .run(cover_image, Date.now(), req.params.id);
    res.json({ ok: true });
});

// --- Crear link de invitación (solo el dueño, y solo cuentas premium) ---
// Compartir modpacks es lo único que se reserva a cuentas de Microsoft
// verificadas; crear modpacks propios y unirse a los de otros (redeem, en
// inviteRoutes.js) sigue abierto a cualquier cuenta, offline incluida.
const MAX_INVITE_USES = 10000;
const MAX_INVITE_EXPIRES_HOURS = 24 * 365; // 1 año
router.post('/:id/invite', requireOwner, requirePremium, (req, res) => {
    const { max_uses, expires_in_hours } = req.body || {};

    if (max_uses !== undefined && max_uses !== null) {
        if (!Number.isInteger(max_uses) || max_uses < 1 || max_uses > MAX_INVITE_USES) {
            return res.status(400).json({ error: `"max_uses" debe ser un número entero entre 1 y ${MAX_INVITE_USES}.` });
        }
    }
    if (expires_in_hours !== undefined && expires_in_hours !== null) {
        if (typeof expires_in_hours !== 'number' || !Number.isFinite(expires_in_hours) || expires_in_hours <= 0 || expires_in_hours > MAX_INVITE_EXPIRES_HOURS) {
            return res.status(400).json({ error: `"expires_in_hours" debe ser un número positivo de hasta ${MAX_INVITE_EXPIRES_HOURS} horas (1 año).` });
        }
    }

    const token = crypto.randomBytes(16).toString('hex');
    const now = Date.now();
    const expiresAt = expires_in_hours ? now + expires_in_hours * 3600 * 1000 : null;

    db.prepare(`
        INSERT INTO invites (token, modpack_id, created_by, max_uses, uses, expires_at, created_at)
        VALUES (?, ?, ?, ?, 0, ?, ?)
    `).run(token, req.params.id, req.user.uuid, max_uses || null, expiresAt, now);

    res.json({ token, url: `milauncher://invite/${token}` });
});

// --- Listar invitaciones vigentes (solo el dueño) ---
router.get('/:id/invites', requireOwner, (req, res) => {
    const invites = db.prepare(`
        SELECT token, max_uses, uses, expires_at, created_at FROM invites
        WHERE modpack_id = ? ORDER BY created_at DESC
    `).all(req.params.id);
    res.json(invites);
});

// --- Revocar una invitación antes de que se use/caduque (solo el dueño) ---
router.delete('/:id/invites/:token', requireOwner, (req, res) => {
    const result = db.prepare('DELETE FROM invites WHERE token = ? AND modpack_id = ?').run(req.params.token, req.params.id);
    if (result.changes === 0) return res.status(404).json({ error: 'Esa invitación no existe.' });
    res.json({ ok: true });
});

// --- Ver quién tiene acceso a un modpack compartido (solo el dueño) ---
router.get('/:id/access', requireOwner, (req, res) => {
    const users = db.prepare(`
        SELECT a.user_uuid AS uuid, u.username, a.granted_at
        FROM access a
        LEFT JOIN users u ON u.uuid = a.user_uuid
        WHERE a.modpack_id = ? AND a.user_uuid != (SELECT owner_uuid FROM modpacks WHERE id = ?)
        ORDER BY a.granted_at DESC
    `).all(req.params.id, req.params.id);
    res.json(users);
});

// --- Revocar el acceso de un usuario concreto (solo el dueño) ---
router.delete('/:id/access/:uuid', requireOwner, (req, res) => {
    const pack = db.prepare('SELECT owner_uuid FROM modpacks WHERE id = ?').get(req.params.id);
    if (pack && pack.owner_uuid === req.params.uuid) {
        return res.status(400).json({ error: 'No puedes quitarte el acceso a ti mismo como creador.' });
    }
    const result = db.prepare('DELETE FROM access WHERE modpack_id = ? AND user_uuid = ?').run(req.params.id, req.params.uuid);
    if (result.changes === 0) return res.status(404).json({ error: 'Ese usuario no tenía acceso.' });
    res.json({ ok: true });
});

// --- Abandonar un modpack compartido (cualquiera con acceso, menos el dueño) ---
// Antes de esto, la única forma de que un jugador dejara de tener un
// modpack compartido en su lista era que el DUEÑO le revocara el acceso a
// mano; el propio jugador no tenía ninguna forma de quitárselo de encima.
router.post('/:id/leave', requireAccess, (req, res) => {
    const pack = db.prepare('SELECT owner_uuid FROM modpacks WHERE id = ?').get(req.params.id);
    if (pack.owner_uuid === req.user.uuid) {
        return res.status(400).json({ error: 'Eres el creador de este modpack: no puedes abandonarlo, pero puedes eliminarlo si ya no lo quieres.' });
    }
    db.prepare('DELETE FROM access WHERE modpack_id = ? AND user_uuid = ?').run(req.params.id, req.user.uuid);
    res.json({ ok: true });
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
