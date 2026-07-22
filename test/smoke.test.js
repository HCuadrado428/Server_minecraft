// Test de humo end-to-end: arranca el servidor real como subproceso contra
// una base de datos temporal y ejercita los flujos que ya se rompieron una
// vez a lo largo de las últimas rondas de arreglos (cuenta offline, gateo
// de premium al compartir, revocación de sesión, validación de invitación,
// cuota de almacenamiento). No sustituye tests unitarios más finos, pero es
// la primera red de seguridad que existe en este proyecto: antes ningún
// cambio tenía forma automática de detectar que había roto algo de esto.
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const { DatabaseSync } = require('node:sqlite');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

const TEST_PORT = 4173;
const BASE_URL = `http://localhost:${TEST_PORT}`;
const dbPath = path.join(os.tmpdir(), `ember-launcher-test-${Date.now()}.sqlite`);

let serverProcess;

async function waitForServer(timeoutMs = 15000) {
    const start = Date.now();
    while (Date.now() - start < timeoutMs) {
        try {
            const res = await fetch(`${BASE_URL}/health`);
            if (res.ok) return;
        } catch (err) {
            // todavía no está escuchando
        }
        await new Promise((resolve) => setTimeout(resolve, 200));
    }
    throw new Error('El servidor no arrancó a tiempo para los tests.');
}

before(async () => {
    serverProcess = spawn(process.execPath, [path.join(__dirname, '..', 'server.js')], {
        env: {
            ...process.env,
            PORT: String(TEST_PORT),
            DB_PATH: dbPath,
            JWT_SECRET: 'test-secret-solo-para-los-tests'
        },
        stdio: 'pipe'
    });
    await waitForServer();
});

after(async () => {
    if (serverProcess) serverProcess.kill();
    for (const suffix of ['', '-journal', '-wal', '-shm']) {
        try { fs.unlinkSync(dbPath + suffix); } catch (err) { /* no existía */ }
    }
});

async function registerOffline(username) {
    const res = await fetch(`${BASE_URL}/api/auth/verify-offline`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username })
    });
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.premium, false);
    assert.ok(data.token);
    return data;
}

// No hay forma de conseguir una cuenta premium de verdad en un test (exige
// un access_token real de Microsoft), así que para probar las rutas que
// requieren requirePremium se registra una cuenta offline normal y se le
// sube el flag directamente en la base de datos de prueba, igual que haría
// una verificación real contra Mojang.
function markPremium(uuid) {
    const db = new DatabaseSync(dbPath);
    db.prepare('UPDATE users SET premium = 1 WHERE uuid = ?').run(uuid);
    db.close();
}

test('/health responde ok', async () => {
    const res = await fetch(`${BASE_URL}/health`);
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.ok, true);
});

test('una cuenta offline se registra como no premium', async () => {
    await registerOffline('TestOffline1');
});

test('una cuenta offline puede crear un modpack', async () => {
    const { token } = await registerOffline('TestOffline2');
    const res = await fetch(`${BASE_URL}/api/modpacks`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ name: 'Pack de test', mc_version: '1.21.1' })
    });
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.ok(data.id);
});

test('crear un modpack con una versión inválida devuelve 400', async () => {
    const { token } = await registerOffline('TestOffline3');
    const res = await fetch(`${BASE_URL}/api/modpacks`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ name: 'Pack roto', mc_version: '<script>' })
    });
    assert.equal(res.status, 400);
});

test('una cuenta offline (no premium) no puede generar invitaciones', async () => {
    const { token } = await registerOffline('TestOffline4');
    const createRes = await fetch(`${BASE_URL}/api/modpacks`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ name: 'Pack sin compartir', mc_version: '1.21.1' })
    });
    const { id } = await createRes.json();

    const inviteRes = await fetch(`${BASE_URL}/api/modpacks/${id}/invite`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({})
    });
    assert.equal(inviteRes.status, 403);
});

test('una cuenta premium puede generar, listar y revocar invitaciones', async () => {
    const { token, uuid } = await registerOffline('TestPremium1');
    markPremium(uuid);

    const createRes = await fetch(`${BASE_URL}/api/modpacks`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ name: 'Pack compartible', mc_version: '1.21.1' })
    });
    const { id } = await createRes.json();

    const inviteRes = await fetch(`${BASE_URL}/api/modpacks/${id}/invite`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ max_uses: 5, expires_in_hours: 24 })
    });
    assert.equal(inviteRes.status, 200);
    const invite = await inviteRes.json();
    assert.ok(invite.token);

    const listRes = await fetch(`${BASE_URL}/api/modpacks/${id}/invites`, {
        headers: { Authorization: `Bearer ${token}` }
    });
    const invites = await listRes.json();
    assert.equal(invites.length, 1);
    assert.equal(invites[0].max_uses, 5);

    const revokeRes = await fetch(`${BASE_URL}/api/modpacks/${id}/invites/${invite.token}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${token}` }
    });
    assert.equal(revokeRes.status, 200);
});

test('max_uses fuera de rango devuelve 400 aunque la cuenta sea premium', async () => {
    const { token, uuid } = await registerOffline('TestPremium2');
    markPremium(uuid);

    const createRes = await fetch(`${BASE_URL}/api/modpacks`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ name: 'Pack límites', mc_version: '1.21.1' })
    });
    const { id } = await createRes.json();

    const inviteRes = await fetch(`${BASE_URL}/api/modpacks/${id}/invite`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ max_uses: 999999999 })
    });
    assert.equal(inviteRes.status, 400);
});

test('otro usuario puede canjear una invitación y luego abandonar el modpack', async () => {
    const owner = await registerOffline('TestPremium3');
    markPremium(owner.uuid);
    const member = await registerOffline('TestMember1');

    const createRes = await fetch(`${BASE_URL}/api/modpacks`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${owner.token}` },
        body: JSON.stringify({ name: 'Pack compartido', mc_version: '1.21.1' })
    });
    const { id } = await createRes.json();

    const inviteRes = await fetch(`${BASE_URL}/api/modpacks/${id}/invite`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${owner.token}` },
        body: JSON.stringify({})
    });
    const invite = await inviteRes.json();

    const redeemRes = await fetch(`${BASE_URL}/api/invites/${invite.token}/redeem`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${member.token}` }
    });
    assert.equal(redeemRes.status, 200);

    const mineRes = await fetch(`${BASE_URL}/api/modpacks/mine`, {
        headers: { Authorization: `Bearer ${member.token}` }
    });
    const mine = await mineRes.json();
    assert.ok(mine.shared.some((p) => p.id === id));

    const leaveRes = await fetch(`${BASE_URL}/api/modpacks/${id}/leave`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${member.token}` }
    });
    assert.equal(leaveRes.status, 200);

    const mineAfterRes = await fetch(`${BASE_URL}/api/modpacks/mine`, {
        headers: { Authorization: `Bearer ${member.token}` }
    });
    const mineAfter = await mineAfterRes.json();
    assert.ok(!mineAfter.shared.some((p) => p.id === id));
});

test('el uso de almacenamiento se puede consultar y empieza en 0', async () => {
    const { token } = await registerOffline('TestOffline6');
    const res = await fetch(`${BASE_URL}/api/modpacks/storage`, {
        headers: { Authorization: `Bearer ${token}` }
    });
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.used_bytes, 0);
    assert.ok(data.limit_bytes > 0);
});

test('cerrar sesión invalida el token de inmediato', async () => {
    const { token } = await registerOffline('TestOffline7');

    const beforeLogout = await fetch(`${BASE_URL}/api/modpacks/mine`, {
        headers: { Authorization: `Bearer ${token}` }
    });
    assert.equal(beforeLogout.status, 200);

    const logoutRes = await fetch(`${BASE_URL}/api/auth/logout`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` }
    });
    assert.equal(logoutRes.status, 200);

    const afterLogout = await fetch(`${BASE_URL}/api/modpacks/mine`, {
        headers: { Authorization: `Bearer ${token}` }
    });
    assert.equal(afterLogout.status, 401);
});

test('sin token de autenticación, las rutas de modpacks responden 401', async () => {
    const res = await fetch(`${BASE_URL}/api/modpacks/mine`);
    assert.equal(res.status, 401);
});

test('canjear la misma invitación dos veces con la misma cuenta no gasta dos usos', async () => {
    const owner = await registerOffline('TestPremium4');
    markPremium(owner.uuid);
    const member = await registerOffline('TestMember2');

    const createRes = await fetch(`${BASE_URL}/api/modpacks`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${owner.token}` },
        body: JSON.stringify({ name: 'Pack doble canje', mc_version: '1.21.1' })
    });
    const { id } = await createRes.json();

    const inviteRes = await fetch(`${BASE_URL}/api/modpacks/${id}/invite`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${owner.token}` },
        body: JSON.stringify({ max_uses: 1 })
    });
    const invite = await inviteRes.json();

    const redeem1 = await fetch(`${BASE_URL}/api/invites/${invite.token}/redeem`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${member.token}` }
    });
    assert.equal(redeem1.status, 200);

    // Redimir otra vez con la misma cuenta (un doble click en "unirse", o
    // reabrir el mismo link) ya tiene acceso concedido: no debería gastar el
    // único uso disponible del invite una segunda vez.
    const redeem2 = await fetch(`${BASE_URL}/api/invites/${invite.token}/redeem`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${member.token}` }
    });
    assert.equal(redeem2.status, 200);

    const listRes = await fetch(`${BASE_URL}/api/modpacks/${id}/invites`, {
        headers: { Authorization: `Bearer ${owner.token}` }
    });
    const invites = await listRes.json();
    assert.equal(invites[0].uses, 1);
});

test('un filename manipulado en la DB no permite escapar del directorio del modpack al descargar', async () => {
    const { token } = await registerOffline('TestTraversal1');
    const createRes = await fetch(`${BASE_URL}/api/modpacks`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ name: 'Pack traversal', mc_version: '1.21.1' })
    });
    const { id } = await createRes.json();

    // Simula una fila con un filename malicioso, como llegaría de una fuente
    // externa no saneada (ver sanitizeFilename/resolveModpackFilePath en
    // modpackRoutes.js). No pasa por la API real de Modrinth porque
    // provocarlo de verdad requeriría controlar su respuesta.
    const db = new DatabaseSync(dbPath);
    const modId = crypto.randomUUID();
    db.prepare(`
        INSERT INTO mods (id, modpack_id, filename, filesize, sha1, added_at)
        VALUES (?, ?, ?, ?, ?, ?)
    `).run(modId, id, '../../evil.txt', 10, 'deadbeef', Date.now());
    db.close();

    const downloadRes = await fetch(`${BASE_URL}/api/modpacks/${id}/mods/${modId}/download`, {
        headers: { Authorization: `Bearer ${token}` }
    });
    assert.equal(downloadRes.status, 400);
});
