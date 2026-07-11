require('dotenv').config();
const express = require('express');
const authRoutes = require('./routes/authRoutes');
const modpackRoutes = require('./routes/modpackRoutes');
const inviteRoutes = require('./routes/inviteRoutes');

const app = express();
app.use(express.json());

app.get('/health', (req, res) => res.json({ ok: true }));

app.use('/api/auth', authRoutes);
app.use('/api/modpacks', modpackRoutes);
app.use('/api/invites', inviteRoutes);

// Handler de errores genérico: evita que errores de middlewares como multer
// (p.ej. extensión de archivo equivocada) devuelvan la página HTML por
// defecto de Express en vez de un JSON que el launcher pueda mostrar.
app.use((err, req, res, next) => {
    console.error('[ERROR]', err.message || err);
    res.status(400).json({ error: err.message || 'Petición inválida.' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`[OK] Servidor de modpacks escuchando en el puerto ${PORT}`);
});
