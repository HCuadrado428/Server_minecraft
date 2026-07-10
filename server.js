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

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`[OK] Servidor de modpacks escuchando en el puerto ${PORT}`);
});
