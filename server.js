require('dotenv').config();
const express = require('express');
const rateLimit = require('express-rate-limit');
const authRoutes = require('./routes/authRoutes');
const modpackRoutes = require('./routes/modpackRoutes');
const inviteRoutes = require('./routes/inviteRoutes');

const app = express();
// Railway pone la app detrás de un proxy inverso: sin esto, todas las
// peticiones llegarían con la IP del proxy y el rate limiting de abajo
// agruparía a todo el mundo en el mismo cupo en vez de limitar por IP real.
app.set('trust proxy', 1);
// El límite por defecto (100kb) se queda corto para la portada de un
// modpack, que viaja como data URI en base64 dentro del JSON.
app.use(express.json({ limit: '1mb' }));

app.get('/health', (req, res) => res.json({ ok: true }));

// Antes no había ningún límite: cualquiera podía inundar /api/auth/verify
// (que a su vez reenvía cada llamada a la API de Mojang) o el resto de la
// API sin ninguna restricción. authLimiter es más estricto porque login es
// donde más interesa frenar fuerza bruta; apiLimiter es un límite general
// más laxo para el resto, pensado para tráfico normal de varios launchers.
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 30,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Demasiados intentos de inicio de sesión. Espera unos minutos.' }
});
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 600,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Demasiadas peticiones. Espera un momento.' }
});
app.use('/api', apiLimiter);
app.use('/api/auth', authLimiter);

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
