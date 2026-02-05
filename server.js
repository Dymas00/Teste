/**
 * CAPTIVE PORTAL CARNAVAL DE RECIFE
 * Servidor Principal
 *
 * Sistema de gestão e monetização de Wi-Fi
 * com tema do Carnaval de Recife
 */

require('dotenv').config();

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const compression = require('compression');
const path = require('path');
const session = require('express-session');
const { createClient } = require('redis');
const RedisStore = require('connect-redis').default;

// Logger
const pino = require('pino');
const logger = pino({
    level: process.env.LOG_LEVEL || 'info',
    transport: process.env.NODE_ENV !== 'production' ? {
        target: 'pino-pretty',
        options: { colorize: true }
    } : undefined
});

// Importar serviços
const { initDatabase, getPool } = require('./database/db-manager');
const { initRedis, getRedisClient } = require('./services/cache');
const { setupPrometheus } = require('./services/monitoring');
const securityMiddleware = require('./middleware/security');
const { startSessionCleanup, recoverActiveSessions } = require('./services/session-manager');

// Importar rotas
const authRoutes = require('./routes/auth');
const plansRoutes = require('./routes/plans');
const paymentsRoutes = require('./routes/payments');
const sessionsRoutes = require('./routes/sessions');
const adminRoutes = require('./routes/admin');
const webhooksRoutes = require('./routes/webhooks');
const metricsRoutes = require('./routes/metrics');

const app = express();
const PORT = process.env.PORT || 3000;

// Trust proxy (necessário para rate limiting atrás de nginx)
app.set('trust proxy', 1);

// Compression
app.use(compression());

// Helmet - Security headers
// CSP desabilitado para captive portal (rede interna controlada)
app.use(helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false,
    crossOriginResourcePolicy: false
}));

// CORS
app.use(cors({
    origin: process.env.NODE_ENV === 'production'
        ? [process.env.PUBLIC_URL, `http://${process.env.LOCAL_IP}:${PORT}`]
        : '*',
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

// Body parsers
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Security middleware
app.use(securityMiddleware.sanitizeInput);
app.use(securityMiddleware.preventSqlInjection);

// Rate limiting geral
app.use(securityMiddleware.generalRateLimit);

// Arquivos estáticos
app.use(express.static(path.join(__dirname, 'public'), {
    maxAge: process.env.NODE_ENV === 'production' ? '1d' : 0,
    etag: true
}));

// Inicialização assíncrona
async function initializeApp() {
    try {
        logger.info('🎭 Iniciando Captive Portal Carnaval de Recife...');

        // Inicializar banco de dados
        logger.info('📦 Conectando ao banco de dados...');
        await initDatabase();
        logger.info('✅ Banco de dados conectado');

        // Inicializar Redis
        logger.info('🔴 Conectando ao Redis...');
        const redisClient = await initRedis();

        // Configurar sessões com Redis
        // Para captive portal, secure deve ser false para funcionar em HTTP
        // Captive portals geralmente não suportam HTTPS na primeira conexão
        app.use(session({
            store: new RedisStore({ client: redisClient }),
            secret: process.env.SESSION_SECRET,
            resave: false,
            saveUninitialized: false,
            cookie: {
                secure: false, // Captive portal precisa funcionar em HTTP
                httpOnly: true,
                maxAge: 24 * 60 * 60 * 1000, // 24 horas
                sameSite: 'lax'
            },
            name: 'carnaval.sid'
        }));
        logger.info('✅ Redis conectado');

        // Configurar Prometheus
        if (process.env.PROMETHEUS_ENABLED === 'true') {
            setupPrometheus(app);
            logger.info('📊 Prometheus configurado');
        }

        // Rotas da API
        app.use('/api/auth', authRoutes);
        app.use('/api/plans', plansRoutes);
        app.use('/api/payments', paymentsRoutes);
        app.use('/api/sessions', sessionsRoutes);
        app.use('/api/admin', adminRoutes);
        app.use('/api/webhooks', webhooksRoutes);
        app.use('/api/metrics', metricsRoutes);

        // Health check
        app.get('/health', async (req, res) => {
            try {
                const pool = getPool();
                await pool.query('SELECT 1');

                const redis = getRedisClient();
                await redis.ping();

                res.json({
                    status: 'healthy',
                    timestamp: new Date().toISOString(),
                    uptime: process.uptime(),
                    version: '1.0.0',
                    theme: 'Carnaval de Recife 🎭'
                });
            } catch (error) {
                res.status(503).json({
                    status: 'unhealthy',
                    error: error.message
                });
            }
        });

        // Rota principal - Captive Portal
        app.get('/', (req, res) => {
            res.sendFile(path.join(__dirname, 'public', 'index.html'));
        });

        // Admin
        app.get('/admin', (req, res) => {
            res.sendFile(path.join(__dirname, 'public', 'admin.html'));
        });

        app.get('/admin-login', (req, res) => {
            res.sendFile(path.join(__dirname, 'public', 'admin-login.html'));
        });

        // Hotspot redirect (MikroTik)
        app.get('/hotspot', (req, res) => {
            res.redirect('/');
        });

        // Captive Portal Detection URLs
        // Android
        app.get('/generate_204', (req, res) => {
            // Se o dispositivo já foi autenticado, retorna 204
            // Caso contrário, redireciona para o portal
            res.redirect('/');
        });
        app.get('/gen_204', (req, res) => {
            res.redirect('/');
        });

        // iOS / macOS
        app.get('/hotspot-detect.html', (req, res) => {
            res.redirect('/');
        });
        app.get('/library/test/success.html', (req, res) => {
            res.redirect('/');
        });

        // Windows
        app.get('/ncsi.txt', (req, res) => {
            res.redirect('/');
        });
        app.get('/connecttest.txt', (req, res) => {
            res.redirect('/');
        });

        // Firefox
        app.get('/success.txt', (req, res) => {
            res.redirect('/');
        });

        // Rota de sucesso após login
        app.get('/success', (req, res) => {
            res.sendFile(path.join(__dirname, 'public', 'success.html'));
        });

        // 404 handler
        app.use((req, res) => {
            res.status(404).json({
                error: 'Endpoint não encontrado',
                path: req.path
            });
        });

        // Error handler global
        app.use((err, req, res, next) => {
            logger.error({
                error: err.message,
                stack: err.stack,
                path: req.path,
                method: req.method
            }, 'Erro não tratado');

            res.status(err.status || 500).json({
                error: process.env.NODE_ENV === 'production'
                    ? 'Erro interno do servidor'
                    : err.message
            });
        });

        // Recuperar sessões ativas (após restart/reboot)
        try {
            const recoveryResult = await recoverActiveSessions();
            logger.info({
                recovered: recoveryResult.recovered,
                expired: recoveryResult.expired,
                errors: recoveryResult.errors
            }, '🔄 Sessões recuperadas após reinicialização');
        } catch (recoveryError) {
            logger.error({ error: recoveryError.message }, 'Erro ao recuperar sessões (continuando inicialização)');
        }

        // Iniciar limpeza de sessões expiradas
        startSessionCleanup();
        logger.info('🧹 Limpeza de sessões iniciada');

        // Iniciar servidor
        const server = app.listen(PORT, '0.0.0.0', () => {
            logger.info(`
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   🎭 CAPTIVE PORTAL CARNAVAL DE RECIFE 🎭                    ║
║                                                               ║
║   Servidor rodando na porta ${PORT}                            ║
║   Ambiente: ${process.env.NODE_ENV}                                ║
║                                                               ║
║   URLs:                                                       ║
║   - Portal: http://localhost:${PORT}                           ║
║   - Admin:  http://localhost:${PORT}/admin                     ║
║   - Health: http://localhost:${PORT}/health                    ║
║                                                               ║
║   🎉 Olinda, Recife, Frevo e Maracatu! 🎉                    ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
            `);
        });

        // Graceful shutdown
        const gracefulShutdown = async (signal) => {
            logger.info(`${signal} recebido. Iniciando shutdown graceful...`);

            server.close(async () => {
                logger.info('Servidor HTTP fechado');

                try {
                    const pool = getPool();
                    await pool.end();
                    logger.info('Pool PostgreSQL fechado');

                    const redis = getRedisClient();
                    await redis.quit();
                    logger.info('Redis desconectado');

                    process.exit(0);
                } catch (error) {
                    logger.error('Erro no shutdown:', error);
                    process.exit(1);
                }
            });

            // Forçar saída após 30 segundos
            setTimeout(() => {
                logger.error('Shutdown forçado após timeout');
                process.exit(1);
            }, 30000);
        };

        process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
        process.on('SIGINT', () => gracefulShutdown('SIGINT'));

    } catch (error) {
        logger.fatal({ error: error.message, stack: error.stack }, 'Falha na inicialização');
        process.exit(1);
    }
}

// Iniciar aplicação
initializeApp();

module.exports = app;
