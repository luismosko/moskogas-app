// index.js — Robô Ultragaz Hub × MoskoGás
// Captura pedidos em tempo real via WebSocket e envia para o sistema
import 'dotenv/config';
import { loginHub, getWebsocketInfo, closeBrowser } from './browser.js';
import { startWebSocket, stopWebSocket, setNewOrderHandler } from './websocket.js';
import { getUltragazConfig, enviarPedido } from './moskogas.js';
import { isProcessed, markProcessed, addToRetryQueue, getPendingRetries, updateRetry, logEvent } from './db.js';

const SESSION_RENEWAL_MS = parseInt(process.env.SESSION_RENEWAL_MS) || 6 * 60 * 60 * 1000; // 6h
const RETRY_INTERVAL_MS  = 30 * 1000; // 30s

const log  = (msg)  => console.log(`[robot] ${new Date().toISOString()} ${msg}`);
const warn = (msg)  => console.warn(`[warn]  ${new Date().toISOString()} ${msg}`);
const err  = (msg)  => console.error(`[ERROR] ${new Date().toISOString()} ${msg}`);

let currentPage      = null;
let sessionTimer     = null;
let isRestarting     = false;

// ─── Handler de novo pedido ──────────────────────────────────────────────────
setNewOrderHandler(async (orderData) => {
  const { ultragaz_order_id, event_type } = orderData;

  logEvent(event_type, ultragaz_order_id, orderData);

  // Camada 1 de idempotência: SQLite local
  if (isProcessed(ultragaz_order_id)) {
    log(`Pedido #${ultragaz_order_id} já processado — ignorando`);
    return;
  }

  log(`🛒 NOVO PEDIDO #${ultragaz_order_id} (${event_type}) — ${orderData.customer_name || 'N/D'}`);

  try {
    const result = await enviarPedido(orderData);

    if (result.duplicado) {
      log(`Pedido #${ultragaz_order_id} já existia no MoskoGás (id: ${result.moskogas_order_id})`);
      markProcessed(ultragaz_order_id, result.moskogas_order_id, 'duplicado');
      return;
    }

    log(`✅ Pedido #${ultragaz_order_id} criado no MoskoGás! ID: ${result.moskogas_order_id}`);
    markProcessed(ultragaz_order_id, result.moskogas_order_id, 'ok');

  } catch (e) {
    warn(`Falha ao enviar pedido #${ultragaz_order_id}: ${e.message}`);
    addToRetryQueue(ultragaz_order_id, orderData);
    markProcessed(ultragaz_order_id, null, 'retry');
  }
});

// ─── Fila de retry ───────────────────────────────────────────────────────────
async function processRetryQueue() {
  const pending = getPendingRetries();
  if (pending.length === 0) return;

  log(`🔄 Retry queue: ${pending.length} pedido(s) pendente(s)`);
  for (const item of pending) {
    try {
      const payload = JSON.parse(item.payload_json);
      const result  = await enviarPedido(payload);
      log(`✅ Retry OK — Pedido #${item.ultragaz_order_id} → MoskoGás ID ${result.moskogas_order_id}`);
      updateRetry(item.id, true);
    } catch (e) {
      warn(`Retry falhou para #${item.ultragaz_order_id} (tentativa ${item.attempts + 1}): ${e.message}`);
      updateRetry(item.id, false, e.message);
    }
  }
}

// ─── Inicialização / Renovação de sessão ─────────────────────────────────────
async function startSession() {
  if (isRestarting) return;
  isRestarting = true;

  try {
    log('Buscando credenciais do Hub no painel MoskoGás...');
    const cfg = await getUltragazConfig();

    if (!cfg.ativo) {
      log('Robô desativado no painel. Aguardando 5 minutos...');
      isRestarting = false;
      setTimeout(startSession, 5 * 60 * 1000);
      return;
    }

    log(`Credenciais obtidas para: ${cfg.login}`);

    // ── Aguarda solicitação de login do operador via painel ──
    const apiUrl = process.env.MOSKOGAS_API_URL || 'https://moskogas.com.br';
    const apiKey = process.env.MOSKOGAS_API_KEY;
    log('🟡 Aguardando operador iniciar login pelo painel MoskoGás...');

    let loginRequested = false;
    while (!loginRequested) {
      try {
        const r = await fetch(`${apiUrl}/api/ultragaz/login-request`, {
          headers: { 'X-API-Key': apiKey }
        });
        const data = await r.json();
        if (data.pending) {
          loginRequested = true;
          // Consome a solicitação
          await fetch(`${apiUrl}/api/ultragaz/login-request`, {
            method: 'DELETE', headers: { 'X-API-Key': apiKey }
          }).catch(() => {});
          log('✅ Login solicitado pelo operador! Iniciando...');
        }
      } catch {}
      if (!loginRequested) await new Promise(r => setTimeout(r, 5000));
    }

    stopWebSocket();

    log('Fazendo login no Hub Ultragaz...');
    const { page } = await loginHub(cfg.login, cfg.senha, cfg.hub_url);
    currentPage = page;

    log('Obtendo URL assinada do WebSocket...');
    const wssUrl = await getWebsocketInfo(page);

    log('Iniciando WebSocket listener...');
    startWebSocket(wssUrl, page, apiUrl, apiKey);

    // Agenda renovação de sessão
    if (sessionTimer) clearTimeout(sessionTimer);
    sessionTimer = setTimeout(() => {
      log('⏰ Renovando sessão (intervalo programado)...');
      startSession();
    }, SESSION_RENEWAL_MS);

    log(`✅ Robô rodando! Sessão renovará em ${SESSION_RENEWAL_MS / 3600000}h`);

  } catch (e) {
    err(`Erro na inicialização: ${e.message}`);
    warn('Tentando novamente em 60 segundos...');
    isRestarting = false;
    setTimeout(startSession, 60000);
    return;
  }

  isRestarting = false;
}

// ─── Graceful shutdown ────────────────────────────────────────────────────────
async function shutdown(signal) {
  log(`${signal} recebido — encerrando...`);
  stopWebSocket();
  await closeBrowser();
  if (sessionTimer) clearTimeout(sessionTimer);
  process.exit(0);
}

process.on('SIGINT',  () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));

process.on('unhandledRejection', (reason) => {
  err(`UnhandledRejection: ${reason}`);
});

// ─── Start ────────────────────────────────────────────────────────────────────
log('🤖 Robô Ultragaz × MoskoGás iniciando...');
log(`   Credenciais: via painel config.html (GET /api/ultragaz/config)`);
log(`   Renovação de sessão: a cada ${SESSION_RENEWAL_MS / 3600000}h`);

startSession();
setInterval(processRetryQueue, RETRY_INTERVAL_MS);
