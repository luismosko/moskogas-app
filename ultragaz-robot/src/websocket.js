// websocket.js — Conexão WebSocket com Hub Ultragaz + listener de eventos
import { WebSocket } from 'ws';
import { getOrderDetails, getPendingOrders } from './browser.js';

const log  = (msg) => console.log(`[ws] ${new Date().toISOString()} ${msg}`);
const warn = (msg) => console.warn(`[ws] ${new Date().toISOString()} ${msg}`);

// Tipos de evento que geram pedido novo
const NEW_ORDER_EVENTS = ['newOrder', 'newOrderUG'];

let wsInstance = null;
let pingInterval = null;
let reconnectTimer = null;
let reconnectDelay = 5000;
let running = false;
let consecutive401 = 0;
let scanInterval = null;
const SCAN_INTERVAL_MS = 5 * 60 * 1000; // varredura automática a cada 5 minutos

// Callback chamado quando chega pedido novo — definido pelo index.js
let onNewOrder = null;
let onSessionExpired = null; // chamado quando WSS retorna 401 (sessão expirada)

export function setNewOrderHandler(fn) {
  onNewOrder = fn;
}

export function setSessionExpiredHandler(fn) {
  onSessionExpired = fn;
}

// Conecta ao WebSocket com URL assinada
export function connectWebSocket(wssUrl, page, apiUrl = '', apiKey = '') {
  if (wsInstance) {
    try { wsInstance.terminate(); } catch {}
    wsInstance = null;
  }

  log(`Conectando WSS...`);
  wsInstance = new WebSocket(wssUrl);

  wsInstance.on('open', async () => {
    log('✅ WebSocket conectado!');
    reconnectDelay = 5000; // reset backoff
    consecutive401 = 0; // reset contador de erros 401
    startPing(wssUrl, page);
    startPeriodicScan(apiUrl, apiKey, page);

    // Varredura inicial — processa pedidos em aberto que chegaram antes da conexão
    log('🔍 Varrendo pedidos em aberto no Hub...');
    try {
      const pending = await getPendingOrders(page);
      if (pending && Array.isArray(pending) && pending.length > 0) {
        log(`📋 ${pending.length} pedido(s) em aberto encontrado(s) — processando...`);
        for (const order of pending) {
          const orderId = order.id || order.ID_ORDER_LINK || order.order_id;
          if (!orderId) continue;
          log(`↪ Processando pedido em aberto #${orderId}`);
          try {
            let details = {};
            try { details = await getOrderDetails(page, orderId) || {}; } catch {}
            if (onNewOrder) {
              await onNewOrder({
                ultragaz_order_id: String(orderId),
                event_type: 'pendingOrder',
                raw_payload: order,
                ...parseDetails(details, order),
              });
            }
          } catch (e) {
            warn(`Erro ao processar pedido em aberto #${orderId}: ${e.message}`);
          }
        }
      } else {
        log('✅ Nenhum pedido em aberto encontrado na varredura inicial');
      }
    } catch (e) {
      warn(`Varredura inicial falhou: ${e.message}`);
    }
  });

  wsInstance.on('message', async (raw) => {
    let payload;
    try { payload = JSON.parse(raw.toString()); } catch { return; }

    const data = payload.data || payload;
    const eventType = data.eventType || data.event_type || data.type;
    const orderId   = data.ID_ORDER_LINK || data.order_id || data.id;

    log(`📨 Evento: ${eventType} | Pedido: ${orderId || 'N/A'}`);

    if (NEW_ORDER_EVENTS.includes(eventType) && orderId) {
      try {
        // Busca detalhes completos do pedido via APEX
        let details = {};
        try {
          details = await getOrderDetails(page, orderId) || {};
        } catch (e) {
          warn(`getOrderDetails falhou: ${e.message} — usando dados básicos`);
        }

        if (onNewOrder) {
          await onNewOrder({
            ultragaz_order_id: orderId,
            event_type: eventType,
            raw_payload: data,
            ...parseDetails(details, data),
          });
        }
      } catch (e) {
        warn(`Erro ao processar evento ${eventType} #${orderId}: ${e.message}`);
      }
    }
  });

  wsInstance.on('close', (code, reason) => {
    log(`🔌 WebSocket fechado (${code}). Reconectando em ${reconnectDelay / 1000}s...`);
    stopPing();
    stopPeriodicScan();
    scheduleReconnect(wssUrl, page, apiUrl, apiKey);
  });

  wsInstance.on('error', (err) => {
    warn(`Erro WebSocket: ${err.message}`);
    if (err.message && err.message.includes('401')) {
      consecutive401++;
      warn(`WSS 401 (${consecutive401}x) — URL expirada. ${consecutive401 >= 2 ? 'Disparando re-login...' : 'Aguardando...'}`);
      if (consecutive401 >= 2) {
        consecutive401 = 0;
        running = false;
        stopPing();
        stopPeriodicScan();
        if (reconnectTimer) { clearTimeout(reconnectTimer); reconnectTimer = null; }
        if (onSessionExpired) onSessionExpired();
        return;
      }
    } else {
      consecutive401 = 0;
    }
  });
}

// Mantém conexão viva com ping a cada 3min50s (antes dos 4min do servidor)
function startPing(wssUrl, page) {
  stopPing();
  pingInterval = setInterval(() => {
    if (wsInstance && wsInstance.readyState === WebSocket.OPEN) {
      wsInstance.ping();
      log('ping enviado');
    }
  }, 230000); // 3min50s
}

function stopPing() {
  if (pingInterval) { clearInterval(pingInterval); pingInterval = null; }
}

function scheduleReconnect(wssUrl, page, apiUrl, apiKey) {
  if (reconnectTimer) return;
  reconnectTimer = setTimeout(async () => {
    reconnectTimer = null;
    if (!running) return;
    try {
      // Tenta reconectar com a mesma URL (pode ter expirado — index.js vai renovar se falhar)
      connectWebSocket(wssUrl, page, apiUrl, apiKey);
    } catch (e) {
      warn(`Reconexão falhou: ${e.message}`);
      reconnectDelay = Math.min(reconnectDelay * 2, 60000);
      scheduleReconnect(wssUrl, page);
    }
  }, reconnectDelay);

  reconnectDelay = Math.min(reconnectDelay * 1.5, 60000);
}

export function startWebSocket(wssUrl, page, apiUrl, apiKey) {
  running = true;
  connectWebSocket(wssUrl, page, apiUrl, apiKey);
}

// Verifica no Worker se há solicitação de varredura manual (botão na UI)
async function checkScanRequest(apiUrl, apiKey, page) {
  try {
    const res = await fetch(`${apiUrl}/api/ultragaz/scan-orders`, {
      headers: { 'X-API-Key': apiKey }
    });
    const data = await res.json();
    if (data.pending) {
      log(`🔍 Varredura solicitada pelo operador — iniciando...`);
      return true;
    }
  } catch {}
  return false;
}

// Executa varredura e processa pedidos encontrados
async function runScan(page, source = 'auto') {
  const log  = (msg) => console.log(`[ws] ${new Date().toISOString()} ${msg}`);
  const warn = (msg) => console.warn(`[ws] ${new Date().toISOString()} ${msg}`);
  log(`🔍 Varredura [${source}] — buscando pedidos em aberto...`);
  try {
    const pending = await getPendingOrders(page);
    if (pending && Array.isArray(pending) && pending.length > 0) {
      log(`📋 ${pending.length} pedido(s) em aberto — processando...`);
      for (const order of pending) {
        const orderId = order.id || order.ID_ORDER_LINK || order.order_id;
        if (!orderId) continue;
        try {
          let details = {};
          try { details = await getOrderDetails(page, orderId) || {}; } catch {}
          if (onNewOrder) {
            await onNewOrder({
              ultragaz_order_id: String(orderId),
              event_type: 'pendingOrder',
              raw_payload: order,
              ...parseDetails(details, order),
            });
          }
        } catch (e) {
          warn(`Erro ao processar #${orderId}: ${e.message}`);
        }
      }
    } else {
      log(`✅ Nenhum pedido em aberto [${source}]`);
    }
  } catch (e) {
    warn(`Varredura [${source}] falhou: ${e.message}`);
  }
}

function startPeriodicScan(apiUrl, apiKey, page) {
  stopPeriodicScan();
  const log = (msg) => console.log(`[ws] ${new Date().toISOString()} ${msg}`);
  log(`⏱ Varredura automática a cada ${SCAN_INTERVAL_MS / 60000} minutos ativada`);
  scanInterval = setInterval(async () => {
    // Verifica solicitação manual primeiro
    const manual = await checkScanRequest(apiUrl, apiKey, page);
    await runScan(page, manual ? 'manual' : 'auto');
  }, SCAN_INTERVAL_MS);
}

function stopPeriodicScan() {
  if (scanInterval) { clearInterval(scanInterval); scanInterval = null; }
}

export function stopWebSocket() {
  running = false;
  stopPing();
  stopPeriodicScan();
  if (reconnectTimer) { clearTimeout(reconnectTimer); reconnectTimer = null; }
  if (wsInstance) { try { wsInstance.terminate(); } catch {} wsInstance = null; }
}

// Parseia os detalhes retornados pelo GET_SELECTS para o formato MoskoGás
function parseDetails(details, rawData) {
  // O GET_SELECTS retorna estrutura que pode variar — tenta extrair campos comuns
  const d = details || {};

  // Campos possíveis retornados pelo APEX GET_SELECTS
  const customer_name  = d.NAME_CUSTOMER || d.customer_name || d.NOME_CLIENTE || rawData.NAME_CUSTOMER || '';
  const address_line   = d.ADDRESS || d.address_line || d.ENDERECO || d.LOGRADOURO || '';
  const bairro         = d.BAIRRO || d.bairro || '';
  const complemento    = d.COMPLEMENTO || d.complemento || '';
  const referencia     = d.REFERENCIA || d.referencia || '';
  const phone_digits   = (d.PHONE || d.phone || d.TELEFONE || '').replace(/\D/g, '');
  const produto        = d.PRODUCT || d.produto || d.PRODUTO || d.DESCRICAO_PRODUTO || 'P13';
  const quantidade     = parseInt(d.QUANTITY || d.quantidade || d.QTD || 1) || 1;
  const valor_unit     = parseFloat(d.UNIT_VALUE || d.valor_unit || d.VALOR_UNIT || 0) || 0;
  const total_value    = parseFloat(d.TOTAL || d.total_value || d.VALOR_TOTAL || d.TOTAL_VALUE || 0) || 0;
  const forma_pagamento = d.PAYMENT_FORM || d.forma_pagamento || d.FORMA_PAGAMENTO || '';

  return {
    customer_name, address_line, bairro, complemento, referencia,
    phone_digits, produto, quantidade, valor_unit, total_value, forma_pagamento,
  };
}
