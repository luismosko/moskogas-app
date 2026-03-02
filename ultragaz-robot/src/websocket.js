// websocket.js — Conexão WebSocket com Hub Ultragaz + listener de eventos
import { WebSocket } from 'ws';
import { getOrderDetails } from './browser.js';

const log  = (msg) => console.log(`[ws] ${new Date().toISOString()} ${msg}`);
const warn = (msg) => console.warn(`[ws] ${new Date().toISOString()} ${msg}`);

// Tipos de evento que geram pedido novo
const NEW_ORDER_EVENTS = ['newOrder', 'newOrderUG'];

let wsInstance = null;
let pingInterval = null;
let reconnectTimer = null;
let reconnectDelay = 5000;
let running = false;

// Callback chamado quando chega pedido novo — definido pelo index.js
let onNewOrder = null;

export function setNewOrderHandler(fn) {
  onNewOrder = fn;
}

// Conecta ao WebSocket com URL assinada
export function connectWebSocket(wssUrl, page) {
  if (wsInstance) {
    try { wsInstance.terminate(); } catch {}
    wsInstance = null;
  }

  log(`Conectando WSS...`);
  wsInstance = new WebSocket(wssUrl);

  wsInstance.on('open', () => {
    log('✅ WebSocket conectado!');
    reconnectDelay = 5000; // reset backoff
    startPing(wssUrl, page);
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
    scheduleReconnect(wssUrl, page);
  });

  wsInstance.on('error', (err) => {
    warn(`Erro WebSocket: ${err.message}`);
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

function scheduleReconnect(wssUrl, page) {
  if (reconnectTimer) return;
  reconnectTimer = setTimeout(async () => {
    reconnectTimer = null;
    if (!running) return;
    try {
      // Tenta reconectar com a mesma URL (pode ter expirado — index.js vai renovar se falhar)
      connectWebSocket(wssUrl, page);
    } catch (e) {
      warn(`Reconexão falhou: ${e.message}`);
      reconnectDelay = Math.min(reconnectDelay * 2, 60000);
      scheduleReconnect(wssUrl, page);
    }
  }, reconnectDelay);

  reconnectDelay = Math.min(reconnectDelay * 1.5, 60000);
}

export function startWebSocket(wssUrl, page) {
  running = true;
  connectWebSocket(wssUrl, page);
}

export function stopWebSocket() {
  running = false;
  stopPing();
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
