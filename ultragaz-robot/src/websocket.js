// websocket.js — Conexão WebSocket com Hub Ultragaz + listener de eventos
import { WebSocket } from 'ws';
import { enviarCancelamento } from './moskogas.js';
import { getOrderDetails, getPendingOrders, getCanceledOrders } from './browser.js';

const log  = (msg) => console.log(`[ws] ${new Date().toISOString()} ${msg}`);
const warn = (msg) => console.warn(`[ws] ${new Date().toISOString()} ${msg}`);

// Tipos de evento que geram pedido novo
const NEW_ORDER_EVENTS = ['newOrder', 'newOrderUG'];

// IDs de cancelamentos já notificados (evita re-notificar a cada varredura)
const canceledSeen = new Set();

let wsInstance = null;
let pingInterval = null;
let reconnectTimer = null;
let reconnectDelay = 5000;
let running = false;
let consecutive401 = 0;
let scanInterval = null;
let heartbeatInterval = null;
const SCAN_INTERVAL_MS = 60 * 1000; // varredura automática a cada 60 segundos
const HEARTBEAT_MS = 3 * 60 * 1000; // heartbeat a cada 3 minutos (worker expira em 30min)

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
    startHeartbeat(apiUrl, apiKey);

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
    stopHeartbeat();
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
    // Verifica cancelamentos na aba "Pedidos Cancelados"
    await runCancelScan(page, source);

  } catch (e) {
    warn(`Varredura [${source}] falhou: ${e.message}`);
  }
}

// Varre aba de cancelados e notifica MoskoGás
async function runCancelScan(page, source) {
  try {
    const cancelados = await getCanceledOrders(page);
    if (!cancelados || cancelados.length === 0) return;
    for (const order of cancelados) {
      const orderId = String(order.id);
      if (canceledSeen.has(orderId)) continue;
      canceledSeen.add(orderId);
      try {
        const result = await enviarCancelamento(orderId);
        if (result.cancelado) {
          log(`🚫 Cancelamento #${orderId} notificado — pedido MoskoGás #${result.moskogas_order_id}`);
        } else if (result.nao_encontrado) {
          // Pedido cancelado no Hub que não estava no MoskoGás — ignorar silenciosamente
        }
      } catch (e) {
        warn(`Erro ao notificar cancelamento #${orderId}: ${e.message}`);
        canceledSeen.delete(orderId); // permite retry
      }
    }
  } catch (e) {
    warn(`runCancelScan falhou: ${e.message}`);
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

// Heartbeat — atualiza timestamp do status a cada 3min para evitar falso "desconectado"
async function _sendHeartbeat(apiUrl, apiKey) {
  try {
    await fetch(`${apiUrl}/api/ultragaz/hub-status`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-API-Key': apiKey },
      body: JSON.stringify({
        conectado: true, status: 'conectado',
        mensagem: `Conectado (heartbeat ${new Date().toLocaleString('pt-BR', { timeZone: 'America/Campo_Grande' })})`,
        updated_at: new Date().toISOString()
      })
    });
  } catch {}
}

function startHeartbeat(apiUrl, apiKey) {
  stopHeartbeat();
  const log = (msg) => console.log(`[ws] ${new Date().toISOString()} ${msg}`);
  _sendHeartbeat(apiUrl, apiKey); // imediato ao conectar
  heartbeatInterval = setInterval(async () => {
    await _sendHeartbeat(apiUrl, apiKey);
  }, HEARTBEAT_MS);
  log(`💓 Heartbeat ativado (a cada ${HEARTBEAT_MS / 60000} min)`);
}

function stopHeartbeat() {
  if (heartbeatInterval) { clearInterval(heartbeatInterval); heartbeatInterval = null; }
}

function stopPeriodicScan() {
  if (scanInterval) { clearInterval(scanInterval); scanInterval = null; }
}

export function stopWebSocket() {
  running = false;
  stopPing();
  stopPeriodicScan();
  stopHeartbeat();
  if (reconnectTimer) { clearTimeout(reconnectTimer); reconnectTimer = null; }
  if (wsInstance) { try { wsInstance.terminate(); } catch {} wsInstance = null; }
}

// Parseia os detalhes retornados pelo GET_SELECTS para o formato MoskoGás
//
// Layout confirmado em 07/03/2026:
// Aba "Em Aberto" / "Em Andamento":
//   [0]=ícone, [1]=pedidoID, [2]=data, [3]=cliente, [4]=produto, [5]=qtd,
//   [6]=formaPgto, [7]=endereço, [8]=vlrUnit, [9]=desconto, [10]=total, [11]=reembolso, [12]=entregador
//
// Aba "Agendados":
//   [0]=pedidoID, [1]=modalidade, [2]=dataAgendada, [3]=horário, [4]=endereço,
//   [5]=produto, [6]=qtd, [7]=vlrUnit, [8]=desconto, [9]=total, [10]=cliente
//
function parseDetails(details, rawData) {
  const d = details || {};
  const cells = rawData.cells || [];
  const tab   = rawData.tab  || '';

  // Normaliza valor (ex: "111,00" → 111.00)
  const parseValor = (v) => parseFloat(String(v).replace(/\./g, '').replace(',', '.')) || 0;

  // Mapeia produto Hub para código interno
  const mapProduto = (p) => {
    const pu = String(p).toUpperCase();
    if (/P45|45KG/.test(pu)) return 'P45';
    if (/P20|20KG/.test(pu)) return 'P20';
    if (/P13|13KG/.test(pu)) return 'P13';
    if (/ÁGUA|AGUA|20L|WATER/.test(pu)) return 'AGUA20L';
    return p || 'P13';
  };

  let domCliente, domProduto, domQtd, domPgto, domEndereco, domVlrUnit, domTotal;

  if (/Agendad/i.test(tab)) {
    // Aba Pedidos Agendados — layout confirmado 07/03/2026:
    // [0]=ícone [1]=pedidoID [2]=modalidade [3]=data [4]=horário
    // [5]=endereço [6]=produto [7]=qtd [8]=vlrUnit [9]=desconto [10]=total [11]=cliente [12]=Cancelar
    domCliente  = cells[11] || '';
    domProduto  = cells[6]  || '';
    domQtd      = cells[7]  || '1';
    domPgto     = cells[2]  || '';   // modalidade de entrega
    domEndereco = cells[5]  || '';
    domVlrUnit  = cells[8]  || '0';
    domTotal    = cells[10] || '0';
  } else {
    // Aba Em Aberto / Em Andamento
    domCliente  = cells[3]  || '';
    domProduto  = cells[4]  || '';
    domQtd      = cells[5]  || '1';
    domPgto     = cells[6]  || '';
    domEndereco = cells[7]  || '';
    domVlrUnit  = cells[8]  || '0';
    domTotal    = cells[10] || '0';
  }

  const customer_name   = d.NAME_CUSTOMER || d.NOME_CLIENTE || domCliente || '';
  const address_line    = d.ADDRESS || d.ENDERECO || domEndereco || '';
  const bairro          = d.BAIRRO || d.bairro || '';
  const complemento     = d.COMPLEMENTO || d.complemento || '';
  const referencia      = d.REFERENCIA || d.referencia || '';
  const phone_digits    = (d.PHONE || d.TELEFONE || '').replace(/\D/g, '');
  const produto         = mapProduto(d.PRODUCT || d.PRODUTO || domProduto);
  const quantidade      = parseInt(d.QUANTITY || d.QTD || domQtd) || 1;
  const valor_unit      = parseValor(d.UNIT_VALUE || d.VALOR_UNIT || domVlrUnit);
  const total_value     = parseValor(d.TOTAL || d.VALOR_TOTAL || domTotal);
  const forma_pagamento = d.PAYMENT_FORM || d.FORMA_PAGAMENTO || domPgto || '';

  const log = (msg) => console.log(`[ws] ${new Date().toISOString()} ${msg}`);
  log(`parseDetails [${tab}] — cliente:"${customer_name}" prod:"${produto}" qtd:${quantidade} total:${total_value} pgto:"${forma_pagamento}" end:"${address_line.substring(0,40)}"`);

  return {
    customer_name, address_line, bairro, complemento, referencia,
    phone_digits, produto, quantidade, valor_unit, total_value, forma_pagamento,
  };
}
