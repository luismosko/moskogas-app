// IZGLP — Background Service Worker v2.0.0
// Hub Ultragaz + Bina Virtual — Sistema integrado

const SCAN_INTERVAL_MINUTES = 1;
const HUB_URL_PATTERN   = 'https://hub.ultragaz.com.br/*';
const IZCHAT_URL_PATTERN = 'https://chat.izchat.com.br/*';
const MOSKO_URL_PATTERN = 'https://moskogas-app.pages.dev/*';
const DEFAULT_API_KEY   = 'Moskogas0909';
const DEFAULT_API_URL   = 'https://api.moskogas.com.br';

// ══════════════════════════════════════════════════════════════════════════════
// ALARME PERIÓDICO (Hub)
// ══════════════════════════════════════════════════════════════════════════════
try {
  if (chrome.runtime && chrome.runtime.onInstalled) {
    chrome.runtime.onInstalled.addListener(() => {
      chrome.alarms.create('scan', { periodInMinutes: SCAN_INTERVAL_MINUTES });
      console.log('[IZGLP] Instalado. Scan Hub a cada', SCAN_INTERVAL_MINUTES, 'min.');
      
      // Configurações padrão
      chrome.storage.sync.set({
        bina_enabled: true,
        bina_position: 'right'
      });
    });
  }
} catch (e) {}

try {
  chrome.alarms.get('scan', alarm => {
    if (!alarm) chrome.alarms.create('scan', { periodInMinutes: SCAN_INTERVAL_MINUTES });
  });
} catch (e) {}

chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name === 'scan') await triggerScanOnHubTab();
});

// ══════════════════════════════════════════════════════════════════════════════
// CONFIG
// ══════════════════════════════════════════════════════════════════════════════
async function getConfig() {
  return new Promise(resolve => {
    chrome.storage.sync.get(['apiKey', 'apiUrl'], data => {
      resolve({
        apiKey: (data.apiKey && data.apiKey.trim()) ? data.apiKey.trim() : DEFAULT_API_KEY,
        apiUrl: (data.apiUrl && data.apiUrl.trim()) ? data.apiUrl.trim() : DEFAULT_API_URL,
      });
    });
  });
}

// ══════════════════════════════════════════════════════════════════════════════
// API CALLS
// ══════════════════════════════════════════════════════════════════════════════
async function apiCall(path, body, method = 'POST') {
  const config = await getConfig();
  const url = `${config.apiUrl}${path}${path.includes('?') ? '&' : '?'}api_key=${encodeURIComponent(config.apiKey)}`;
  try {
    const opts = {
      method,
      headers: { 'Content-Type': 'application/json', 'X-API-KEY': config.apiKey },
    };
    if (method !== 'GET' && body) opts.body = JSON.stringify(body);
    
    const resp = await fetch(url, opts);
    const data = await resp.json().catch(() => ({}));
    console.log(`[IZGLP] ${method} ${path} → HTTP ${resp.status}`);
    return { status: resp.status, data };
  } catch (e) {
    console.warn(`[IZGLP] Erro ${path}:`, e.message);
    return { status: 0, data: {} };
  }
}

async function apiGet(path) {
  return apiCall(path, null, 'GET');
}

// ══════════════════════════════════════════════════════════════════════════════
// HUB ULTRAGAZ — FUNÇÕES
// ══════════════════════════════════════════════════════════════════════════════
async function sendOrder(orderData) {
  const result = await apiCall('/api/ultragaz/pedido', orderData);
  return result.data;
}

async function cancelOrder(ultragazOrderId) {
  const result = await apiCall('/api/ultragaz/cancelar', { ultragaz_order_id: String(ultragazOrderId) });
  return result.data;
}

async function updateHubStatus(conectado, status) {
  const config = await getConfig();
  const url = `${config.apiUrl}/api/ultragaz/hub-status?api_key=${encodeURIComponent(config.apiKey)}`;
  try {
    await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-API-KEY': config.apiKey },
      body: JSON.stringify({ conectado, status, mensagem: 'IZGLP Extension v2.0.0', updated_at: new Date().toISOString() }),
    });
  } catch {}
}

async function isPaused() {
  return new Promise(resolve => {
    chrome.storage.local.get(['pausedUntil'], data => {
      if (!data.pausedUntil) return resolve(false);
      if (Date.now() < data.pausedUntil) return resolve(true);
      chrome.storage.local.remove('pausedUntil');
      resolve(false);
    });
  });
}

async function triggerScanOnHubTab() {
  if (await isPaused()) {
    console.log('[IZGLP] ⏸ Hub pausado — pulando varredura');
    return;
  }

  try {
    const tabs = await chrome.tabs.query({ url: HUB_URL_PATTERN });
    if (tabs.length === 0) { await updateHubStatus(false, 'desconectado'); return; }

    const tab = tabs[0];

    console.log('[IZGLP] 🔄 Recarregando Hub...');
    await chrome.tabs.reload(tab.id);
    await new Promise(r => setTimeout(r, 6000));

    try {
      await chrome.scripting.executeScript({ target: { tabId: tab.id }, files: ['content-hub.js'] });
      await new Promise(r => setTimeout(r, 1000));
    } catch (e) {
      console.warn('[IZGLP] Erro injetar:', e.message);
      return;
    }

    const response = await chrome.tabs.sendMessage(tab.id, { type: 'SCAN' }).catch(() => null);
    if (!response) console.log('[IZGLP] Sem resposta da aba');

  } catch (e) {
    console.warn('[IZGLP] Erro scan:', e.message);
  }
}

async function refreshMoskoGasTabs() {
  try {
    const tabs = await chrome.tabs.query({ url: MOSKO_URL_PATTERN });
    for (const tab of tabs) await chrome.tabs.reload(tab.id);
    if (tabs.length > 0) console.log(`[IZGLP] ✅ ${tabs.length} aba(s) IZGLP atualizada(s)`);
  } catch(e) {}
}

// ══════════════════════════════════════════════════════════════════════════════
// BINA — FUNÇÕES
// ══════════════════════════════════════════════════════════════════════════════
async function searchCustomer(phone) {
  const result = await apiGet(`/api/customer/search?q=${phone}&type=phone`);
  return result;
}

async function getLastOrder(phone) {
  const result = await apiGet(`/api/customer/last-order?phone=${phone}`);
  return result;
}

// ══════════════════════════════════════════════════════════════════════════════
// MENSAGENS
// ══════════════════════════════════════════════════════════════════════════════
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {

  // ── HUB: Processa pedidos ──────────────────────────────────────────────────
  if (msg.type === 'PROCESS_ORDERS') {
    (async () => {
      const { activeOrders, canceledIds } = msg;
      let novos = 0, cancelamentos = 0;

      for (const order of (activeOrders || [])) {
        const r = await sendOrder(order.payload);
        if (r && r.ok && !r.duplicado) {
          novos++;
          console.log(`[IZGLP] ✅ Criado #${r.moskogas_order_id}`);
        }
      }

      for (const id of (canceledIds || [])) {
        const r = await cancelOrder(id);
        if (r && r.cancelado) {
          cancelamentos++;
          console.log(`[IZGLP] 🚫 Cancelado Hub #${id}`);
        }
      }

      await updateHubStatus(true, 'conectado');

      if (novos > 0) {
        refreshMoskoGasTabs();
        chrome.notifications.create(`scan-${Date.now()}`, {
          type: 'basic', iconUrl: 'icons/icon48.png',
          title: '🛒 Novo pedido Ultragaz!',
          message: `${novos} pedido(s) novo(s) no IZGLP!`,
        });
      }

      chrome.storage.local.set({ lastScan: { ts: Date.now(), novos, cancelamentos, total: (activeOrders||[]).length } });
      sendResponse({ ok: true, novos, cancelamentos });
    })();
    return true;
  }

  // ── HUB: Controles ─────────────────────────────────────────────────────────
  if (msg.type === 'PAUSE') {
    const minutes = msg.minutes || 10;
    const until = Date.now() + (minutes * 60 * 1000);
    chrome.storage.local.set({ pausedUntil: until }, () => {
      console.log(`[IZGLP] ⏸ Hub pausado por ${minutes} minutos`);
      sendResponse({ ok: true, until });
    });
    return true;
  }
  
  if (msg.type === 'RESUME') {
    chrome.storage.local.remove('pausedUntil', () => {
      console.log('[IZGLP] ▶️ Hub retomado');
      sendResponse({ ok: true });
    });
    return true;
  }
  
  if (msg.type === 'GET_PAUSE_STATUS') {
    chrome.storage.local.get(['pausedUntil'], data => {
      const paused = data.pausedUntil && Date.now() < data.pausedUntil;
      sendResponse({ paused: !!paused, until: data.pausedUntil || 0 });
    });
    return true;
  }
  
  if (msg.type === 'SCAN_NOW') {
    triggerScanOnHubTab().then(() => sendResponse({ ok: true }));
    return true;
  }

  // ── Config ─────────────────────────────────────────────────────────────────
  if (msg.type === 'SAVE_CONFIG') {
    chrome.storage.sync.set({ apiKey: msg.apiKey, apiUrl: msg.apiUrl || DEFAULT_API_URL }, () => sendResponse({ ok: true }));
    return true;
  }

  if (msg.type === 'TEST_API_KEY') {
    (async () => {
      const result = await apiCall('/api/ultragaz/hub-status', {
        conectado: true, status: 'testando', mensagem: 'Teste conexão IZGLP', updated_at: new Date().toISOString()
      });
      sendResponse({ ok: result.status >= 200 && result.status < 300 });
    })();
    return true;
  }

  // ── BINA: Busca cliente ────────────────────────────────────────────────────
  if (msg.type === 'BINA_SEARCH') {
    (async () => {
      const phone = msg.phone;
      
      // Busca no cache local
      const result = await searchCustomer(phone);
      
      if (result.status === 200 && result.data && result.data.length > 0) {
        sendResponse({ ok: true, found: true, client: result.data[0] });
        return;
      }
      
      // Tenta buscar última compra
      const lastOrder = await getLastOrder(phone);
      if (lastOrder.status === 200 && lastOrder.data && lastOrder.data.order) {
        const order = lastOrder.data.order;
        sendResponse({ 
          ok: true, 
          found: true, 
          client: {
            name: order.customer_name,
            address_line: order.address_line,
            bairro: order.bairro,
            complemento: order.complemento,
            referencia: order.referencia
          },
          lastOrder: order
        });
        return;
      }
      
      sendResponse({ ok: true, found: false });
    })();
    return true;
  }

  // ── BINA: Controles ────────────────────────────────────────────────────────
  if (msg.type === 'BINA_SET_ENABLED') {
    chrome.storage.sync.set({ bina_enabled: msg.enabled }, () => {
      sendResponse({ ok: true });
    });
    return true;
  }

  if (msg.type === 'BINA_GET_STATUS') {
    chrome.storage.sync.get(['bina_enabled'], data => {
      sendResponse({ enabled: data.bina_enabled !== false });
    });
    return true;
  }

  // ── Abrir IZGLP ────────────────────────────────────────────────────────────
  if (msg.type === 'OPEN_IZGLP') {
    chrome.tabs.create({
      url: `https://moskogas-app.pages.dev/${msg.page || 'pedido.html'}${msg.phone ? '?phone=' + msg.phone : ''}`
    });
    sendResponse({ ok: true });
    return true;
  }

  // ── GET CONFIG ─────────────────────────────────────────────────────────────
  if (msg.type === 'GET_CONFIG') {
    getConfig().then(config => sendResponse(config));
    return true;
  }
});

// ══════════════════════════════════════════════════════════════════════════════
// SCAN INICIAL
// ══════════════════════════════════════════════════════════════════════════════
triggerScanOnHubTab();

console.log('[IZGLP] 🟢 Background v2.0.0 ativo');
