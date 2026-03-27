// IZGLP — Background Service Worker v2.2.0
// Hub Ultragaz + Bina Virtual — Sistema integrado

const SCAN_INTERVAL_MINUTES = 3;       // ← era 1, agora 3 min entre varreduras
const HUB_URL_PATTERN    = 'https://hub.ultragaz.com.br/*';
const IZCHAT_URL_PATTERN = 'https://chat.izchat.com.br/*';
const MOSKO_URL_PATTERN  = 'https://moskogas-app.pages.dev/*';
const DEFAULT_API_KEY    = 'Moskogas0909';
const DEFAULT_API_URL    = 'https://api.moskogas.com.br';

// ── Alarme periódico ──────────────────────────────────────────────────────────
try {
  if (chrome.runtime && chrome.runtime.onInstalled) {
    chrome.runtime.onInstalled.addListener(() => {
      chrome.alarms.create('scan', { periodInMinutes: SCAN_INTERVAL_MINUTES });
      console.log('[IZGLP] Instalado. Scan Hub a cada', SCAN_INTERVAL_MINUTES, 'min.');
      chrome.storage.sync.set({ bina_enabled: true });
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

// ── Config ────────────────────────────────────────────────────────────────────
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

// ── API calls ─────────────────────────────────────────────────────────────────
async function apiCall(path, body, method = 'POST') {
  const config = await getConfig();
  const sep = path.includes('?') ? '&' : '?';
  const url = `${config.apiUrl}${path}${sep}api_key=${encodeURIComponent(config.apiKey)}`;
  try {
    const opts = { method, headers: { 'Content-Type': 'application/json', 'X-API-KEY': config.apiKey } };
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

async function apiGet(path) { return apiCall(path, null, 'GET'); }

// ── Hub: enviar/cancelar pedido ────────────────────────────────────────────────
async function sendOrder(orderData) {
  return (await apiCall('/api/ultragaz/pedido', orderData)).data;
}

async function cancelOrder(id) {
  return (await apiCall('/api/ultragaz/cancelar', { ultragaz_order_id: String(id) })).data;
}

async function updateHubStatus(conectado, status) {
  const config = await getConfig();
  try {
    await fetch(`${config.apiUrl}/api/ultragaz/hub-status?api_key=${encodeURIComponent(config.apiKey)}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-API-KEY': config.apiKey },
      body: JSON.stringify({ conectado, status, mensagem: 'IZGLP Extension v2.2.0', updated_at: new Date().toISOString() }),
    });
  } catch {}
}

// ── Pausa ─────────────────────────────────────────────────────────────────────
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

// ── Alertas pendentes ─────────────────────────────────────────────────────────
async function addPendingAlert(orderInfo) {
  return new Promise(resolve => {
    chrome.storage.local.get(['pendingAlerts'], data => {
      const alerts = data.pendingAlerts || [];
      // Não duplicar
      if (!alerts.find(a => a.ultragaz_id === orderInfo.ultragaz_id)) {
        alerts.push({ ...orderInfo, ts: Date.now() });
      }
      chrome.storage.local.set({ pendingAlerts: alerts }, resolve);
    });
  });
}

// ── Toca som de alerta na aba do Hub ─────────────────────────────────────────
async function playSoundInHubTab() {
  try {
    const tabs = await chrome.tabs.query({ url: HUB_URL_PATTERN });
    if (tabs.length === 0) return;
    // Injeta script inline que toca o áudio
    await chrome.scripting.executeScript({
      target: { tabId: tabs[0].id },
      func: (audioUrl) => {
        try {
          // Para qualquer áudio anterior
          if (window._izglpAudio) { window._izglpAudio.pause(); window._izglpAudio.currentTime = 0; }
          window._izglpAudio = new Audio(audioUrl);
          window._izglpAudio.volume = 1.0;
          window._izglpAudio.play().catch(() => {});
          console.log('[IZGLP] 🔊 Alerta sonoro tocando!');
        } catch(e) { console.warn('[IZGLP] Erro áudio:', e); }
      },
      args: [chrome.runtime.getURL('alerta.mp3')],
    });
    console.log('[IZGLP] 🔊 Som injetado na aba do Hub');
  } catch(e) {
    console.warn('[IZGLP] Erro ao tocar som:', e.message);
  }
}

// ── Atualiza badge do ícone ────────────────────────────────────────────────────
async function updateBadge() {
  return new Promise(resolve => {
    chrome.storage.local.get(['pendingAlerts'], data => {
      const count = (data.pendingAlerts || []).length;
      if (count > 0) {
        chrome.action.setBadgeText({ text: String(count) });
        chrome.action.setBadgeBackgroundColor({ color: '#f59e0b' });
      } else {
        chrome.action.setBadgeText({ text: '' });
      }
      resolve();
    });
  });
}

// ── Dispara scan ──────────────────────────────────────────────────────────────
async function triggerScanOnHubTab() {
  if (await isPaused()) {
    console.log('[IZGLP] ⏸ Hub pausado — pulando varredura');
    return;
  }

  try {
    const tabs = await chrome.tabs.query({ url: HUB_URL_PATTERN });
    if (tabs.length === 0) { await updateHubStatus(false, 'desconectado'); return; }

    const tab = tabs[0];

    // Recarrega o Hub para dados frescos
    console.log('[IZGLP] 🔄 Recarregando Hub...');
    await chrome.tabs.reload(tab.id);
    await new Promise(r => setTimeout(r, 7000)); // aguarda 7s

    // Injeta content script
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

// ── Mensagens ─────────────────────────────────────────────────────────────────
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {

  // ── Processa pedidos (vem do content-hub.js) ─────────────────────────────
  if (msg.type === 'PROCESS_ORDERS') {
    (async () => {
      const { activeOrders, canceledIds } = msg;
      let novos = 0, cancelamentos = 0;

      for (const order of (activeOrders || [])) {
        const r = await sendOrder(order.payload);
        if (r && r.ok && !r.duplicado) {
          novos++;
          console.log(`[IZGLP] ✅ Criado MoskoGás #${r.moskogas_order_id}`);
          // Salva como alerta pendente (para o popup mostrar e tocar som)
          await addPendingAlert({
            ultragaz_id: order.payload.ultragaz_order_id,
            moskogas_id: r.moskogas_order_id,
            customer:    order.payload.customer_name,
            total:       order.payload.total_value,
            produto:     order.payload.items_json ? JSON.parse(order.payload.items_json)[0]?.produto || 'P13' : 'P13',
          });
          // Toca som na aba do Hub (content script pode acessar Audio API)
          await playSoundInHubTab();
        }
      }

      for (const id of (canceledIds || [])) {
        const r = await cancelOrder(id);
        if (r && r.cancelado) {
          cancelamentos++;
          console.log(`[IZGLP] 🚫 Cancelado Hub #${id} → MoskoGás #${r.moskogas_order_id}`);
        }
      }

      await updateHubStatus(true, 'conectado');

      if (novos > 0) {
        // ⚠️ NÃO recarrega o MoskoGás — o shared.js detecta sozinho via polling
        // Recarregar destruía o banner laranja antes do usuário ver
        
        // Notificação do sistema (som padrão do Chrome)
        try {
          chrome.notifications.create(`pedido-${Date.now()}`, {
            type: 'basic', iconUrl: 'icons/icon48.png',
            title: `🛒 ${novos} novo(s) pedido(s) Ultragaz!`,
            message: `Abra o IZGLP para ver os detalhes.`,
          });
        } catch {}
      }

      chrome.storage.local.set({
        lastScan: { ts: Date.now(), novos, cancelamentos, total: (activeOrders||[]).length }
      });
      // Atualiza badge do ícone da extensão
      await updateBadge();

      sendResponse({ ok: true, novos, cancelamentos });
    })();
    return true;
  }

  // ── Pausa ────────────────────────────────────────────────────────────────
  if (msg.type === 'PAUSE') {
    const minutes = msg.minutes || 10;
    const until = Date.now() + (minutes * 60 * 1000);
    chrome.storage.local.set({ pausedUntil: until }, () => {
      sendResponse({ ok: true, until });
    });
    return true;
  }

  if (msg.type === 'RESUME') {
    chrome.storage.local.remove('pausedUntil', () => sendResponse({ ok: true }));
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

  // ── Alertas ──────────────────────────────────────────────────────────────
  if (msg.type === 'DISMISS_ALERTS') {
    chrome.storage.local.set({ pendingAlerts: [] }, () => sendResponse({ ok: true }));
    return true;
  }

  if (msg.type === 'GET_ALERTS') {
    chrome.storage.local.get(['pendingAlerts'], data => {
      sendResponse({ alerts: data.pendingAlerts || [] });
    });
    return true;
  }

  // ── Config ────────────────────────────────────────────────────────────────
  if (msg.type === 'SAVE_CONFIG') {
    chrome.storage.sync.set({ apiKey: msg.apiKey, apiUrl: msg.apiUrl || DEFAULT_API_URL }, () => {
      sendResponse({ ok: true });
    });
    return true;
  }

  if (msg.type === 'TEST_API_KEY') {
    (async () => {
      const result = await apiCall('/api/ultragaz/hub-status', {
        conectado: true, status: 'testando', mensagem: 'Teste IZGLP', updated_at: new Date().toISOString()
      });
      sendResponse({ ok: result.status >= 200 && result.status < 300 });
    })();
    return true;
  }

  // ── Bina ──────────────────────────────────────────────────────────────────
  if (msg.type === 'BINA_SEARCH') {
    (async () => {
      const result = await apiGet(`/api/customer/search?q=${msg.phone}&type=phone`);
      if (result.status === 200 && result.data && result.data.length > 0) {
        sendResponse({ ok: true, found: true, client: result.data[0] });
        return;
      }
      const lastOrder = await apiGet(`/api/customer/last-order?phone=${msg.phone}`);
      if (lastOrder.status === 200 && lastOrder.data?.order) {
        const o = lastOrder.data.order;
        sendResponse({ ok: true, found: true, client: { name: o.customer_name, address_line: o.address_line, bairro: o.bairro } });
        return;
      }
      sendResponse({ ok: true, found: false });
    })();
    return true;
  }

  if (msg.type === 'BINA_SET_ENABLED') {
    chrome.storage.sync.set({ bina_enabled: msg.enabled }, () => sendResponse({ ok: true }));
    return true;
  }

  if (msg.type === 'BINA_GET_STATUS') {
    chrome.storage.sync.get(['bina_enabled'], data => sendResponse({ enabled: data.bina_enabled !== false }));
    return true;
  }

  if (msg.type === 'OPEN_IZGLP') {
    chrome.tabs.create({ url: `https://moskogas-app.pages.dev/${msg.page || 'pedido.html'}${msg.phone ? '?phone=' + msg.phone : ''}` });
    sendResponse({ ok: true });
    return true;
  }

  if (msg.type === 'GET_CONFIG') {
    getConfig().then(config => sendResponse(config));
    return true;
  }
});

// ── Scan inicial ──────────────────────────────────────────────────────────────
triggerScanOnHubTab();
console.log('[IZGLP] 🟢 Background v2.2.0 ativo — scan a cada', SCAN_INTERVAL_MINUTES, 'min');
