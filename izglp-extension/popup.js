// IZGLP — Popup Script v2.1.0

const API_URL = 'https://api.moskogas.com.br';

function toast(msg, type = 'green') {
  const el = document.getElementById('toast');
  el.textContent = msg;
  el.className = `toast toast-${type} show`;
  setTimeout(() => { el.className = 'toast'; }, 3000);
}

function timeSince(ts) {
  if (!ts) return '—';
  const diff = Math.floor((Date.now() - ts) / 1000);
  if (diff < 60)   return `há ${diff}s`;
  if (diff < 3600) return `há ${Math.floor(diff/60)}min`;
  return `há ${Math.floor(diff/3600)}h`;
}

// ══════════════════════════════════════════════════════════════════════════════
// TABS
// ══════════════════════════════════════════════════════════════════════════════
document.querySelectorAll('.tab').forEach(tab => {
  tab.addEventListener('click', () => {
    // Remove active de todas as tabs
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
    
    // Ativa a tab clicada
    tab.classList.add('active');
    document.getElementById('tab-' + tab.dataset.tab).classList.add('active');
  });
});

// ══════════════════════════════════════════════════════════════════════════════
// CONFIG
// ══════════════════════════════════════════════════════════════════════════════
function showConnected() {
  document.getElementById('config-section').style.display = 'none';
  document.getElementById('config-connected').style.display = 'flex';
}

function showConfig() {
  document.getElementById('config-section').style.display = 'block';
  document.getElementById('config-connected').style.display = 'none';
}

async function testApiKey(apiKey) {
  return new Promise(resolve => {
    chrome.storage.sync.set({ apiKey, apiUrl: API_URL }, () => {
      chrome.runtime.sendMessage({ type: 'TEST_API_KEY' }, response => {
        resolve(response && response.ok);
      });
    });
  });
}

// ══════════════════════════════════════════════════════════════════════════════
// HUB
// ══════════════════════════════════════════════════════════════════════════════
function updatePauseButton(resp) {
  const btn = document.getElementById('btn-pause');
  if (!btn) return;
  if (resp && resp.paused) {
    const mins = Math.ceil((resp.until - Date.now()) / 60000);
    btn.textContent = `▶️ Retomar (pause: ${mins}min)`;
    btn.classList.add('is-paused');
  } else {
    btn.textContent = '⏸ Pausar Varredura (10 min)';
    btn.classList.remove('is-paused');
  }
}

async function initHub() {
  // Último scan
  chrome.storage.local.get(['lastScan'], data => {
    if (data.lastScan) {
      document.getElementById('last-scan-info').textContent =
        `${timeSince(data.lastScan.ts)} · ${data.lastScan.novos} novo(s)`;
      
      const el = document.getElementById('pedidos-novos');
      el.textContent = data.lastScan.novos;
      el.className = `badge ${data.lastScan.novos > 0 ? 'badge-orange' : 'badge-green'}`;
    }
  });

  // Status de pausa
  chrome.runtime.sendMessage({ type: 'GET_PAUSE_STATUS' }, resp => {
    updatePauseButton(resp);
  });

  // Carrega alertas pendentes
  chrome.runtime.sendMessage({ type: 'GET_ALERTS' }, resp => {
    updateAlertsPanel(resp && resp.alerts);
  });

  // Verifica aba do Hub
  chrome.tabs.query({ url: 'https://hub.ultragaz.com.br/*' }, tabs => {
    const el = document.getElementById('hub-tab-status');
    if (tabs.length > 0) {
      el.textContent = '✅ Aberta';
      el.className = 'badge badge-green';
    } else {
      el.textContent = '❌ Não encontrada';
      el.className = 'badge badge-red';
    }
  });
}

// ══════════════════════════════════════════════════════════════════════════════
// BINA
// ══════════════════════════════════════════════════════════════════════════════
async function initBina() {
  // Verifica aba do IzChat
  chrome.tabs.query({ url: 'https://chat.izchat.com.br/*' }, async tabs => {
    const el = document.getElementById('izchat-tab-status');
    if (tabs.length > 0) {
      el.textContent = '✅ Aberta';
      el.className = 'badge badge-green';
      
      // Tenta obter telefone do content script
      try {
        const response = await chrome.tabs.sendMessage(tabs[0].id, { action: 'getStatus' });
        if (response && response.currentPhone) {
          const phoneEl = document.getElementById('bina-phone');
          phoneEl.textContent = formatPhone(response.currentPhone);
          phoneEl.className = 'badge badge-green';
        }
      } catch (e) {}
    } else {
      el.textContent = '❌ Não encontrada';
      el.className = 'badge badge-red';
    }
  });

  // Status do toggle
  chrome.storage.sync.get(['bina_enabled'], data => {
    document.getElementById('toggle-bina').checked = data.bina_enabled !== false;
  });
}

function formatPhone(phone) {
  if (!phone) return '—';
  const digits = phone.replace(/\D/g, '');
  if (digits.length === 13) {
    return `(${digits.slice(2,4)}) ${digits.slice(4,9)}-${digits.slice(9)}`;
  }
  return phone;
}

// ══════════════════════════════════════════════════════════════════════════════
// INIT
// ══════════════════════════════════════════════════════════════════════════════
// ── Som de alerta (Web Audio API) ─────────────────────────────────────────────
function playAlertSound() {
  try {
    const ctx = new (window.AudioContext || window.webkitAudioContext)();
    // 3 beeps ascendentes
    [600, 800, 1000].forEach((freq, i) => {
      const osc  = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.connect(gain);
      gain.connect(ctx.destination);
      osc.frequency.value = freq;
      osc.type = 'sine';
      gain.gain.setValueAtTime(0.3, ctx.currentTime + i * 0.18);
      gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + i * 0.18 + 0.15);
      osc.start(ctx.currentTime + i * 0.18);
      osc.stop(ctx.currentTime + i * 0.18 + 0.15);
    });
  } catch(e) {}
}

// ── Atualiza painel de alertas ─────────────────────────────────────────────────
function updateAlertsPanel(alerts) {
  const panel = document.getElementById('alerts-panel');
  const title = document.getElementById('alerts-title');
  const list  = document.getElementById('alerts-list');
  if (!panel) return;

  if (!alerts || alerts.length === 0) {
    panel.style.display = 'none';
    return;
  }

  panel.style.display = 'block';
  title.textContent = `${alerts.length} pedido(s) novo(s) aguardando!`;
  list.innerHTML = alerts.map(a =>
    `<div>🛒 <strong>${a.customer || 'Cliente'}</strong> · ${a.produto || 'P13'} · R$ ${parseFloat(a.total||0).toFixed(2).replace('.',',')} · Hub #${a.ultragaz_id}</div>`
  ).join('');

  // Toca som ao abrir popup se há alertas
  playAlertSound();
}

async function init() {
  // Versão
  try {
    const manifest = chrome.runtime.getManifest();
    document.getElementById('ext-version').textContent = 'Sistema de Gestão v' + manifest.version;
  } catch(e) {}

  // Config
  chrome.storage.sync.get(['apiKey'], async data => {
    if (data.apiKey) {
      const valid = await testApiKey(data.apiKey);
      if (valid) {
        document.getElementById('input-apikey').value = data.apiKey;
        showConnected();
      } else {
        showConfig();
        toast('⚠️ API Key inválida', 'red');
      }
    } else {
      showConfig();
    }
  });

  initHub();
  initBina();
}

// ══════════════════════════════════════════════════════════════════════════════
// EVENT LISTENERS
// ══════════════════════════════════════════════════════════════════════════════

// Hub: Varrer Agora
document.getElementById('btn-scan').addEventListener('click', async () => {
  const btn = document.getElementById('btn-scan');
  btn.disabled = true;
  btn.textContent = '⏳ Varrendo...';

  chrome.runtime.sendMessage({ type: 'SCAN_NOW' }, response => {
    btn.disabled = false;
    btn.textContent = '🔍 Varrer Agora';
    if (response && response.ok) {
      toast('✅ Scan iniciado!');
      setTimeout(() => initHub(), 2000);
    } else {
      toast('⚠️ Abra a aba do Hub Ultragaz', 'red');
    }
  });
});

// Hub: Pausar/Retomar
document.getElementById('btn-pause').addEventListener('click', () => {
  chrome.runtime.sendMessage({ type: 'GET_PAUSE_STATUS' }, resp => {
    if (resp && resp.paused) {
      chrome.runtime.sendMessage({ type: 'RESUME' }, () => {
        toast('▶️ Varredura retomada!');
        updatePauseButton({ paused: false });
      });
    } else {
      chrome.runtime.sendMessage({ type: 'PAUSE', minutes: 10 }, (r) => {
        toast('⏸ Pausado por 10 minutos');
        updatePauseButton({ paused: true, until: r.until });
      });
    }
  });
});

// Config: Salvar
document.getElementById('btn-save').addEventListener('click', async () => {
  const btn = document.getElementById('btn-save');
  const apiKey = document.getElementById('input-apikey').value.trim();
  if (!apiKey) { toast('Informe a API Key', 'red'); return; }

  btn.disabled = true;
  btn.textContent = '⏳ Testando...';

  const valid = await testApiKey(apiKey);

  if (!valid) {
    btn.disabled = false;
    btn.textContent = '💾 Salvar e Conectar';
    toast('❌ API Key inválida!', 'red');
    return;
  }

  chrome.runtime.sendMessage({ type: 'SAVE_CONFIG', apiKey, apiUrl: API_URL }, () => {
    btn.disabled = false;
    btn.textContent = '💾 Salvar e Conectar';
    toast('✅ Conectado com sucesso!');
    setTimeout(showConnected, 800);
  });
});

// Config: Editar
document.getElementById('btn-edit-config').addEventListener('click', showConfig);

// Bina: Toggle
document.getElementById('toggle-bina').addEventListener('change', async () => {
  const enabled = document.getElementById('toggle-bina').checked;
  
  chrome.storage.sync.set({ bina_enabled: enabled });
  
  // Notifica content script
  const tabs = await chrome.tabs.query({ url: 'https://chat.izchat.com.br/*' });
  for (const tab of tabs) {
    try {
      await chrome.tabs.sendMessage(tab.id, { action: 'setEnabled', enabled });
    } catch (e) {}
  }
  
  toast(enabled ? '✅ Bina ativada' : '❌ Bina desativada');
});

// Bina: Atualizar
document.getElementById('btn-refresh-bina').addEventListener('click', async () => {
  const btn = document.getElementById('btn-refresh-bina');
  btn.disabled = true;
  btn.textContent = '⏳ Atualizando...';
  
  const tabs = await chrome.tabs.query({ url: 'https://chat.izchat.com.br/*' });
  
  if (tabs.length === 0) {
    btn.disabled = false;
    btn.textContent = '🔄 Atualizar Bina';
    toast('⚠️ Abra o IzChat primeiro', 'red');
    return;
  }
  
  try {
    await chrome.tabs.sendMessage(tabs[0].id, { action: 'refresh' });
    toast('✅ Bina atualizada!');
  } catch (e) {
    toast('⚠️ Erro ao atualizar', 'red');
  }
  
  btn.disabled = false;
  btn.textContent = '🔄 Atualizar Bina';
  
  setTimeout(initBina, 1000);
});

// Inicia
init();
