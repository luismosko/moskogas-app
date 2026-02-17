// shared.js — Utilitários compartilhados MoskoGás v1.1.0
const API_BASE = 'https://api.moskogas.com.br';
const API_KEY  = localStorage.getItem('mg_api_key') || '';

function apiKey() {
  return localStorage.getItem('mg_api_key') || '';
}

async function api(path, options = {}) {
  const resp = await fetch(API_BASE + path, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      'X-API-KEY': apiKey(),
      ...(options.headers || {}),
    },
  });
  if (!resp.ok) {
    const e = await resp.json().catch(() => ({ error: resp.statusText }));
    throw new Error(e.error || 'Erro ' + resp.status);
  }
  return resp.json();
}

function statusBadge(status) {
  const map = {
    novo:             ['🔴', '#dc2626', 'NOVO'],
    encaminhado:      ['🟡', '#d97706', 'ENCAMINHADO'],
    whatsapp_enviado: ['🟢', '#16a34a', 'WHATS ENVIADO'],
    entregue:         ['🔵', '#2563eb', 'ENTREGUE'],
    cancelado:        ['⚫', '#6b7280', 'CANCELADO'],
  };
  const [emoji, color, label] = map[status] || ['⚪', '#888', status];
  return `<span style="background:${color};color:#fff;padding:2px 8px;border-radius:12px;font-size:11px;font-weight:700;">${emoji} ${label}</span>`;
}

function payBadge(status) {
  const map = {
    pendente:  ['#dc2626', 'PENDENTE'],
    recebido:  ['#16a34a', 'RECEBIDO'],
    estornado: ['#6b7280', 'ESTORNADO'],
  };
  const [color, label] = map[status] || ['#888', status];
  return `<span style="background:${color};color:#fff;padding:2px 8px;border-radius:12px;font-size:11px;font-weight:700;">${label}</span>`;
}

function fmtDate(ts) {
  if (!ts) return '—';
  return new Date(ts * 1000).toLocaleString('pt-BR', { timeZone: 'America/Campo_Grande', dateStyle: 'short', timeStyle: 'short' });
}

function today() {
  return new Date().toLocaleDateString('sv-SE', { timeZone: 'America/Campo_Grande' });
}

function toast(msg, type = 'success') {
  const el = document.createElement('div');
  el.textContent = msg;
  el.style.cssText = `position:fixed;top:16px;right:16px;padding:12px 20px;border-radius:8px;
    background:${type === 'error' ? '#dc2626' : '#16a34a'};color:#fff;font-weight:700;
    z-index:9999;box-shadow:0 4px 12px rgba(0,0,0,0.3);font-size:14px;`;
  document.body.appendChild(el);
  setTimeout(() => el.remove(), 3000);
}

const NAV_HTML = `
<nav style="background:#334155;padding:10px 20px;display:flex;gap:12px;align-items:center;flex-wrap:wrap;">
  <a href="https://moskogas.com.br" target="_blank" style="margin-right:12px;display:flex;align-items:center;"><img src="https://moskogas.com.br/wp-content/uploads/2021/08/Logo-Moskogas-Ultragaz.png" alt="Mosko Gás" style="height:32px;" onerror="this.style.display='none'"></a>
  <a href="pedido.html" class="nav-btn">➕ Novo Pedido</a>
  <a href="gestao.html" class="nav-btn">📋 Gestão</a>
  <a href="entregador.html" class="nav-btn">🚚 Entregador</a>
  <a href="pagamentos.html" class="nav-btn">💰 Pagamentos</a>
  <a href="relatorio.html" class="nav-btn">📊 Relatório</a>
  <a href="config.html" class="nav-btn" style="margin-left:auto;">⚙️ Config</a>
</nav>
<style>
  .nav-btn { color:#94a3b8;text-decoration:none;padding:6px 14px;border-radius:6px;font-size:13px;font-weight:600; }
  .nav-btn:hover { background:#475569;color:#fff; }
</style>`;

function checkApiKey() {
  if (!apiKey() && !window.location.pathname.includes('config')) {
    const k = prompt('🔑 Digite a APP_API_KEY para acessar o sistema:');
    if (k) localStorage.setItem('mg_api_key', k);
    else window.location.href = 'config.html';
  }
}
