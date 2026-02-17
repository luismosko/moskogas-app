// shared.js — Utilitários compartilhados MoskoGás v1.4.0
// v1.4.0: Nav com link Auditoria

const API_BASE = 'https://api.moskogas.com.br';

function getSessionToken() {
  return localStorage.getItem('mg_session_token') || '';
}

function getCurrentUser() {
  try { return JSON.parse(localStorage.getItem('mg_user') || 'null'); } catch { return null; }
}

function apiKey() {
  return localStorage.getItem('mg_api_key') || '';
}

async function api(path, options = {}) {
  const token = getSessionToken();
  const key = apiKey();
  const headers = {
    'Content-Type': 'application/json',
    ...(options.headers || {}),
  };
  // Prioriza sessão, fallback para API key
  if (token) headers['Authorization'] = 'Bearer ' + token;
  else if (key) headers['X-API-KEY'] = key;

  const resp = await fetch(API_BASE + path, { ...options, headers });

  // Se 401, redireciona para login
  if (resp.status === 401) {
    localStorage.removeItem('mg_session_token');
    localStorage.removeItem('mg_user');
    window.location.href = 'login.html';
    throw new Error('Sessão expirada');
  }

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
  // Remove toast anterior se existir
  const old = document.getElementById('mg-toast');
  if (old) old.remove();

  const el = document.createElement('div');
  el.id = 'mg-toast';
  const icon = type === 'error' ? '❌' : '✅';
  const bg = type === 'error' ? '#dc2626' : '#16a34a';
  el.innerHTML = `<span style="font-size:22px;margin-right:8px;">${icon}</span><span>${msg}</span>`;
  el.style.cssText = `position:fixed;top:20px;left:50%;transform:translateX(-50%) translateY(-100px);
    padding:16px 28px;border-radius:12px;background:${bg};color:#fff;font-weight:700;
    z-index:99999;box-shadow:0 8px 30px rgba(0,0,0,0.4);font-size:16px;
    display:flex;align-items:center;max-width:90vw;
    transition:transform 0.3s cubic-bezier(0.34,1.56,0.64,1), opacity 0.3s ease;opacity:0;`;
  document.body.appendChild(el);
  // Anima entrada
  requestAnimationFrame(() => {
    el.style.transform = 'translateX(-50%) translateY(0)';
    el.style.opacity = '1';
  });
  // Anima saída
  setTimeout(() => {
    el.style.transform = 'translateX(-50%) translateY(-100px)';
    el.style.opacity = '0';
    setTimeout(() => el.remove(), 400);
  }, 3500);
}

// ── Navegação por Role ────────────────────────────────────────

const NAV_ITEMS = [
  { href: 'pedido.html',      icon: '➕', label: 'Novo Pedido', roles: ['admin', 'atendente'] },
  { href: 'gestao.html',      icon: '📋', label: 'Gestão',      roles: ['admin', 'atendente'] },
  { href: 'entregador.html',  icon: '🚚', label: 'Entregador',  roles: ['admin', 'atendente', 'entregador'] },
  { href: 'pagamentos.html',  icon: '💰', label: 'Pagamentos',  roles: ['admin'] },
  { href: 'relatorio.html',   icon: '📊', label: 'Relatório',   roles: ['admin'] },
  { href: 'auditoria.html',   icon: '🔍', label: 'Auditoria',   roles: ['admin'] },
  { href: 'usuarios.html',    icon: '👥', label: 'Usuários',     roles: ['admin'] },
  { href: 'config.html',      icon: '⚙️', label: 'Config',      roles: ['admin'], right: true },
];

function buildNav() {
  const user = getCurrentUser();
  const role = user?.role || 'admin';

  const links = NAV_ITEMS
    .filter(item => item.roles.includes(role))
    .map(item => `<a href="${item.href}" class="nav-btn">${item.icon} ${item.label}</a>`)
    .join('\n  ');

  const userInfo = user
    ? `<span style="color:#94a3b8;font-size:11px;">👤 ${user.nome} <span style="background:#475569;padding:1px 6px;border-radius:4px;font-size:9px;">${user.role.toUpperCase()}</span></span>
  <a href="#" onclick="doLogout();return false" class="nav-btn" style="color:#f87171;font-size:12px;">⬅ Sair</a>`
    : '';

  return `
<nav style="background:#334155;padding:10px 20px;display:flex;gap:12px;align-items:center;flex-wrap:wrap;">
  <a href="https://moskogas.com.br" target="_blank" style="margin-right:12px;display:flex;align-items:center;"><img src="https://moskogas.com.br/wp-content/uploads/2021/08/Logo-Moskogas-Ultragaz.png" alt="Mosko Gás" style="height:32px;" onerror="this.style.display='none'"></a>
  ${links}
  <span style="margin-left:auto;display:flex;align-items:center;gap:8px;">${userInfo}</span>
</nav>
<style>
  .nav-btn { color:#94a3b8;text-decoration:none;padding:6px 14px;border-radius:6px;font-size:13px;font-weight:600; }
  .nav-btn:hover { background:#475569;color:#fff; }
</style>`;
}

// Mantém NAV_HTML para compatibilidade (páginas não migradas)
const NAV_HTML = buildNav();

function doLogout() {
  const token = getSessionToken();
  if (token) {
    fetch(API_BASE + '/api/auth/logout', {
      method: 'POST',
      headers: { 'Authorization': 'Bearer ' + token },
    }).catch(() => {});
  }
  localStorage.removeItem('mg_session_token');
  localStorage.removeItem('mg_user');
  localStorage.removeItem('mg_api_key');
  window.location.href = 'login.html';
}

// ── Verificação de Acesso ────────────────────────────────────

function checkAuth(requiredRoles = null) {
  const token = getSessionToken();
  const key = apiKey();

  // API key legacy = acesso total
  if (key && !token) return;

  // Sem token e sem key → login
  if (!token) {
    window.location.href = 'login.html';
    return;
  }

  // Verifica role
  if (requiredRoles) {
    const user = getCurrentUser();
    if (!user || !requiredRoles.includes(user.role)) {
      toast('Sem permissão para esta página', 'error');
      window.location.href = 'login.html';
      return;
    }
  }
}

// Legacy — mantém para compatibilidade
function checkApiKey() {
  // Se tem sessão, não pede API key
  if (getSessionToken()) return;
  if (!apiKey() && !window.location.pathname.includes('config') && !window.location.pathname.includes('login')) {
    window.location.href = 'login.html';
  }
}
