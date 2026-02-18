// shared.js — Utilitários compartilhados MoskoGás v1.9.1
// v1.9.1: Consulta Pedidos adicionado ao dropdown Relatório
// v1.8.0: Nav compacta — Auditoria dentro de Relatório, Usuários dentro de Config
// v1.7.0: Dropdown usuário (Trocar Senha + Sair), modal troca senha
// v1.6.0: Loading overlay global (showLoading/hideLoading)
// v1.5.0: Navbar azul, dropdown Relatório, menu RBAC, toast warning
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
  const headers = { ...(options.headers || {}) };

  // Não sobrescrever Content-Type se já foi definido (ex: multipart)
  if (!headers['Content-Type'] && !options.body?.constructor?.name?.includes('FormData')) {
    headers['Content-Type'] = 'application/json';
  }

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
  const old = document.getElementById('mg-toast');
  if (old) old.remove();

  const el = document.createElement('div');
  el.id = 'mg-toast';
  const icons = { success: '✅', error: '❌', warning: '⚠️', info: 'ℹ️' };
  const bgs   = { success: '#16a34a', error: '#dc2626', warning: '#d97706', info: '#2563eb' };
  const icon = icons[type] || '✅';
  const bg = bgs[type] || '#16a34a';
  el.innerHTML = `<span style="font-size:22px;margin-right:8px;">${icon}</span><span>${msg}</span>`;
  el.style.cssText = `position:fixed;top:20px;left:50%;transform:translateX(-50%) translateY(-100px);
    padding:16px 28px;border-radius:12px;background:${bg};color:#fff;font-weight:700;
    z-index:99999;box-shadow:0 8px 30px rgba(0,0,0,0.4);font-size:16px;
    display:flex;align-items:center;max-width:90vw;
    transition:transform 0.3s cubic-bezier(0.34,1.56,0.64,1), opacity 0.3s ease;opacity:0;`;
  document.body.appendChild(el);
  requestAnimationFrame(() => {
    el.style.transform = 'translateX(-50%) translateY(0)';
    el.style.opacity = '1';
  });
  setTimeout(() => {
    el.style.transform = 'translateX(-50%) translateY(-100px)';
    el.style.opacity = '0';
    setTimeout(() => el.remove(), 400);
  }, 3500);
}

// ── Loading Overlay Global ────────────────────────────────────
function showLoading(msg = 'Salvando...') {
  let overlay = document.getElementById('mg-loading-overlay');
  if (overlay) { overlay.querySelector('.mg-loading-text').textContent = msg; overlay.style.display = 'flex'; return; }
  overlay = document.createElement('div');
  overlay.id = 'mg-loading-overlay';
  overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.55);display:flex;align-items:center;justify-content:center;z-index:999999;backdrop-filter:blur(3px);';
  overlay.innerHTML = `<div style="background:#fff;border-radius:20px;padding:36px 48px;text-align:center;box-shadow:0 20px 60px rgba(0,0,0,0.3);max-width:320px;animation:mgLoadPop 0.3s ease;">
    <div style="margin-bottom:16px;">
      <svg width="56" height="56" viewBox="0 0 56 56" style="animation:mgLoadSpin 1s linear infinite;">
        <circle cx="28" cy="28" r="22" fill="none" stroke="#e2e8f0" stroke-width="5"/>
        <circle cx="28" cy="28" r="22" fill="none" stroke="#2563eb" stroke-width="5" stroke-dasharray="100 40" stroke-linecap="round"/>
      </svg>
    </div>
    <div class="mg-loading-text" style="font-size:18px;font-weight:800;color:#1e293b;">${msg}</div>
    <div style="font-size:13px;color:#64748b;margin-top:6px;">Aguarde...</div>
  </div>
  <style>
    @keyframes mgLoadSpin { to { transform: rotate(360deg); } }
    @keyframes mgLoadPop { from { transform: scale(0.8); opacity: 0; } to { transform: scale(1); opacity: 1; } }
  </style>`;
  document.body.appendChild(overlay);
}

function hideLoading() {
  const overlay = document.getElementById('mg-loading-overlay');
  if (overlay) overlay.style.display = 'none';
}

// ── Navegação por Role ────────────────────────────────────────
// Cores do tema
const NAV_BG      = '#0B2A6F';
const NAV_HOVER   = '#104BB8';
const NAV_TEXT    = '#ffffffcc';
const NAV_ACTIVE  = '#ffffff';

const NAV_ITEMS = [
  { href: 'pedido.html',     icon: '➕', label: 'Novo Pedido',  roles: ['admin', 'atendente'] },
  { href: 'gestao.html',     icon: '📋', label: 'Gestão',       roles: ['admin', 'atendente'] },
  { href: 'pagamentos.html', icon: '💰', label: 'Pagamentos',   roles: ['admin', 'atendente'] },
];

// Dropdowns — cada um com ID único para abrir/fechar independente
const NAV_DROPDOWNS = [
  {
    id: 'relatorio', icon: '📊', label: 'Relatório', roles: ['admin', 'atendente'],
    children: [
      { href: 'relatorio.html',   icon: '📊', label: 'Relatório do Dia' },
      { href: 'entregador.html',  icon: '🚚', label: 'Painel Entregador' },
      { href: 'auditoria.html',   icon: '🔍', label: 'Auditoria' },
      { href: 'consulta-pedidos.html', icon: '🔎', label: 'Consulta Pedidos' },
    ]
  },
  {
    id: 'config', icon: '⚙️', label: 'Config', roles: ['admin', 'atendente'],
    children: [
      { href: 'config.html',     icon: '⚙️', label: 'Configurações' },
      { href: 'usuarios.html',   icon: '👥', label: 'Usuários' },
    ]
  },
];

// Itens para entregador (visão minimal)
const NAV_ENTREGADOR = [
  { href: 'entregador.html', icon: '🚚', label: 'Minhas Entregas', roles: ['entregador'] },
];

function buildNav() {
  const user = getCurrentUser();
  const role = user?.role || 'admin';
  const currentPage = window.location.pathname.split('/').pop() || 'index.html';

  // ── Gerar links normais ──
  let items;
  if (role === 'entregador') {
    items = NAV_ENTREGADOR;
  } else {
    items = NAV_ITEMS.filter(item => item.roles.includes(role));
  }

  let linksHtml = items.map(item => {
    const active = currentPage === item.href;
    return `<a href="${item.href}" class="mg-nav-link${active ? ' mg-nav-active' : ''}">${item.icon} ${item.label}</a>`;
  }).join('\n    ');

  // ── Dropdowns (Relatório, Config, etc) ──
  for (const dd of NAV_DROPDOWNS) {
    if (!dd.roles.includes(role)) continue;
    const isInDd = dd.children.some(c => c.href === currentPage);
    const childrenHtml = dd.children.map(c => {
      const active = currentPage === c.href;
      return `<a href="${c.href}" class="mg-dd-item${active ? ' mg-dd-active' : ''}">${c.icon} ${c.label}</a>`;
    }).join('\n        ');

    linksHtml += `
    <div class="mg-nav-dropdown">
      <button class="mg-nav-link mg-dd-trigger${isInDd ? ' mg-nav-active' : ''}" onclick="toggleNavDropdown(event, '${dd.id}')">
        ${dd.icon} ${dd.label} <span class="mg-dd-arrow">▾</span>
      </button>
      <div class="mg-dd-menu" id="mgDd_${dd.id}">
        ${childrenHtml}
      </div>
    </div>`;
  }

  // ── User dropdown (Trocar Senha + Sair) ──
  const userInfo = user
    ? `<div class="mg-user-dropdown" id="mgUserDropdown">
      <button class="mg-user-trigger" onclick="toggleUserDropdown(event)">
        👤 ${user.nome} <span class="mg-nav-role">${role.toUpperCase()}</span> <span class="mg-ud-arrow">▾</span>
      </button>
      <div class="mg-ud-menu" id="mgUserMenu">
        <a href="#" class="mg-ud-item" onclick="openTrocarSenha();return false;">🔑 Trocar Senha</a>
        <div class="mg-ud-divider"></div>
        <a href="#" class="mg-ud-item mg-ud-logout" onclick="doLogout();return false;">🚪 Sair</a>
      </div>
    </div>`
    : '';

  return `
<nav class="mg-navbar" id="mgNavbar">
  <a href="dashboard.html" class="mg-nav-logo">
    <img src="https://moskogas.com.br/wp-content/uploads/2021/08/Logo-Moskogas-Ultragaz.png" alt="MoskoGás" onerror="this.onerror=null;this.parentElement.innerHTML='<span style=\\'font-weight:800;font-size:16px;color:#fff;letter-spacing:1px\\'>MOSKOGAS</span>'">
  </a>
  <div class="mg-nav-links">
    ${linksHtml}
  </div>
  <div class="mg-nav-right">
    ${userInfo}
  </div>
  <button class="mg-nav-hamburger" onclick="toggleMobileNav()" id="mgHamburger">☰</button>
</nav>
<div class="mg-nav-mobile-overlay" id="mgMobileOverlay" onclick="closeMobileNav()"></div>

<style>
/* ── Navbar azul MoskoGás ────────────────────────────── */
.mg-navbar {
  background: ${NAV_BG};
  padding: 0 20px;
  display: flex;
  align-items: center;
  height: 52px;
  gap: 4px;
  position: relative;
  z-index: 1000;
  box-shadow: 0 2px 12px rgba(0,0,0,0.25);
}
.mg-nav-logo {
  margin-right: 16px;
  display: flex;
  align-items: center;
  flex-shrink: 0;
}
.mg-nav-logo img {
  height: 30px;
  filter: brightness(0) invert(1);
  transition: opacity 0.2s;
}
.mg-nav-logo img:hover { opacity: 0.85; }

.mg-nav-links {
  display: flex;
  align-items: center;
  gap: 2px;
  flex: 1;
}

.mg-nav-link {
  color: ${NAV_TEXT};
  text-decoration: none;
  padding: 8px 14px;
  border-radius: 6px;
  font-size: 13px;
  font-weight: 600;
  white-space: nowrap;
  transition: background 0.15s, color 0.15s;
  border: none;
  background: none;
  cursor: pointer;
  font-family: inherit;
}
.mg-nav-link:hover {
  background: ${NAV_HOVER};
  color: ${NAV_ACTIVE};
}
.mg-nav-active {
  background: ${NAV_HOVER} !important;
  color: ${NAV_ACTIVE} !important;
}

/* ── Dropdown ────────────────────────────────── */
.mg-nav-dropdown {
  position: relative;
  display: inline-flex;
}
.mg-dd-trigger {
  display: flex;
  align-items: center;
  gap: 4px;
}
.mg-dd-arrow {
  font-size: 10px;
  transition: transform 0.2s;
}
.mg-dd-menu {
  display: none;
  position: absolute;
  top: calc(100% + 4px);
  left: 0;
  background: #fff;
  border-radius: 10px;
  box-shadow: 0 8px 32px rgba(0,0,0,0.18);
  padding: 6px;
  min-width: 200px;
  z-index: 2000;
}
.mg-dd-menu.mg-dd-open {
  display: block;
  animation: mgDdSlide 0.15s ease-out;
}
@keyframes mgDdSlide {
  from { opacity: 0; transform: translateY(-6px); }
  to   { opacity: 1; transform: translateY(0); }
}
.mg-dd-item {
  display: block;
  padding: 10px 14px;
  color: #334155;
  text-decoration: none;
  font-size: 13px;
  font-weight: 600;
  border-radius: 6px;
  transition: background 0.12s;
}
.mg-dd-item:hover { background: #f1f5f9; }
.mg-dd-active { background: #e0e7ff; color: #3730a3; }

/* ── Right side (user dropdown) ────────────────────────── */
.mg-nav-right {
  margin-left: auto;
  display: flex;
  align-items: center;
  gap: 8px;
  flex-shrink: 0;
}
.mg-user-dropdown {
  position: relative;
}
.mg-user-trigger {
  color: #ffffffcc;
  font-size: 12px;
  font-weight: 600;
  white-space: nowrap;
  background: none;
  border: 1px solid rgba(255,255,255,0.15);
  border-radius: 8px;
  padding: 6px 12px;
  cursor: pointer;
  display: flex;
  align-items: center;
  gap: 6px;
  font-family: inherit;
  transition: background 0.15s;
}
.mg-user-trigger:hover { background: rgba(255,255,255,0.1); }
.mg-ud-arrow { font-size: 10px; transition: transform 0.2s; }
.mg-nav-role {
  background: rgba(255,255,255,0.15);
  padding: 1px 6px;
  border-radius: 4px;
  font-size: 9px;
  font-weight: 700;
  letter-spacing: 0.5px;
}
.mg-ud-menu {
  display: none;
  position: absolute;
  top: calc(100% + 6px);
  right: 0;
  background: #fff;
  border-radius: 10px;
  box-shadow: 0 8px 32px rgba(0,0,0,0.2);
  padding: 6px;
  min-width: 180px;
  z-index: 2001;
}
.mg-ud-menu.mg-ud-open {
  display: block;
  animation: mgDdSlide 0.15s ease-out;
}
.mg-ud-item {
  display: block;
  padding: 10px 14px;
  color: #334155;
  text-decoration: none;
  font-size: 13px;
  font-weight: 600;
  border-radius: 6px;
  transition: background 0.12s;
  cursor: pointer;
}
.mg-ud-item:hover { background: #f1f5f9; }
.mg-ud-divider { height: 1px; background: #e2e8f0; margin: 4px 6px; }
.mg-ud-logout { color: #dc2626 !important; }
.mg-ud-logout:hover { background: #fef2f2 !important; }

/* ── Modal Trocar Senha ────────────────────────── */
.mg-pwd-overlay {
  display: none;
  position: fixed;
  inset: 0;
  background: rgba(0,0,0,0.5);
  z-index: 5000;
  align-items: center;
  justify-content: center;
}
.mg-pwd-overlay.mg-pwd-open { display: flex; }
.mg-pwd-box {
  background: #fff;
  border-radius: 14px;
  padding: 28px 24px;
  width: 100%;
  max-width: 380px;
  box-shadow: 0 20px 60px rgba(0,0,0,0.3);
}
.mg-pwd-box h3 { margin: 0 0 18px; font-size: 18px; color: #1e293b; }
.mg-pwd-box label { display: block; font-size: 11px; font-weight: 700; color: #64748b; text-transform: uppercase; margin-bottom: 4px; }
.mg-pwd-box input { width: 100%; padding: 10px 12px; border: 2px solid #e2e8f0; border-radius: 8px; font-size: 15px; margin-bottom: 12px; }
.mg-pwd-box input:focus { outline: none; border-color: #f97316; }
.mg-pwd-actions { display: flex; gap: 8px; justify-content: flex-end; margin-top: 4px; }
.mg-pwd-actions button { padding: 10px 20px; border-radius: 8px; font-size: 14px; font-weight: 700; cursor: pointer; border: none; }
.mg-pwd-cancel { background: #e2e8f0; color: #475569; }
.mg-pwd-cancel:hover { background: #cbd5e1; }
.mg-pwd-save { background: #f97316; color: #fff; }
.mg-pwd-save:hover { background: #ea580c; }
.mg-pwd-save:disabled { background: #94a3b8; cursor: not-allowed; }
.mg-pwd-error { background: #fee2e2; color: #dc2626; padding: 8px 12px; border-radius: 6px; font-size: 12px; font-weight: 600; margin-bottom: 12px; display: none; }
.mg-pwd-ok { background: #dcfce7; color: #16a34a; padding: 8px 12px; border-radius: 6px; font-size: 12px; font-weight: 600; margin-bottom: 12px; display: none; }

/* ── Hamburger mobile ────────────────────────── */
.mg-nav-hamburger {
  display: none;
  background: none;
  border: none;
  color: #fff;
  font-size: 24px;
  cursor: pointer;
  padding: 4px 8px;
  margin-left: auto;
}
.mg-nav-mobile-overlay {
  display: none;
  position: fixed;
  inset: 0;
  background: rgba(0,0,0,0.4);
  z-index: 999;
}

@media (max-width: 860px) {
  .mg-nav-links, .mg-nav-right { display: none; }
  .mg-nav-hamburger { display: block; }
  .mg-navbar.mg-mobile-open .mg-nav-links,
  .mg-navbar.mg-mobile-open .mg-nav-right {
    display: flex;
    flex-direction: column;
    position: absolute;
    top: 52px;
    left: 0;
    right: 0;
    background: ${NAV_BG};
    padding: 12px 16px;
    gap: 4px;
    box-shadow: 0 8px 24px rgba(0,0,0,0.3);
    z-index: 1001;
  }
  .mg-navbar.mg-mobile-open .mg-nav-right {
    top: auto;
    position: relative;
    padding-top: 8px;
    border-top: 1px solid rgba(255,255,255,0.1);
    margin-top: 4px;
  }
  .mg-navbar.mg-mobile-open + .mg-nav-mobile-overlay { display: block; }
  .mg-dd-menu {
    position: static;
    box-shadow: none;
    background: rgba(255,255,255,0.08);
    border-radius: 8px;
    margin-top: 4px;
  }
  .mg-dd-item { color: #ffffffcc; }
  .mg-dd-item:hover { background: rgba(255,255,255,0.1); }
  .mg-dd-active { background: rgba(255,255,255,0.15); color: #fff; }
  /* User dropdown mobile */
  .mg-user-trigger { width: 100%; justify-content: center; }
  .mg-ud-menu {
    position: static;
    box-shadow: none;
    background: rgba(255,255,255,0.08);
    border-radius: 8px;
    margin-top: 4px;
    min-width: auto;
  }
  .mg-ud-menu.mg-ud-open { display: block; }
  .mg-ud-item { color: #ffffffcc; }
  .mg-ud-item:hover { background: rgba(255,255,255,0.1); }
  .mg-ud-divider { background: rgba(255,255,255,0.1); }
  .mg-ud-logout { color: #fca5a5 !important; }
}
</style>`;
}

function toggleNavDropdown(e, ddId) {
  e.stopPropagation();
  const menu = document.getElementById('mgDd_' + ddId);
  if (!menu) return;
  // Fechar outros dropdowns abertos
  document.querySelectorAll('.mg-dd-menu.mg-dd-open').forEach(m => {
    if (m !== menu) m.classList.remove('mg-dd-open');
  });
  menu.classList.toggle('mg-dd-open');
  if (menu.classList.contains('mg-dd-open')) {
    setTimeout(() => {
      document.addEventListener('click', closeAllNavDropdowns, { once: true });
    }, 10);
  }
}

function closeAllNavDropdowns() {
  document.querySelectorAll('.mg-dd-menu.mg-dd-open').forEach(m => m.classList.remove('mg-dd-open'));
}

function toggleMobileNav() {
  const nav = document.getElementById('mgNavbar');
  if (nav) nav.classList.toggle('mg-mobile-open');
}

function closeMobileNav() {
  const nav = document.getElementById('mgNavbar');
  if (nav) nav.classList.remove('mg-mobile-open');
}

// Mantém NAV_HTML para compatibilidade
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

// ── User Dropdown ─────────────────────────────────────────────

function toggleUserDropdown(e) {
  e.stopPropagation();
  const menu = document.getElementById('mgUserMenu');
  if (!menu) return;
  menu.classList.toggle('mg-ud-open');
  if (menu.classList.contains('mg-ud-open')) {
    setTimeout(() => {
      document.addEventListener('click', closeUserDropdown, { once: true });
    }, 10);
  }
}

function closeUserDropdown() {
  const menu = document.getElementById('mgUserMenu');
  if (menu) menu.classList.remove('mg-ud-open');
}

// ── Modal Trocar Senha ────────────────────────────────────────

function openTrocarSenha() {
  closeUserDropdown();
  closeMobileNav();
  // Cria modal se não existe
  if (!document.getElementById('mgPwdOverlay')) {
    const div = document.createElement('div');
    div.innerHTML = `
    <div class="mg-pwd-overlay" id="mgPwdOverlay">
      <div class="mg-pwd-box">
        <h3>🔑 Trocar Senha</h3>
        <div class="mg-pwd-error" id="mgPwdError"></div>
        <div class="mg-pwd-ok" id="mgPwdOk"></div>
        <label>Senha Atual</label>
        <input type="password" id="mgPwdAtual" autocomplete="current-password">
        <label>Nova Senha</label>
        <input type="password" id="mgPwdNova" autocomplete="new-password">
        <label>Confirmar Nova Senha</label>
        <input type="password" id="mgPwdConfirm" autocomplete="new-password">
        <div class="mg-pwd-actions">
          <button class="mg-pwd-cancel" onclick="closeTrocarSenha()">Cancelar</button>
          <button class="mg-pwd-save" id="mgPwdSave" onclick="salvarNovaSenha()">Salvar</button>
        </div>
      </div>
    </div>`;
    document.body.appendChild(div.firstElementChild);
  }
  // Reset
  const overlay = document.getElementById('mgPwdOverlay');
  overlay.querySelector('#mgPwdAtual').value = '';
  overlay.querySelector('#mgPwdNova').value = '';
  overlay.querySelector('#mgPwdConfirm').value = '';
  overlay.querySelector('#mgPwdError').style.display = 'none';
  overlay.querySelector('#mgPwdOk').style.display = 'none';
  overlay.querySelector('#mgPwdSave').disabled = false;
  overlay.classList.add('mg-pwd-open');
  overlay.querySelector('#mgPwdAtual').focus();
}

function closeTrocarSenha() {
  const overlay = document.getElementById('mgPwdOverlay');
  if (overlay) overlay.classList.remove('mg-pwd-open');
}

async function salvarNovaSenha() {
  const errEl = document.getElementById('mgPwdError');
  const okEl = document.getElementById('mgPwdOk');
  const btn = document.getElementById('mgPwdSave');
  errEl.style.display = 'none';
  okEl.style.display = 'none';

  const senha_atual = document.getElementById('mgPwdAtual').value;
  const nova_senha = document.getElementById('mgPwdNova').value;
  const confirmar = document.getElementById('mgPwdConfirm').value;

  if (!senha_atual || !nova_senha) {
    errEl.textContent = 'Preencha todos os campos';
    errEl.style.display = 'block';
    return;
  }
  if (nova_senha.length < 4) {
    errEl.textContent = 'Nova senha deve ter pelo menos 4 caracteres';
    errEl.style.display = 'block';
    return;
  }
  if (nova_senha !== confirmar) {
    errEl.textContent = 'As senhas não conferem';
    errEl.style.display = 'block';
    return;
  }

  btn.disabled = true;
  btn.textContent = '⏳ Salvando...';

  try {
    const resp = await api('/api/auth/me/senha', {
      method: 'PATCH',
      body: JSON.stringify({ senha_atual, nova_senha }),
    });
    const data = await resp.json();

    if (!resp.ok || !data.ok) {
      errEl.textContent = data.error || 'Erro ao trocar senha';
      errEl.style.display = 'block';
      btn.disabled = false;
      btn.textContent = 'Salvar';
      return;
    }

    okEl.textContent = '✅ Senha alterada com sucesso!';
    okEl.style.display = 'block';
    btn.textContent = 'Salvar';
    btn.disabled = false;

    setTimeout(() => closeTrocarSenha(), 1500);
  } catch (e) {
    errEl.textContent = 'Erro de conexão: ' + e.message;
    errEl.style.display = 'block';
    btn.disabled = false;
    btn.textContent = 'Salvar';
  }
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
  if (getSessionToken()) return;
  if (!apiKey() && !window.location.pathname.includes('config') && !window.location.pathname.includes('login')) {
    window.location.href = 'login.html';
  }
}
