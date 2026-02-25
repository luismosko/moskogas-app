// shared.js — Utilitários compartilhados MoskoGás v1.12.2
// v1.11.0: Bling Auto-Recovery — ensureBling() + apiBling() + modal reconexão
// v1.10.0: Contratos adicionado à navbar
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
    novo:             ['#dc2626', 'NOVO'],
    encaminhado:      ['#d97706', 'ENCAMINHADO'],
    whatsapp_enviado: ['#16a34a', 'WHATS'],
    entregue:         ['#2563eb', 'ENTREGUE'],
    cancelado:        ['#6b7280', 'CANCELADO'],
  };
  const [color, label] = map[status] || ['#888', status];
  return `<span style="background:${color};color:#fff;padding:2px 7px;border-radius:10px;font-size:10px;font-weight:700;white-space:nowrap">${label}</span>`;
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
  { href: 'pagamentos.html', icon: '💰', label: 'Financeiro',   roles: ['admin', 'atendente'] },
  { href: 'contratos.html',  icon: '📄', label: 'Contratos',    roles: ['admin', 'atendente'] },
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
    <img src="data:image/jpeg;base64,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" alt="MoskoGás">
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

// ══════════════════════════════════════════════════════════════
// BLING AUTO-RECOVERY v1.11.0
// ensureBling()  — verifica e reconecta antes de ações
// apiBling(name, fn) — executa ação com auto-retry em caso de 401
// ══════════════════════════════════════════════════════════════

let _blingModalEl = null;
let _blingOAuthWin = null;

function _createBlingModal() {
  if (_blingModalEl) return _blingModalEl;
  const div = document.createElement('div');
  div.id = 'bling-recovery-overlay';
  div.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.6);display:none;align-items:center;justify-content:center;z-index:99999;font-family:system-ui,-apple-system,sans-serif';
  div.innerHTML = `
    <div id="bling-recovery-box" style="background:#fff;border-radius:16px;padding:32px;max-width:420px;width:90%;box-shadow:0 20px 60px rgba(0,0,0,0.3);text-align:center">
      <div id="br-icon" style="font-size:48px;margin-bottom:12px">🔗</div>
      <div id="br-title" style="font-size:18px;font-weight:700;color:#1e293b;margin-bottom:8px">Verificando Bling...</div>
      <div id="br-msg" style="font-size:14px;color:#64748b;margin-bottom:20px;line-height:1.5">Aguarde um momento</div>
      <div id="br-steps" style="text-align:left;margin:0 auto 20px;max-width:320px;font-size:13px"></div>
      <div id="br-actions" style="display:none;gap:10px;justify-content:center"></div>
    </div>`;
  document.body.appendChild(div);
  _blingModalEl = div;
  return div;
}

function _showBlingModal() {
  const m = _createBlingModal();
  m.style.display = 'flex';
}

function _hideBlingModal() {
  if (_blingModalEl) _blingModalEl.style.display = 'none';
}

function _blingStep(icon, title, msg, steps, actions) {
  _showBlingModal();
  const box = _blingModalEl.querySelector('#bling-recovery-box');
  box.querySelector('#br-icon').textContent = icon;
  box.querySelector('#br-title').textContent = title;
  box.querySelector('#br-msg').innerHTML = msg;
  const stepsEl = box.querySelector('#br-steps');
  stepsEl.innerHTML = (steps || []).map(s =>
    `<div style="padding:6px 0;display:flex;align-items:center;gap:8px;${s.done ? 'color:#16a34a' : s.fail ? 'color:#dc2626' : s.active ? 'color:#1e293b;font-weight:600' : 'color:#cbd5e1'}">
      <span style="font-size:16px">${s.done ? '✅' : s.fail ? '❌' : s.active ? '⏳' : '⬜'}</span>
      <span>${s.text}</span>
    </div>`
  ).join('');
  const actEl = box.querySelector('#br-actions');
  if (actions && actions.length) {
    actEl.style.display = 'flex';
    actEl.innerHTML = actions.map(a =>
      `<button onclick="${a.onclick}" style="padding:10px 24px;border-radius:10px;font-size:14px;font-weight:700;cursor:pointer;border:${a.primary ? 'none' : '1px solid #e2e8f0'};background:${a.primary ? '#2563eb' : '#fff'};color:${a.primary ? '#fff' : '#64748b'}">${a.label}</button>`
    ).join('');
  } else {
    actEl.style.display = 'none';
  }
}

/**
 * ensureBling() — Verifica conexão Bling e reconecta se necessário
 * Retorna true se conectado, false se falhou
 * Mostra modal com progresso e tenta:
 * 1. keep-alive (refresh automático)
 * 2. OAuth popup (se refresh falhar)
 */
async function ensureBling() {
  // Step 1: Quick check
  _blingStep('🔗', 'Verificando Bling...', 'Testando conexão com o ERP', [
    { text: 'Verificar token', active: true },
    { text: 'Reconectar se necessário' },
    { text: 'Pronto para ação' },
  ]);

  try {
    const token = getSessionToken();
    const headers = token ? { Authorization: 'Bearer ' + token } : { 'X-API-KEY': apiKey() || '' };
    const resp = await fetch(API_BASE + '/api/bling/keep-alive', { headers });
    const data = await resp.json();

    if (data.ok && data.connected) {
      const refreshMsg = data.refreshed ? ' (token renovado!)' : '';
      _blingStep('✅', 'Bling Conectado!', `Token válido — ${data.minutesLeft}min restantes${refreshMsg}`, [
        { text: 'Verificar token', done: true },
        { text: data.refreshed ? 'Token renovado automaticamente' : 'Conexão OK', done: true },
        { text: 'Pronto para ação', done: true },
      ]);
      await _sleep(800);
      _hideBlingModal();
      return true;
    }

    // Step 2: Refresh failed — need OAuth
    console.warn('[ensureBling] Keep-alive falhou:', data.error);
    return await _blingOAuthFlow();

  } catch (e) {
    console.error('[ensureBling] Erro:', e);
    return await _blingOAuthFlow();
  }
}

async function _blingOAuthFlow() {
  return new Promise((resolve) => {
    _blingStep('🔑', 'Reconexão Necessária', 'O token do Bling expirou.<br>Abrindo janela de autorização...', [
      { text: 'Verificar token', done: true },
      { text: 'Refresh automático falhou', fail: true },
      { text: 'Autorização manual necessária', active: true },
    ], [
      { label: '🔑 Conectar Bling', primary: true, onclick: '_openBlingOAuth()' },
      { label: 'Cancelar', onclick: '_cancelBlingRecovery()' },
    ]);

    // Auto-open after brief delay
    setTimeout(() => _openBlingOAuth(), 600);

    // Listen for OAuth callback
    const handler = async (event) => {
      if (event.data?.type === 'bling_connected') {
        window.removeEventListener('message', handler);
        if (_blingOAuthWin && !_blingOAuthWin.closed) _blingOAuthWin.close();
        _blingOAuthWin = null;

        _blingStep('✅', 'Bling Reconectado!', 'Autorização concluída com sucesso!', [
          { text: 'Verificar token', done: true },
          { text: 'Refresh automático falhou', fail: true },
          { text: 'Reautorizado via OAuth', done: true },
          { text: 'Pronto para ação', done: true },
        ]);
        await _sleep(1000);
        _hideBlingModal();
        resolve(true);
      }
    };
    window.addEventListener('message', handler);

    // Store resolve for cancel button
    window._blingRecoveryResolve = (val) => {
      window.removeEventListener('message', handler);
      resolve(val);
    };
  });
}

function _openBlingOAuth() {
  const w = 600, h = 700;
  const left = (screen.width - w) / 2, top = (screen.height - h) / 2;
  _blingOAuthWin = window.open(
    API_BASE + '/bling/oauth/start',
    'bling_oauth',
    `width=${w},height=${h},left=${left},top=${top},toolbar=no,menubar=no`
  );
  _blingStep('🔑', 'Aguardando Autorização', 'Faça login no Bling na janela que abriu.<br>Após autorizar, esta tela fechará automaticamente.', [
    { text: 'Verificar token', done: true },
    { text: 'Refresh automático falhou', fail: true },
    { text: 'Aguardando autorização...', active: true },
  ], [
    { label: '🔄 Reabrir Janela', primary: true, onclick: '_openBlingOAuth()' },
    { label: 'Cancelar', onclick: '_cancelBlingRecovery()' },
  ]);
}

function _cancelBlingRecovery() {
  if (_blingOAuthWin && !_blingOAuthWin.closed) _blingOAuthWin.close();
  _blingOAuthWin = null;
  _hideBlingModal();
  if (window._blingRecoveryResolve) {
    window._blingRecoveryResolve(false);
    window._blingRecoveryResolve = null;
  }
}

/**
 * apiBling(actionName, apiCallFn) — Executa ação Bling com auto-recovery
 *
 * Uso:
 *   const result = await apiBling('Gerando Venda', async () => {
 *     return await api('/api/pagamentos/criar-vendas-bling', { method: 'POST', body: ... });
 *   });
 *
 * Se o Bling retornar 401, automaticamente:
 * 1. Mostra modal de reconexão
 * 2. Tenta refresh / OAuth
 * 3. Retenta a ação original
 *
 * Retorna: { ok, data } ou { ok: false, error, canceled }
 */
function _isBlingAuthError(obj) {
  if (!obj) return false;
  const s = typeof obj === 'string' ? obj : JSON.stringify(obj);
  return s.includes('bling_reauth') || s.includes('invalid_token') || s.includes('Token Bling expirado');
}

async function apiBling(actionName, apiCallFn) {
  // Attempt 1: Try direct
  try {
    const result = await apiCallFn();
    // Check for Bling auth errors in response (could be nested in resultados)
    if (_isBlingAuthError(result?.error) || _isBlingAuthError(result?.resultados)) {
      throw new Error('bling_reauth_required');
    }
    return { ok: true, data: result };
  } catch (e) {
    if (!_isBlingAuthError(e.message)) {
      return { ok: false, error: e.message };
    }
  }

  // Bling auth failed — try recovery
  console.warn('[apiBling] Bling 401 detectado, iniciando recovery...');
  const recovered = await ensureBling();
  if (!recovered) {
    return { ok: false, error: 'Conexão Bling não restaurada', canceled: true };
  }

  // Attempt 2: Retry after recovery
  _blingStep('🔄', 'Retentando...', `${actionName}`, [
    { text: 'Bling reconectado', done: true },
    { text: actionName + '...', active: true },
  ]);

  try {
    const result = await apiCallFn();
    if (_isBlingAuthError(result?.error) || _isBlingAuthError(result?.resultados)) {
      _hideBlingModal();
      return { ok: false, error: 'Bling ainda não conectado após retry' };
    }
    _blingStep('✅', 'Sucesso!', `${actionName} concluído!`, [
      { text: 'Bling reconectado', done: true },
      { text: actionName, done: true },
    ]);
    await _sleep(800);
    _hideBlingModal();
    return { ok: true, data: result, recovered: true };
  } catch (e) {
    _hideBlingModal();
    return { ok: false, error: e.message };
  }
}

/**
 * checkBlingBeforeAction() — Verificação rápida antes de ação
 * Diferente do ensureBling() completo, faz check silencioso e
 * só mostra modal se precisar reconectar.
 * Retorna true/false
 */
async function checkBlingBeforeAction() {
  try {
    const token = getSessionToken();
    const headers = token ? { Authorization: 'Bearer ' + token } : {};
    const resp = await fetch(API_BASE + '/api/bling/status', { headers });
    const data = await resp.json();
    if (data.ok && data.connected && data.minutesLeft > 2) return true;
    // Needs recovery
    return await ensureBling();
  } catch(e) {
    return await ensureBling();
  }
}

function _sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
