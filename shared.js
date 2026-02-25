// shared.js — Utilitários compartilhados MoskoGás v1.12.3
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
    <img src="data:image/png;base64,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" alt="MoskoGás">
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
