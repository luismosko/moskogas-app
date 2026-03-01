// shared.js — Utilitários compartilhados MoskoGás v1.15.0
// v1.17.0
// v1.17.0: Nova navbar — menu ADM (Contratos/Estoque/Vales) + menu Marketing (GMB/Social/Ads)
// v1.14.0: 📦 Estoque adicionado à navbar
// v1.13.0: Dropdown Financeiro (Pagamentos + Empenhos GOV) na navbar
// v1.11.0: Contratos adicionado à navbar
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
    novo: ['#dc2626', 'NOVO'],
    encaminhado: ['#d97706', 'ENCAMINHADO'],
    whatsapp_enviado: ['#16a34a', 'WHATS'],
    entregue: ['#2563eb', 'ENTREGUE'],
    cancelado: ['#6b7280', 'CANCELADO'],
  };
  const [color, label] = map[status] || ['#888', status];
  return `<span style="background:${color};color:#fff;padding:2px 7px;border-radius:10px;font-size:10px;font-weight:700;white-space:nowrap">${label}</span>`;
}

function payBadge(status) {
  const map = {
    pendente: ['#dc2626', 'PENDENTE'],
    recebido: ['#16a34a', 'RECEBIDO'],
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
  const bgs = { success: '#16a34a', error: '#dc2626', warning: '#d97706', info: '#2563eb' };
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
const NAV_BG = '#0B2A6F';
const NAV_HOVER = '#104BB8';
const NAV_TEXT = '#ffffffcc';
const NAV_ACTIVE = '#ffffff';

const NAV_ITEMS = [
  { href: 'pedido.html', icon: '➕', label: 'Novo Pedido', roles: ['admin', 'atendente'] },
  { href: 'gestao.html', icon: '📋', label: 'Gestão', roles: ['admin', 'atendente'] },
];

// Dropdowns — cada um com ID único para abrir/fechar independente
const NAV_DROPDOWNS = [
  {
    id: 'adm', icon: '🏢', label: 'ADM', roles: ['admin', 'atendente'],
    children: [
      { href: 'contratos.html', icon: '📄', label: 'Contratos' },
      { href: 'estoque.html', icon: '📦', label: 'Estoque' },
      { href: 'vales.html', icon: '🎟️', label: 'Vale Gás' },
    ]
  },
  {
    id: 'financeiro', icon: '💰', label: 'Financeiro', roles: ['admin', 'atendente'],
    children: [
      { href: 'pagamentos.html', icon: '💳', label: 'Pagamentos Pendentes' },
      { href: 'empenhos.html', icon: '🏛️', label: 'Empenhos GOV' },
    ]
  },
  {
    id: 'marketing', icon: '🎯', label: 'Marketing', roles: ['admin', 'atendente'],
    children: [
      { href: 'marketing-gmb.html', icon: '📍', label: 'Google Meu Negócio' },
      { href: 'marketing-social.html', icon: '📱', label: 'Facebook & Instagram' },
      { href: 'marketing-ads.html', icon: '📢', label: 'Google Ads' },
    ]
  },
  {
    id: 'relatorio', icon: '📊', label: 'Relatório', roles: ['admin', 'atendente'],
    children: [
      { href: 'relatorio.html', icon: '📊', label: 'Relatório do Dia' },
      { href: 'entregador.html', icon: '🚚', label: 'Painel Entregador' },
      { href: 'auditoria.html', icon: '🔍', label: 'Auditoria' },
      { href: 'consulta-pedidos.html', icon: '🔎', label: 'Consulta Pedidos' },
    ]
  },
  {
    id: 'config', icon: '⚙️', label: 'Config', roles: ['admin', 'atendente'],
    children: [
      { href: 'config.html', icon: '⚙️', label: 'Configurações' },
      { href: 'usuarios.html', icon: '👥', label: 'Usuários' },
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
    }).catch(() => { });
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
  } catch (e) {
    return await ensureBling();
  }
}

function _sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
