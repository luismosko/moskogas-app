// IZGLP — Bina Virtual Content Script v2.0.0
// Injeta no IzChat e mostra dados do cliente

(function() {
  'use strict';
  
  let currentPhone = null;
  let binaPanel = null;
  let lastCheckedPhone = null;
  let config = { enabled: true };
  
  const log = (msg) => console.log(`[IZGLP-Bina] ${msg}`);
  
  function isContextValid() {
    try { return !!(typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.id); }
    catch (e) { return false; }
  }
  
  // Carregar configurações
  if (isContextValid()) {
    chrome.storage.sync.get(['bina_enabled'], (result) => {
      config.enabled = result.bina_enabled !== false;
      if (config.enabled) init();
    });
  }
  
  function init() {
    log('🔥 IZGLP Bina iniciada');
    createBinaPanel();
    startMonitoring();
  }
  
  function createBinaPanel() {
    if (binaPanel) binaPanel.remove();
    
    binaPanel = document.createElement('div');
    binaPanel.id = 'izglp-bina-panel';
    binaPanel.innerHTML = `
      <div class="bina-header">
        <span class="bina-logo">🔥</span>
        <span class="bina-title">IZGLP Bina</span>
        <button class="bina-minimize" title="Minimizar">−</button>
      </div>
      <div class="bina-content">
        <div class="bina-status">
          <span class="bina-icon">👀</span>
          <span>Aguardando conversa...</span>
        </div>
      </div>
    `;
    
    document.body.appendChild(binaPanel);
    binaPanel.querySelector('.bina-minimize').addEventListener('click', toggleMinimize);
    makeDraggable(binaPanel);
  }
  
  function toggleMinimize() {
    binaPanel.classList.toggle('minimized');
  }
  
  function makeDraggable(el) {
    const header = el.querySelector('.bina-header');
    let isDragging = false;
    let offsetX, offsetY;
    
    header.addEventListener('mousedown', (e) => {
      if (e.target.classList.contains('bina-minimize')) return;
      isDragging = true;
      offsetX = e.clientX - el.offsetLeft;
      offsetY = e.clientY - el.offsetTop;
      el.style.cursor = 'grabbing';
    });
    
    document.addEventListener('mousemove', (e) => {
      if (!isDragging) return;
      el.style.left = (e.clientX - offsetX) + 'px';
      el.style.top = (e.clientY - offsetY) + 'px';
      el.style.right = 'auto';
    });
    
    document.addEventListener('mouseup', () => {
      isDragging = false;
      el.style.cursor = '';
    });
  }
  
  function startMonitoring() {
    setInterval(checkForPhone, 1000);
    
    const observer = new MutationObserver(() => {
      setTimeout(checkForPhone, 500);
    });
    
    observer.observe(document.body, {
      childList: true,
      subtree: true
    });
  }
  
  function checkForPhone() {
    const phone = extractPhoneFromPage();
    
    if (phone && phone !== lastCheckedPhone) {
      lastCheckedPhone = phone;
      currentPhone = phone;
      fetchClientData(phone);
    }
  }
  
  function extractPhoneFromPage() {
    // Estratégia 1: Buscar em elementos específicos
    const selectors = [
      '[class*="header"] [class*="phone"]',
      '[class*="header"] [class*="number"]',
      '[class*="contact"] [class*="phone"]',
      '[class*="chat"] [class*="header"]',
      '[class*="title"]',
      '[class*="name"]',
      '[class*="detail"]',
      '[class*="info"]'
    ];
    
    for (const selector of selectors) {
      const elements = document.querySelectorAll(selector);
      for (const el of elements) {
        const phone = extractPhoneFromText(el.textContent);
        if (phone) return phone;
      }
    }
    
    // Estratégia 2: Buscar na URL
    const urlMatch = window.location.href.match(/(?:contact|chat|ticket)[\/=](\d{10,13})/i);
    if (urlMatch) return normalizePhone(urlMatch[1]);
    
    // Estratégia 3: Título da página
    const titlePhone = extractPhoneFromText(document.title);
    if (titlePhone) return titlePhone;
    
    // Estratégia 4: Data attributes
    const dataElements = document.querySelectorAll('[data-phone], [data-number], [data-contact]');
    for (const el of dataElements) {
      const phone = el.dataset.phone || el.dataset.number || el.dataset.contact;
      if (phone) {
        const normalized = normalizePhone(phone);
        if (normalized) return normalized;
      }
    }
    
    // Estratégia 5: Cabeçalho
    const headerArea = document.querySelector('[class*="header"], [class*="top"], [class*="toolbar"]');
    if (headerArea) {
      const phone = extractPhoneFromText(headerArea.textContent);
      if (phone) return phone;
    }
    
    return null;
  }
  
  function extractPhoneFromText(text) {
    if (!text) return null;
    
    const clean = text.replace(/\s+/g, ' ').trim();
    
    const patterns = [
      /\+?55\s*\(?(\d{2})\)?\s*(\d{4,5})[\s-]?(\d{4})/,
      /\(?(\d{2})\)?\s*(\d{4,5})[\s-]?(\d{4})/,
      /(\d{2})(\d{4,5})(\d{4})/
    ];
    
    for (const pattern of patterns) {
      const match = clean.match(pattern);
      if (match) {
        const ddd = match[1];
        const part1 = match[2];
        const part2 = match[3];
        
        if (ddd && part1 && part2) {
          return normalizePhone(`${ddd}${part1}${part2}`);
        }
      }
    }
    
    return null;
  }
  
  function normalizePhone(phone) {
    if (!phone) return null;
    
    let digits = phone.replace(/\D/g, '');
    
    if (digits.length === 10 || digits.length === 11) {
      digits = '55' + digits;
    }
    
    if (digits.length >= 12 && digits.length <= 13) {
      return digits;
    }
    
    return null;
  }
  
  function fetchClientData(phone) {
    updatePanel('loading', { phone });
    
    if (!isContextValid()) {
      updatePanel('error', { phone, error: 'Extensão desconectada' });
      return;
    }
    
    chrome.runtime.sendMessage({ type: 'BINA_SEARCH', phone }, (response) => {
      if (chrome.runtime.lastError) {
        updatePanel('error', { phone, error: chrome.runtime.lastError.message });
        return;
      }
      
      if (response && response.ok) {
        if (response.found) {
          updatePanel('found', { 
            client: response.client, 
            phone, 
            lastOrder: response.lastOrder 
          });
        } else {
          updatePanel('not-found', { phone });
        }
      } else {
        updatePanel('error', { phone, error: 'Falha na busca' });
      }
    });
  }
  
  function updatePanel(status, data = {}) {
    const content = binaPanel.querySelector('.bina-content');
    
    switch (status) {
      case 'loading':
        content.innerHTML = `
          <div class="bina-status loading">
            <span class="bina-spinner">⏳</span>
            <span>Buscando ${formatPhone(data.phone)}...</span>
          </div>
        `;
        break;
        
      case 'found':
        const c = data.client;
        content.innerHTML = `
          <div class="bina-client">
            <div class="bina-client-name">
              <span class="bina-icon">👤</span>
              <strong>${c.name || 'Sem nome'}</strong>
            </div>
            <div class="bina-client-phone">
              <span class="bina-icon">📱</span>
              ${formatPhone(data.phone)}
            </div>
            ${c.address_line ? `
              <div class="bina-client-address">
                <span class="bina-icon">📍</span>
                ${c.address_line}
              </div>
            ` : ''}
            ${c.bairro ? `
              <div class="bina-client-bairro">
                <span class="bina-icon">🏘️</span>
                ${c.bairro}
              </div>
            ` : ''}
            ${c.complemento ? `
              <div class="bina-client-complemento">
                <span class="bina-icon">🏠</span>
                ${c.complemento}
              </div>
            ` : ''}
            ${c.referencia ? `
              <div class="bina-client-referencia">
                <span class="bina-icon">📌</span>
                ${c.referencia}
              </div>
            ` : ''}
            ${c.ultima_compra_glp ? `
              <div class="bina-client-last">
                <span class="bina-icon">📦</span>
                Última: ${c.ultima_compra_glp}
              </div>
            ` : ''}
            ${data.lastOrder ? `
              <div class="bina-client-last">
                <span class="bina-icon">📦</span>
                Último pedido: ${formatDate(data.lastOrder.created_at)}
              </div>
            ` : ''}
          </div>
          <div class="bina-actions">
            <button class="bina-btn bina-btn-primary" id="btn-novo-pedido">
              🛒 Novo Pedido
            </button>
            <button class="bina-btn bina-btn-secondary" id="btn-historico">
              📋 Histórico
            </button>
          </div>
        `;
        
        // Event listeners
        content.querySelector('#btn-novo-pedido').addEventListener('click', () => {
          chrome.runtime.sendMessage({ type: 'OPEN_IZGLP', page: 'pedido.html', phone: data.phone });
        });
        content.querySelector('#btn-historico').addEventListener('click', () => {
          chrome.runtime.sendMessage({ type: 'OPEN_IZGLP', page: 'consulta-pedidos.html', phone: data.phone });
        });
        
        binaPanel.classList.add('found');
        setTimeout(() => binaPanel.classList.remove('found'), 2000);
        break;
        
      case 'not-found':
        content.innerHTML = `
          <div class="bina-status not-found">
            <span class="bina-icon">❓</span>
            <span>Cliente não cadastrado</span>
            <div class="bina-phone-display">${formatPhone(data.phone)}</div>
          </div>
          <div class="bina-actions">
            <button class="bina-btn bina-btn-primary" id="btn-cadastrar">
              ➕ Cadastrar e Fazer Pedido
            </button>
          </div>
        `;
        
        content.querySelector('#btn-cadastrar').addEventListener('click', () => {
          chrome.runtime.sendMessage({ type: 'OPEN_IZGLP', page: 'pedido.html', phone: data.phone });
        });
        break;
        
      case 'error':
        content.innerHTML = `
          <div class="bina-status error">
            <span class="bina-icon">⚠️</span>
            <span>Erro ao buscar</span>
            <div class="bina-error-msg">${data.error}</div>
          </div>
          <div class="bina-actions">
            <button class="bina-btn bina-btn-secondary" id="btn-retry">
              🔄 Tentar novamente
            </button>
          </div>
        `;
        
        content.querySelector('#btn-retry').addEventListener('click', () => {
          lastCheckedPhone = null;
          checkForPhone();
        });
        break;
        
      default:
        content.innerHTML = `
          <div class="bina-status">
            <span class="bina-icon">👀</span>
            <span>Aguardando conversa...</span>
          </div>
        `;
    }
  }
  
  function formatPhone(phone) {
    if (!phone) return '';
    const digits = phone.replace(/\D/g, '');
    if (digits.length === 13) {
      return `+${digits.slice(0,2)} (${digits.slice(2,4)}) ${digits.slice(4,9)}-${digits.slice(9)}`;
    }
    if (digits.length === 12) {
      return `+${digits.slice(0,2)} (${digits.slice(2,4)}) ${digits.slice(4,8)}-${digits.slice(8)}`;
    }
    return phone;
  }
  
  function formatDate(timestamp) {
    if (!timestamp) return '';
    const date = new Date(timestamp * 1000);
    return date.toLocaleDateString('pt-BR');
  }
  
  // Escutar mensagens
  if (isContextValid()) {
    chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
      if (request.action === 'getStatus') {
        sendResponse({ currentPhone, enabled: config.enabled });
      } else if (request.action === 'setEnabled') {
        config.enabled = request.enabled;
        if (config.enabled) {
          if (!binaPanel) createBinaPanel();
          binaPanel.style.display = '';
        } else {
          if (binaPanel) binaPanel.style.display = 'none';
        }
        sendResponse({ ok: true });
      } else if (request.action === 'refresh') {
        lastCheckedPhone = null;
        checkForPhone();
        sendResponse({ ok: true });
      }
      return true;
    });
  }
  
  log('🟢 IZGLP Bina v2.0.0 ativa');
  
})();
