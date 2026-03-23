// MoskoGás Bina - Content Script v1.0.0
// Injeta no IzChat e mostra dados do cliente

(function() {
  'use strict';
  
  const API_BASE = 'https://api.moskogas.com.br';
  let currentPhone = null;
  let binaPanel = null;
  let lastCheckedPhone = null;
  let checkInterval = null;
  
  // Configurações salvas
  let config = {
    apiKey: '',
    enabled: true,
    position: 'right' // right ou left
  };
  
  // Carregar configurações
  chrome.storage.sync.get(['moskogas_api_key', 'bina_enabled', 'bina_position'], (result) => {
    config.apiKey = result.moskogas_api_key || '';
    config.enabled = result.bina_enabled !== false;
    config.position = result.bina_position || 'right';
    
    if (config.enabled) {
      init();
    }
  });
  
  function init() {
    console.log('🔥 MoskoGás Bina iniciada');
    createBinaPanel();
    startMonitoring();
  }
  
  function createBinaPanel() {
    // Remover painel existente se houver
    if (binaPanel) binaPanel.remove();
    
    binaPanel = document.createElement('div');
    binaPanel.id = 'moskogas-bina-panel';
    binaPanel.innerHTML = `
      <div class="bina-header">
        <span class="bina-logo">🔥</span>
        <span class="bina-title">MoskoGás Bina</span>
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
    
    // Botão minimizar
    binaPanel.querySelector('.bina-minimize').addEventListener('click', toggleMinimize);
    
    // Permitir arrastar
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
    // Verificar a cada 1 segundo
    checkInterval = setInterval(checkForPhone, 1000);
    
    // Também observar mudanças no DOM
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
    // Estratégia 1: Buscar no cabeçalho da conversa
    // O IzChat geralmente mostra o número no topo da conversa
    
    // Buscar elementos que contenham número de telefone
    const selectors = [
      // Cabeçalho da conversa
      '[class*="header"] [class*="phone"]',
      '[class*="header"] [class*="number"]',
      '[class*="contact"] [class*="phone"]',
      '[class*="chat"] [class*="header"]',
      // Título da conversa
      '[class*="title"]',
      '[class*="name"]',
      // Área de detalhes do contato
      '[class*="detail"]',
      '[class*="info"]'
    ];
    
    // Primeiro, tentar encontrar em elementos específicos
    for (const selector of selectors) {
      const elements = document.querySelectorAll(selector);
      for (const el of elements) {
        const phone = extractPhoneFromText(el.textContent);
        if (phone) return phone;
      }
    }
    
    // Estratégia 2: Buscar na URL
    const urlMatch = window.location.href.match(/(?:contact|chat|ticket)[\/=](\d{10,13})/i);
    if (urlMatch) {
      return normalizePhone(urlMatch[1]);
    }
    
    // Estratégia 3: Buscar no título da página
    const titlePhone = extractPhoneFromText(document.title);
    if (titlePhone) return titlePhone;
    
    // Estratégia 4: Buscar em data attributes
    const dataElements = document.querySelectorAll('[data-phone], [data-number], [data-contact]');
    for (const el of dataElements) {
      const phone = el.dataset.phone || el.dataset.number || el.dataset.contact;
      if (phone) {
        const normalized = normalizePhone(phone);
        if (normalized) return normalized;
      }
    }
    
    // Estratégia 5: Buscar qualquer sequência de 10-11 dígitos visível na área de cabeçalho
    const headerArea = document.querySelector('[class*="header"], [class*="top"], [class*="toolbar"]');
    if (headerArea) {
      const phone = extractPhoneFromText(headerArea.textContent);
      if (phone) return phone;
    }
    
    return null;
  }
  
  function extractPhoneFromText(text) {
    if (!text) return null;
    
    // Limpar texto
    const clean = text.replace(/\s+/g, ' ').trim();
    
    // Padrões de telefone brasileiro
    const patterns = [
      /\+?55\s*\(?(\d{2})\)?\s*(\d{4,5})[\s-]?(\d{4})/,  // +55 (67) 99999-9999
      /\(?(\d{2})\)?\s*(\d{4,5})[\s-]?(\d{4})/,          // (67) 99999-9999
      /(\d{2})(\d{4,5})(\d{4})/                           // 67999999999
    ];
    
    for (const pattern of patterns) {
      const match = clean.match(pattern);
      if (match) {
        const ddd = match[1];
        const part1 = match[2];
        const part2 = match[3];
        
        // Validar DDD (67 para MS)
        if (ddd && part1 && part2) {
          return normalizePhone(`${ddd}${part1}${part2}`);
        }
      }
    }
    
    return null;
  }
  
  function normalizePhone(phone) {
    if (!phone) return null;
    
    // Remover tudo que não for número
    let digits = phone.replace(/\D/g, '');
    
    // Adicionar 55 se não tiver
    if (digits.length === 10 || digits.length === 11) {
      digits = '55' + digits;
    }
    
    // Validar tamanho (13 dígitos: 55 + DDD + 9 dígitos)
    if (digits.length >= 12 && digits.length <= 13) {
      return digits;
    }
    
    return null;
  }
  
  async function fetchClientData(phone) {
    updatePanel('loading', { phone });
    
    try {
      // Buscar no MoskoGás
      const response = await fetch(`${API_BASE}/api/customer/search?q=${phone}&type=phone`, {
        headers: {
          'Content-Type': 'application/json',
          'X-API-KEY': config.apiKey
        }
      });
      
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }
      
      const data = await response.json();
      
      if (data.results && data.results.length > 0) {
        const client = data.results[0];
        updatePanel('found', { client, phone });
      } else {
        // Tentar buscar última compra
        const lastOrderResp = await fetch(`${API_BASE}/api/customer/last-order?phone=${phone}`, {
          headers: {
            'Content-Type': 'application/json',
            'X-API-KEY': config.apiKey
          }
        });
        
        if (lastOrderResp.ok) {
          const lastOrder = await lastOrderResp.json();
          if (lastOrder.order) {
            updatePanel('found', { 
              client: {
                name: lastOrder.order.customer_name,
                address_line: lastOrder.order.address_line,
                bairro: lastOrder.order.bairro
              },
              phone,
              lastOrder: lastOrder.order
            });
            return;
          }
        }
        
        updatePanel('not-found', { phone });
      }
    } catch (error) {
      console.error('Erro ao buscar cliente:', error);
      updatePanel('error', { phone, error: error.message });
    }
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
            <button class="bina-btn bina-btn-primary" onclick="window.open('https://moskogas-app.pages.dev/pedido.html?phone=${data.phone}', '_blank')">
              🛒 Novo Pedido
            </button>
            <button class="bina-btn bina-btn-secondary" onclick="window.open('https://moskogas-app.pages.dev/consulta-pedidos.html?phone=${data.phone}', '_blank')">
              📋 Histórico
            </button>
          </div>
        `;
        
        // Highlight do painel
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
            <button class="bina-btn bina-btn-primary" onclick="window.open('https://moskogas-app.pages.dev/pedido.html?phone=${data.phone}&new=1', '_blank')">
              ➕ Cadastrar e Fazer Pedido
            </button>
          </div>
        `;
        break;
        
      case 'error':
        content.innerHTML = `
          <div class="bina-status error">
            <span class="bina-icon">⚠️</span>
            <span>Erro ao buscar</span>
            <div class="bina-error-msg">${data.error}</div>
          </div>
          <div class="bina-actions">
            <button class="bina-btn bina-btn-secondary" onclick="location.reload()">
              🔄 Tentar novamente
            </button>
          </div>
        `;
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
  
  // Escutar mensagens do popup
  chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'getStatus') {
      sendResponse({
        currentPhone,
        enabled: config.enabled
      });
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
  
})();
