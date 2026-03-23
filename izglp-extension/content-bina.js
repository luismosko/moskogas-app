// IZGLP — Bina Virtual Content Script v2.1.0
// Injeta botão "Abrir Pedido" DENTRO da interface do IzChat

(function() {
  'use strict';
  
  const log = (msg) => console.log(`[IZGLP-Bina] ${msg}`);
  const BUTTON_ID = 'izglp-abrir-pedido-btn';
  const PANEL_ID = 'izglp-bina-info';
  
  let lastInjectedPhone = null;
  let observer = null;
  
  function isContextValid() {
    try { return !!(typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.id); }
    catch (e) { return false; }
  }
  
  function init() {
    log('🔥 IZGLP Bina v2.1.0 iniciada — Modo injeção no IzChat');
    injectStyles();
    startMonitoring();
  }
  
  // ══════════════════════════════════════════════════════════════════════════════
  // ESTILOS GLOBAIS
  // ══════════════════════════════════════════════════════════════════════════════
  
  function injectStyles() {
    const style = document.createElement('style');
    style.id = 'izglp-bina-styles';
    style.textContent = `
      #${PANEL_ID} {
        background: linear-gradient(135deg, #059669 0%, #10b981 100%);
        border-radius: 12px;
        padding: 16px;
        margin: 12px 16px;
        box-shadow: 0 4px 12px rgba(0,0,0,0.15);
      }
      #${PANEL_ID} .izglp-header {
        display: flex;
        align-items: center;
        gap: 8px;
        margin-bottom: 12px;
        color: white;
        font-weight: bold;
        font-size: 16px;
      }
      #${PANEL_ID} .izglp-logo {
        font-size: 24px;
      }
      #${PANEL_ID} .izglp-phone {
        background: rgba(255,255,255,0.2);
        color: white;
        padding: 8px 12px;
        border-radius: 8px;
        font-size: 14px;
        margin-bottom: 12px;
        font-family: monospace;
      }
      #${BUTTON_ID} {
        width: 100%;
        padding: 14px 20px;
        background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%);
        color: white;
        border: none;
        border-radius: 10px;
        font-size: 16px;
        font-weight: bold;
        cursor: pointer;
        display: flex;
        align-items: center;
        justify-content: center;
        gap: 8px;
        transition: all 0.2s;
        box-shadow: 0 4px 12px rgba(245, 158, 11, 0.4);
        margin-bottom: 8px;
      }
      #${BUTTON_ID}:hover {
        transform: translateY(-2px);
        box-shadow: 0 6px 16px rgba(245, 158, 11, 0.5);
      }
      #izglp-btn-historico {
        width: 100%;
        padding: 10px 16px;
        background: rgba(255,255,255,0.2);
        color: white;
        border: 2px solid rgba(255,255,255,0.4);
        border-radius: 8px;
        font-size: 14px;
        font-weight: 600;
        cursor: pointer;
        display: flex;
        align-items: center;
        justify-content: center;
        gap: 6px;
        transition: all 0.2s;
      }
      #izglp-btn-historico:hover {
        background: rgba(255,255,255,0.3);
      }
      
      /* Painel flutuante (fallback) */
      #${PANEL_ID}.floating {
        position: fixed;
        bottom: 20px;
        right: 20px;
        width: 280px;
        z-index: 999999;
      }
    `;
    
    // Remover estilo antigo se existir
    const existing = document.getElementById('izglp-bina-styles');
    if (existing) existing.remove();
    
    document.head.appendChild(style);
  }
  
  // ══════════════════════════════════════════════════════════════════════════════
  // MONITORAMENTO DO DOM
  // ══════════════════════════════════════════════════════════════════════════════
  
  function startMonitoring() {
    // Verificar periodicamente
    setInterval(checkAndInject, 1000);
    
    // Observer para mudanças no DOM (quando abre/fecha painel de contato)
    observer = new MutationObserver(() => {
      setTimeout(checkAndInject, 300);
    });
    
    observer.observe(document.body, {
      childList: true,
      subtree: true
    });
    
    // Verificar imediatamente
    checkAndInject();
  }
  
  function checkAndInject() {
    // Procurar o telefone no painel de dados do contato
    const phoneData = findPhoneInContactPanel();
    
    if (phoneData.phone || phoneData.targetContainer) {
      injectButton(phoneData);
    }
  }
  
  // ══════════════════════════════════════════════════════════════════════════════
  // ENCONTRAR TELEFONE NO PAINEL DE CONTATO
  // ══════════════════════════════════════════════════════════════════════════════
  
  function findPhoneInContactPanel() {
    let phone = null;
    let name = null;
    let targetContainer = null;
    
    // Buscar em todos os elementos de texto
    const walker = document.createTreeWalker(
      document.body,
      NodeFilter.SHOW_TEXT,
      null,
      false
    );
    
    while (walker.nextNode()) {
      const text = walker.currentNode.textContent || '';
      
      // Buscar padrão +55 (XX) XXXXX-XXXX
      if (text.includes('+55') || text.match(/\(\d{2}\)\s*\d{4,5}/)) {
        const extracted = extractPhone(text);
        if (extracted) {
          phone = extracted;
          break;
        }
      }
    }
    
    // Encontrar nome do contato no header
    const headerName = document.querySelector('[class*="contactName"], [class*="ContactName"], [class*="ticketName"], [class*="userName"]');
    if (headerName) {
      name = headerName.textContent?.trim();
    }
    
    // Encontrar container "OUTRAS INFORMAÇÕES"
    const allElements = document.querySelectorAll('*');
    for (const el of allElements) {
      const text = (el.textContent || '').trim().toUpperCase();
      
      // Encontrar exatamente o header "OUTRAS INFORMAÇÕES"
      if (el.childNodes.length === 1 && el.childNodes[0].nodeType === Node.TEXT_NODE) {
        if (text === 'OUTRAS INFORMAÇÕES' || text === 'OUTRAS INFORMACOES') {
          targetContainer = el;
          log('📍 Encontrado: OUTRAS INFORMAÇÕES');
          break;
        }
      }
    }
    
    // Se não encontrou, buscar por classe
    if (!targetContainer) {
      targetContainer = document.querySelector('[class*="otherInfo"], [class*="OtherInfo"], [class*="extraInfo"], [class*="additionalInfo"]');
    }
    
    // Verificar se o painel de dados do contato está aberto
    const contactPanel = document.querySelector('[class*="ContactDrawer"], [class*="contactDrawer"], [class*="drawer"]:not([class*="navigation"])');
    if (!targetContainer && contactPanel) {
      // Encontrar qualquer container dentro do painel de contato
      const sections = contactPanel.querySelectorAll('div');
      for (const section of sections) {
        if (section.querySelector('[class*="Salvar"], button') || section.textContent?.includes('OUTRAS')) {
          targetContainer = section.parentElement;
          break;
        }
      }
    }
    
    return { phone, name, targetContainer };
  }
  
  function extractPhone(text) {
    if (!text) return null;
    
    // Padrões de telefone brasileiro
    const patterns = [
      /\+?55\s*\(?(\d{2})\)?\s*(\d{4,5})[\s-]?(\d{4})/,
      /\(?(\d{2})\)?\s*9?\s*(\d{4})[\s-]?(\d{4})/
    ];
    
    for (const pattern of patterns) {
      const match = text.match(pattern);
      if (match) {
        let ddd = match[1];
        let part1 = match[2];
        let part2 = match[3];
        
        // Garantir que DDD tem 2 dígitos
        if (ddd && ddd.length === 2 && part1 && part2) {
          // Adicionar 9 se necessário (celular)
          if (part1.length === 4) {
            part1 = '9' + part1;
          }
          return `55${ddd}${part1}${part2}`;
        }
      }
    }
    
    return null;
  }
  
  // ══════════════════════════════════════════════════════════════════════════════
  // INJETAR BOTÃO NO IZCHAT
  // ══════════════════════════════════════════════════════════════════════════════
  
  function injectButton(data) {
    const { phone, name, targetContainer } = data;
    
    // Verificar se já existe
    const existingPanel = document.getElementById(PANEL_ID);
    
    // Se já existe e é o mesmo telefone, não fazer nada
    if (existingPanel && lastInjectedPhone === phone) {
      return;
    }
    
    // Remover painel antigo
    if (existingPanel) {
      existingPanel.remove();
    }
    
    lastInjectedPhone = phone;
    
    // Criar o painel IZGLP
    const panel = document.createElement('div');
    panel.id = PANEL_ID;
    panel.innerHTML = `
      <div class="izglp-header">
        <span class="izglp-logo">🔥</span>
        <span class="izglp-title">IZGLP</span>
      </div>
      ${phone ? `
        <div class="izglp-phone">
          📱 ${formatPhone(phone)}
        </div>
      ` : '<div class="izglp-phone">📱 Telefone não detectado</div>'}
      <button id="${BUTTON_ID}">
        🛒 Abrir Pedido
      </button>
      <button id="izglp-btn-historico">
        📋 Histórico
      </button>
    `;
    
    // Tentar injetar no local correto
    let injected = false;
    
    // 1. Injetar após "OUTRAS INFORMAÇÕES"
    if (targetContainer && !injected) {
      try {
        const parent = targetContainer.parentElement;
        if (parent) {
          // Inserir ANTES de "OUTRAS INFORMAÇÕES" para ficar mais visível
          parent.insertBefore(panel, targetContainer);
          injected = true;
          log('✅ Botão injetado antes de OUTRAS INFORMAÇÕES');
        }
      } catch (e) {
        log('⚠️ Erro ao injetar: ' + e.message);
      }
    }
    
    // 2. Tentar no painel de contato em geral
    if (!injected) {
      const contactPanel = document.querySelector('[class*="ContactDrawer"], [class*="contactDrawer"], [class*="contact-drawer"]');
      if (contactPanel) {
        // Encontrar um bom lugar - após as tabs ou no final
        const tabs = contactPanel.querySelector('[class*="tabs"], [class*="Tabs"], [role="tablist"]');
        if (tabs && tabs.parentElement) {
          tabs.parentElement.insertBefore(panel, tabs.nextSibling);
        } else {
          contactPanel.appendChild(panel);
        }
        injected = true;
        log('✅ Botão injetado no painel de contato');
      }
    }
    
    // 3. Tentar no painel lateral direito genérico
    if (!injected) {
      const rightPanel = document.querySelector('[class*="rightSide"], [class*="RightSide"], [class*="sidebar"]:last-child');
      if (rightPanel) {
        rightPanel.appendChild(panel);
        injected = true;
        log('✅ Botão injetado no painel lateral');
      }
    }
    
    // 4. Fallback: painel flutuante
    if (!injected) {
      panel.classList.add('floating');
      document.body.appendChild(panel);
      injected = true;
      log('✅ Botão injetado como painel flutuante (fallback)');
    }
    
    // Adicionar event listeners
    setTimeout(() => {
      const btnPedido = document.getElementById(BUTTON_ID);
      const btnHistorico = document.getElementById('izglp-btn-historico');
      
      if (btnPedido) {
        btnPedido.onclick = () => {
          const url = phone 
            ? `https://moskogas-app.pages.dev/pedido.html?phone=${phone}`
            : 'https://moskogas-app.pages.dev/pedido.html';
          window.open(url, '_blank');
          log(`🛒 Abrindo pedido: ${url}`);
        };
      }
      
      if (btnHistorico) {
        btnHistorico.onclick = () => {
          const url = phone 
            ? `https://moskogas-app.pages.dev/consulta-pedidos.html?phone=${phone}`
            : 'https://moskogas-app.pages.dev/consulta-pedidos.html';
          window.open(url, '_blank');
          log(`📋 Abrindo histórico: ${url}`);
        };
      }
    }, 100);
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
  
  // ══════════════════════════════════════════════════════════════════════════════
  // LISTENERS
  // ══════════════════════════════════════════════════════════════════════════════
  
  if (isContextValid()) {
    chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
      if (request.action === 'getStatus') {
        sendResponse({ currentPhone: lastInjectedPhone, enabled: true });
      } else if (request.action === 'refresh') {
        lastInjectedPhone = null;
        checkAndInject();
        sendResponse({ ok: true });
      }
      return true;
    });
  }
  
  // Iniciar
  init();
  
  log('🟢 IZGLP Bina v2.1.0 — Injeção no IzChat ativa');
  
})();
