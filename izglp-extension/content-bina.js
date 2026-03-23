// IZGLP — Bina v2.3.0
// Botão "Abrir Pedido" - abordagem simplificada

(function() {
  'use strict';
  
  const log = (msg) => console.log(`[IZGLP] ${msg}`);
  const BUTTON_ID = 'izglp-btn-pedido';
  
  let currentPhone = null;
  let enabled = true;
  
  // ══════════════════════════════════════════════════════════════════════════════
  // INIT
  // ══════════════════════════════════════════════════════════════════════════════
  
  function init() {
    log('🔥 IZGLP Bina v2.3.0 iniciada');
    injectStyles();
    
    // Monitorar continuamente
    setInterval(checkAndInject, 500);
    
    // Observer para mudanças no DOM
    new MutationObserver(() => {
      setTimeout(checkAndInject, 200);
    }).observe(document.body, { childList: true, subtree: true });
  }
  
  // ══════════════════════════════════════════════════════════════════════════════
  // ESTILOS
  // ══════════════════════════════════════════════════════════════════════════════
  
  function injectStyles() {
    if (document.getElementById('izglp-styles')) return;
    
    const style = document.createElement('style');
    style.id = 'izglp-styles';
    style.textContent = `
      #${BUTTON_ID} {
        display: flex !important;
        align-items: center !important;
        justify-content: center !important;
        gap: 10px !important;
        width: calc(100% - 32px) !important;
        margin: 16px 16px !important;
        padding: 16px 24px !important;
        background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%) !important;
        color: white !important;
        border: none !important;
        border-radius: 12px !important;
        font-size: 16px !important;
        font-weight: bold !important;
        cursor: pointer !important;
        box-shadow: 0 4px 15px rgba(245, 158, 11, 0.4) !important;
        transition: all 0.2s !important;
      }
      #${BUTTON_ID}:hover {
        transform: translateY(-2px) !important;
        box-shadow: 0 6px 20px rgba(245, 158, 11, 0.5) !important;
      }
    `;
    document.head.appendChild(style);
  }
  
  // ══════════════════════════════════════════════════════════════════════════════
  // DETECÇÃO E INJEÇÃO
  // ══════════════════════════════════════════════════════════════════════════════
  
  function checkAndInject() {
    if (!enabled) return;
    
    // Se já existe o botão, verificar se ainda está no DOM
    const existingBtn = document.getElementById(BUTTON_ID);
    if (existingBtn && document.body.contains(existingBtn)) {
      return; // Já existe, não fazer nada
    }
    
    // Procurar o elemento "OUTRAS INFORMAÇÕES"
    const outrasInfo = findOutrasInformacoes();
    
    if (!outrasInfo) {
      // Painel não está aberto
      currentPhone = null;
      return;
    }
    
    // Extrair telefone
    const phone = extractPhone();
    currentPhone = phone;
    
    // Criar e injetar botão
    const btn = createButton(phone);
    
    // Injetar ANTES de "OUTRAS INFORMAÇÕES"
    outrasInfo.parentNode.insertBefore(btn, outrasInfo);
    
    log(`✅ Botão injetado! Telefone: ${phone || 'não detectado'}`);
  }
  
  function findOutrasInformacoes() {
    // Buscar todos os elementos de texto
    const allElements = document.querySelectorAll('*');
    
    for (const el of allElements) {
      // Verificar apenas elementos folha (sem muitos filhos)
      if (el.children.length > 3) continue;
      
      const text = el.textContent?.trim().toUpperCase();
      
      if (text === 'OUTRAS INFORMAÇÕES' || text === 'OUTRAS INFORMACOES') {
        log('📍 Encontrado: OUTRAS INFORMAÇÕES');
        return el;
      }
    }
    
    return null;
  }
  
  function extractPhone() {
    // Buscar telefone no formato +55 (XX) XXXXX-XXXX (COM parênteses)
    const bodyText = document.body.innerText;
    
    // Padrão com parênteses - formato do painel de contato
    const matches = bodyText.match(/\+55\s*\((\d{2})\)\s*(\d{4,5})-?(\d{4})/g);
    
    if (matches && matches.length > 0) {
      // Pegar o primeiro match
      const match = matches[0].match(/\+55\s*\((\d{2})\)\s*(\d{4,5})-?(\d{4})/);
      if (match) {
        const phone = `55${match[1]}${match[2]}${match[3]}`;
        log(`📱 Telefone: ${phone}`);
        return phone;
      }
    }
    
    return null;
  }
  
  function createButton(phone) {
    const btn = document.createElement('button');
    btn.id = BUTTON_ID;
    btn.type = 'button';
    btn.innerHTML = '🛒 Abrir Pedido no App';
    
    if (phone) {
      btn.title = `Abrir pedido para ${formatPhone(phone)}`;
    }
    
    btn.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      
      const url = phone 
        ? `https://moskogas-app.pages.dev/pedido.html?phone=${phone}`
        : 'https://moskogas-app.pages.dev/pedido.html';
      
      window.open(url, '_blank');
      log(`🛒 Abrindo: ${url}`);
    });
    
    return btn;
  }
  
  function formatPhone(phone) {
    if (!phone) return '';
    const d = phone.replace(/\D/g, '');
    if (d.length === 13) return `+${d.slice(0,2)} (${d.slice(2,4)}) ${d.slice(4,9)}-${d.slice(9)}`;
    if (d.length === 12) return `+${d.slice(0,2)} (${d.slice(2,4)}) ${d.slice(4,8)}-${d.slice(8)}`;
    return phone;
  }
  
  // ══════════════════════════════════════════════════════════════════════════════
  // MESSAGE LISTENERS
  // ══════════════════════════════════════════════════════════════════════════════
  
  function isContextValid() {
    try { return !!(typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.id); }
    catch (e) { return false; }
  }
  
  if (isContextValid()) {
    chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
      log(`📨 Mensagem: ${request.action}`);
      
      if (request.action === 'getStatus') {
        sendResponse({ currentPhone, enabled });
      } 
      else if (request.action === 'setEnabled') {
        enabled = request.enabled;
        if (!enabled) {
          const btn = document.getElementById(BUTTON_ID);
          if (btn) btn.remove();
        }
        sendResponse({ ok: true });
      } 
      else if (request.action === 'refresh') {
        const btn = document.getElementById(BUTTON_ID);
        if (btn) btn.remove();
        currentPhone = null;
        setTimeout(checkAndInject, 100);
        sendResponse({ ok: true, phone: currentPhone });
      }
      
      return true;
    });
  }
  
  // ══════════════════════════════════════════════════════════════════════════════
  // INICIAR
  // ══════════════════════════════════════════════════════════════════════════════
  
  init();
  
})();
