// IZGLP — Bina v2.2.1
// Botão "Abrir Pedido" injetado no painel de dados do contato

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
    log('🔥 IZGLP Bina v2.2.1 iniciada');
    injectStyles();
    
    // Monitorar DOM
    setInterval(checkAndInject, 1000);
    
    new MutationObserver(() => setTimeout(checkAndInject, 500))
      .observe(document.body, { childList: true, subtree: true });
    
    // Verificar imediatamente
    checkAndInject();
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
        width: calc(100% - 32px);
        margin: 16px 16px;
        padding: 16px 24px;
        background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%);
        color: white;
        border: none;
        border-radius: 12px;
        font-size: 16px;
        font-weight: bold;
        cursor: pointer;
        display: flex;
        align-items: center;
        justify-content: center;
        gap: 10px;
        transition: all 0.2s;
        box-shadow: 0 4px 15px rgba(245, 158, 11, 0.4);
      }
      #${BUTTON_ID}:hover {
        transform: translateY(-2px);
        box-shadow: 0 6px 20px rgba(245, 158, 11, 0.5);
        background: linear-gradient(135deg, #d97706 0%, #b45309 100%);
      }
      #${BUTTON_ID}:active {
        transform: translateY(0);
      }
    `;
    document.head.appendChild(style);
  }
  
  // ══════════════════════════════════════════════════════════════════════════════
  // DETECÇÃO E INJEÇÃO
  // ══════════════════════════════════════════════════════════════════════════════
  
  function checkAndInject() {
    if (!enabled) return;
    
    // Verificar se o painel "Dados do contato" está aberto
    // Ele aparece à direita e contém o texto "Dados do contato" e "Editar contato"
    const rightPanel = findRightPanel();
    
    if (!rightPanel) {
      // Painel fechado - remover botão se existir
      removeButton();
      currentPhone = null;
      return;
    }
    
    // Extrair telefone do painel direito (NÃO da lista à esquerda)
    const phone = extractPhoneFromPanel(rightPanel);
    
    // Se já existe botão com mesmo telefone, não fazer nada
    const existingBtn = document.getElementById(BUTTON_ID);
    if (existingBtn && currentPhone === phone) {
      return;
    }
    
    currentPhone = phone;
    
    // Remover botão antigo
    removeButton();
    
    // Criar e injetar novo botão
    injectButton(rightPanel, phone);
  }
  
  function findRightPanel() {
    // Procurar o painel que contém "Dados do contato" ou "Editar contato"
    const allDivs = document.querySelectorAll('div');
    
    for (const div of allDivs) {
      // Verificar se é um painel lateral (geralmente tem width fixo ou é um drawer)
      const style = window.getComputedStyle(div);
      const rect = div.getBoundingClientRect();
      
      // O painel direito geralmente está à direita da tela
      if (rect.left < window.innerWidth * 0.5) continue;
      if (rect.width < 200) continue;
      
      const text = div.textContent || '';
      
      // Verificar se contém os elementos típicos do painel de contato
      if ((text.includes('Dados do contato') || text.includes('Editar contato')) &&
          text.includes('OUTRAS INFORMAÇÕES')) {
        return div;
      }
    }
    
    // Fallback: procurar por classe típica de drawer/panel
    const panels = document.querySelectorAll('[class*="Drawer"], [class*="drawer"], [class*="Panel"], [class*="panel"], [class*="Sidebar"], [class*="sidebar"]');
    for (const panel of panels) {
      const text = panel.textContent || '';
      if (text.includes('Dados do contato') || text.includes('Editar contato')) {
        return panel;
      }
    }
    
    return null;
  }
  
  function extractPhoneFromPanel(panel) {
    // O telefone aparece no formato: +55 (67) 9286-8073
    // Precisamos pegar esse formato específico COM parênteses
    // e IGNORAR o formato sem parênteses que aparece nos badges da lista
    
    const text = panel.innerText || panel.textContent || '';
    
    // Padrão COM parênteses: +55 (XX) XXXXX-XXXX
    const match = text.match(/\+55\s*\((\d{2})\)\s*(\d{4,5})-?(\d{4})/);
    
    if (match) {
      const phone = `55${match[1]}${match[2]}${match[3]}`;
      log(`📱 Telefone detectado: ${phone}`);
      return phone;
    }
    
    // Fallback: procurar em spans específicos
    const phoneSpans = panel.querySelectorAll('span, div, p');
    for (const span of phoneSpans) {
      const spanText = span.textContent || '';
      // Só aceitar se tem parênteses (formato do painel de contato)
      const spanMatch = spanText.match(/\+55\s*\((\d{2})\)\s*(\d{4,5})-?(\d{4})/);
      if (spanMatch) {
        return `55${spanMatch[1]}${spanMatch[2]}${spanMatch[3]}`;
      }
    }
    
    log('⚠️ Telefone não encontrado no painel');
    return null;
  }
  
  function injectButton(panel, phone) {
    const btn = document.createElement('button');
    btn.id = BUTTON_ID;
    btn.innerHTML = '🛒 Abrir Pedido no App';
    btn.title = phone ? `Abrir pedido para ${formatPhone(phone)}` : 'Abrir novo pedido';
    
    btn.onclick = (e) => {
      e.preventDefault();
      e.stopPropagation();
      
      const url = phone 
        ? `https://moskogas-app.pages.dev/pedido.html?phone=${phone}`
        : 'https://moskogas-app.pages.dev/pedido.html';
      
      window.open(url, '_blank');
      log(`🛒 Abrindo pedido: ${url}`);
    };
    
    // Encontrar onde injetar - antes de "OUTRAS INFORMAÇÕES"
    let injected = false;
    const allElements = panel.querySelectorAll('*');
    
    for (const el of allElements) {
      const text = (el.textContent || '').trim();
      if (text === 'OUTRAS INFORMAÇÕES' || text === 'OUTRAS INFORMACOES') {
        // Verificar se é o elemento exato (não um container)
        if (el.childNodes.length <= 1) {
          el.parentNode.insertBefore(btn, el);
          injected = true;
          log('✅ Botão injetado antes de OUTRAS INFORMAÇÕES');
          break;
        }
      }
    }
    
    // Fallback: adicionar no final do painel
    if (!injected) {
      panel.appendChild(btn);
      log('✅ Botão injetado no final do painel');
    }
  }
  
  function removeButton() {
    const btn = document.getElementById(BUTTON_ID);
    if (btn) btn.remove();
  }
  
  function formatPhone(phone) {
    if (!phone) return '';
    const d = phone.replace(/\D/g, '');
    if (d.length === 13) return `+${d.slice(0,2)} (${d.slice(2,4)}) ${d.slice(4,9)}-${d.slice(9)}`;
    if (d.length === 12) return `+${d.slice(0,2)} (${d.slice(2,4)}) ${d.slice(4,8)}-${d.slice(8)}`;
    return phone;
  }
  
  // ══════════════════════════════════════════════════════════════════════════════
  // MESSAGE LISTENERS (para comunicação com o popup)
  // ══════════════════════════════════════════════════════════════════════════════
  
  function isContextValid() {
    try { return !!(typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.id); }
    catch (e) { return false; }
  }
  
  if (isContextValid()) {
    chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
      log(`📨 Mensagem recebida: ${request.action}`);
      
      if (request.action === 'getStatus') {
        sendResponse({ 
          currentPhone: currentPhone, 
          enabled: enabled 
        });
      } 
      else if (request.action === 'setEnabled') {
        enabled = request.enabled;
        if (!enabled) {
          removeButton();
        } else {
          checkAndInject();
        }
        sendResponse({ ok: true });
      } 
      else if (request.action === 'refresh') {
        currentPhone = null;
        checkAndInject();
        sendResponse({ ok: true, phone: currentPhone });
      }
      
      return true; // Indica resposta assíncrona
    });
  }
  
  // ══════════════════════════════════════════════════════════════════════════════
  // INICIAR
  // ══════════════════════════════════════════════════════════════════════════════
  
  init();
  
})();
