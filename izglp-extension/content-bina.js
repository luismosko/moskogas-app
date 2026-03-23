// IZGLP — Bina v2.2.0
// Apenas um botão "Abrir Pedido" no painel direito do IzChat

(function() {
  'use strict';
  
  const log = (msg) => console.log(`[IZGLP] ${msg}`);
  const BUTTON_ID = 'izglp-btn-pedido';
  
  let lastPhone = null;
  
  function init() {
    log('🔥 IZGLP Bina v2.2.0');
    injectStyles();
    setInterval(checkAndInject, 800);
    
    // Observer para mudanças
    new MutationObserver(() => setTimeout(checkAndInject, 300))
      .observe(document.body, { childList: true, subtree: true });
  }
  
  function injectStyles() {
    if (document.getElementById('izglp-styles')) return;
    
    const style = document.createElement('style');
    style.id = 'izglp-styles';
    style.textContent = `
      #${BUTTON_ID} {
        width: calc(100% - 32px);
        margin: 12px 16px;
        padding: 14px 20px;
        background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%);
        color: white;
        border: none;
        border-radius: 10px;
        font-size: 15px;
        font-weight: bold;
        cursor: pointer;
        display: flex;
        align-items: center;
        justify-content: center;
        gap: 8px;
        transition: all 0.2s;
        box-shadow: 0 4px 12px rgba(245, 158, 11, 0.4);
      }
      #${BUTTON_ID}:hover {
        transform: translateY(-2px);
        box-shadow: 0 6px 16px rgba(245, 158, 11, 0.5);
        background: linear-gradient(135deg, #d97706 0%, #b45309 100%);
      }
    `;
    document.head.appendChild(style);
  }
  
  function checkAndInject() {
    // Só injetar se o painel "Dados do contato" estiver aberto
    const contactPanel = findContactPanel();
    if (!contactPanel) {
      // Remover botão se painel fechou
      const btn = document.getElementById(BUTTON_ID);
      if (btn) btn.remove();
      lastPhone = null;
      return;
    }
    
    // Pegar telefone do painel direito (NÃO da lista de conversas)
    const phone = getPhoneFromContactPanel(contactPanel);
    
    // Não reinjetar se já existe com mesmo telefone
    if (document.getElementById(BUTTON_ID) && lastPhone === phone) return;
    
    // Remover botão antigo
    const oldBtn = document.getElementById(BUTTON_ID);
    if (oldBtn) oldBtn.remove();
    
    lastPhone = phone;
    
    // Criar botão
    const btn = document.createElement('button');
    btn.id = BUTTON_ID;
    btn.innerHTML = '🛒 Abrir Pedido';
    btn.title = phone ? `Abrir pedido para ${formatPhone(phone)}` : 'Abrir novo pedido';
    
    btn.onclick = () => {
      const url = phone 
        ? `https://moskogas-app.pages.dev/pedido.html?phone=${phone}`
        : 'https://moskogas-app.pages.dev/pedido.html';
      window.open(url, '_blank');
      log(`🛒 Abrindo: ${url}`);
    };
    
    // Encontrar onde injetar (após "OUTRAS INFORMAÇÕES" ou no final do painel)
    const target = findInjectionPoint(contactPanel);
    if (target) {
      target.parentNode.insertBefore(btn, target);
      log(`✅ Botão injetado (${phone ? formatPhone(phone) : 'sem telefone'})`);
    } else {
      // Fallback: adicionar no final do painel
      contactPanel.appendChild(btn);
      log(`✅ Botão injetado no final do painel`);
    }
  }
  
  function findContactPanel() {
    // Procurar o painel "Dados do contato" que aparece à direita
    // Identificar pelo texto "Dados do contato" ou "Editar contato"
    
    const panels = document.querySelectorAll('[class*="drawer"], [class*="Drawer"], [class*="panel"], [class*="Panel"], [class*="sidebar"], [class*="Sidebar"]');
    
    for (const panel of panels) {
      const text = panel.textContent || '';
      // Verificar se é o painel de dados do contato
      if (text.includes('Dados do contato') || text.includes('Editar contato') || text.includes('OUTRAS INFORMAÇÕES')) {
        // Verificar se tem telefone no formato +55
        if (text.match(/\+55\s*\(\d{2}\)\s*\d{4,5}-?\d{4}/)) {
          return panel;
        }
      }
    }
    
    return null;
  }
  
  function getPhoneFromContactPanel(panel) {
    // Buscar o telefone que aparece no cabeçalho do painel de contato
    // Formato: "+55 (67) 9286-8073" (com parênteses e hífen)
    
    const text = panel.textContent || '';
    
    // Padrão específico do IzChat: +55 (XX) XXXXX-XXXX
    // Mas IGNORAR o número da empresa que aparece nos badges: +55 67 XXXX-XXXX (sem parênteses)
    const matches = text.match(/\+55\s*\((\d{2})\)\s*(\d{4,5})-?(\d{4})/g);
    
    if (matches && matches.length > 0) {
      // Pegar o PRIMEIRO match que é o do cliente (no header do painel)
      const match = matches[0].match(/\+55\s*\((\d{2})\)\s*(\d{4,5})-?(\d{4})/);
      if (match) {
        const phone = `55${match[1]}${match[2]}${match[3]}`;
        log(`📱 Telefone encontrado: ${phone}`);
        return phone;
      }
    }
    
    // Fallback: buscar em elementos específicos
    const phoneElements = panel.querySelectorAll('[class*="phone"], [class*="Phone"], [class*="number"], [class*="contact"]');
    for (const el of phoneElements) {
      const elText = el.textContent || '';
      const match = elText.match(/\+55\s*\((\d{2})\)\s*(\d{4,5})-?(\d{4})/);
      if (match) {
        return `55${match[1]}${match[2]}${match[3]}`;
      }
    }
    
    return null;
  }
  
  function findInjectionPoint(panel) {
    // Encontrar "OUTRAS INFORMAÇÕES" para injetar antes
    const elements = panel.querySelectorAll('*');
    for (const el of elements) {
      const text = (el.textContent || '').trim();
      if (text === 'OUTRAS INFORMAÇÕES' || text === 'OUTRAS INFORMACOES') {
        return el;
      }
    }
    return null;
  }
  
  function formatPhone(phone) {
    if (!phone) return '';
    const d = phone.replace(/\D/g, '');
    if (d.length === 13) return `+${d.slice(0,2)} (${d.slice(2,4)}) ${d.slice(4,9)}-${d.slice(9)}`;
    if (d.length === 12) return `+${d.slice(0,2)} (${d.slice(2,4)}) ${d.slice(4,8)}-${d.slice(8)}`;
    return phone;
  }
  
  // Iniciar
  init();
})();
