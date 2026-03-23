// IZGLP — Bina v2.4.0
// Mostra dados do cliente + sincroniza com IzChat + botão Abrir Pedido

(function() {
  'use strict';
  
  const log = (msg) => console.log(`[IZGLP] ${msg}`);
  const PANEL_ID = 'izglp-panel';
  const API_URL = 'https://api.moskogas.com.br';
  
  let currentPhone = null;
  let enabled = true;
  let apiKey = null;
  
  // ══════════════════════════════════════════════════════════════════════════════
  // INIT
  // ══════════════════════════════════════════════════════════════════════════════
  
  function init() {
    log('🔥 IZGLP Bina v2.4.0 iniciada');
    injectStyles();
    
    // Carregar API key
    if (typeof chrome !== 'undefined' && chrome.storage) {
      chrome.storage.sync.get(['apiKey'], (data) => {
        apiKey = data.apiKey;
        log(`🔑 API Key: ${apiKey ? 'OK' : 'não configurada'}`);
      });
    }
    
    // Monitorar DOM
    setInterval(checkAndInject, 800);
    
    new MutationObserver(() => {
      setTimeout(checkAndInject, 300);
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
      #${PANEL_ID} {
        margin: 12px 16px !important;
        padding: 12px !important;
        background: linear-gradient(135deg, #059669 0%, #10b981 100%) !important;
        border-radius: 10px !important;
        box-shadow: 0 3px 10px rgba(0,0,0,0.15) !important;
      }
      #${PANEL_ID} .izglp-header {
        display: flex;
        align-items: center;
        gap: 6px;
        color: white;
        font-weight: bold;
        font-size: 13px;
        margin-bottom: 8px;
      }
      #${PANEL_ID} .izglp-data {
        background: rgba(255,255,255,0.15);
        border-radius: 6px;
        padding: 8px 10px;
        margin-bottom: 10px;
        font-size: 12px;
        color: white;
      }
      #${PANEL_ID} .izglp-data-row {
        display: flex;
        gap: 6px;
        margin-bottom: 4px;
        line-height: 1.4;
      }
      #${PANEL_ID} .izglp-data-row:last-child {
        margin-bottom: 0;
      }
      #${PANEL_ID} .izglp-data-icon {
        flex-shrink: 0;
      }
      #${PANEL_ID} .izglp-data-text {
        word-break: break-word;
      }
      #${PANEL_ID} .izglp-loading {
        color: rgba(255,255,255,0.8);
        font-size: 11px;
        padding: 8px;
        text-align: center;
      }
      #${PANEL_ID} .izglp-not-found {
        color: rgba(255,255,255,0.7);
        font-size: 11px;
        padding: 8px;
        text-align: center;
        font-style: italic;
      }
      #${PANEL_ID} .izglp-btn {
        display: flex !important;
        align-items: center !important;
        justify-content: center !important;
        gap: 6px !important;
        width: 100% !important;
        padding: 10px 16px !important;
        background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%) !important;
        color: white !important;
        border: none !important;
        border-radius: 8px !important;
        font-size: 13px !important;
        font-weight: bold !important;
        cursor: pointer !important;
        box-shadow: 0 3px 8px rgba(245, 158, 11, 0.3) !important;
        transition: all 0.2s !important;
        margin-bottom: 6px !important;
      }
      #${PANEL_ID} .izglp-btn:hover {
        transform: translateY(-1px) !important;
        box-shadow: 0 4px 12px rgba(245, 158, 11, 0.4) !important;
      }
      #${PANEL_ID} .izglp-btn-sync {
        background: rgba(255,255,255,0.2) !important;
        box-shadow: none !important;
        font-size: 11px !important;
        padding: 6px 12px !important;
      }
      #${PANEL_ID} .izglp-btn-sync:hover {
        background: rgba(255,255,255,0.3) !important;
      }
      #${PANEL_ID} .izglp-synced {
        color: rgba(255,255,255,0.8);
        font-size: 10px;
        text-align: center;
        margin-top: 4px;
      }
    `;
    document.head.appendChild(style);
  }
  
  // ══════════════════════════════════════════════════════════════════════════════
  // DETECÇÃO E INJEÇÃO
  // ══════════════════════════════════════════════════════════════════════════════
  
  function checkAndInject() {
    if (!enabled) return;
    
    // Verificar se já existe o painel
    const existingPanel = document.getElementById(PANEL_ID);
    if (existingPanel && document.body.contains(existingPanel)) {
      return;
    }
    
    // Procurar "OUTRAS INFORMAÇÕES"
    const outrasInfo = findOutrasInformacoes();
    if (!outrasInfo) {
      currentPhone = null;
      return;
    }
    
    // Extrair telefone
    const phone = extractPhone();
    if (!phone) return;
    
    currentPhone = phone;
    
    // Criar painel
    const panel = createPanel(phone);
    outrasInfo.parentNode.insertBefore(panel, outrasInfo);
    
    log(`✅ Painel injetado! Telefone: ${phone}`);
    
    // Buscar dados do cliente
    fetchClientData(phone);
  }
  
  function findOutrasInformacoes() {
    const allElements = document.querySelectorAll('*');
    
    for (const el of allElements) {
      if (el.children.length > 3) continue;
      
      const text = el.textContent?.trim().toUpperCase();
      if (text === 'OUTRAS INFORMAÇÕES' || text === 'OUTRAS INFORMACOES') {
        return el;
      }
    }
    return null;
  }
  
  function extractPhone() {
    const bodyText = document.body.innerText;
    const matches = bodyText.match(/\+55\s*\((\d{2})\)\s*(\d{4,5})-?(\d{4})/g);
    
    if (matches && matches.length > 0) {
      const match = matches[0].match(/\+55\s*\((\d{2})\)\s*(\d{4,5})-?(\d{4})/);
      if (match) {
        return `55${match[1]}${match[2]}${match[3]}`;
      }
    }
    return null;
  }
  
  // ══════════════════════════════════════════════════════════════════════════════
  // CRIAR PAINEL
  // ══════════════════════════════════════════════════════════════════════════════
  
  function createPanel(phone) {
    const panel = document.createElement('div');
    panel.id = PANEL_ID;
    
    panel.innerHTML = `
      <div class="izglp-header">
        <span>🔥</span>
        <span>IZGLP</span>
      </div>
      <div class="izglp-data" id="izglp-client-data">
        <div class="izglp-loading">⏳ Buscando cliente...</div>
      </div>
      <button class="izglp-btn" id="izglp-btn-pedido">
        🛒 Abrir Pedido
      </button>
      <button class="izglp-btn izglp-btn-sync" id="izglp-btn-sync" style="display:none">
        🔄 Sincronizar com IzChat
      </button>
    `;
    
    // Event: Abrir Pedido
    panel.querySelector('#izglp-btn-pedido').addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      
      const url = phone 
        ? `https://moskogas-app.pages.dev/pedido.html?phone=${phone}`
        : 'https://moskogas-app.pages.dev/pedido.html';
      
      window.open(url, '_blank');
      log(`🛒 Abrindo: ${url}`);
    });
    
    // Event: Sincronizar
    panel.querySelector('#izglp-btn-sync').addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      syncClient(phone);
    });
    
    return panel;
  }
  
  // ══════════════════════════════════════════════════════════════════════════════
  // BUSCAR DADOS DO CLIENTE - v2.4.1: tenta variações com/sem 9
  // ══════════════════════════════════════════════════════════════════════════════
  
  function getPhoneVariations(phone) {
    // Gerar variações: com/sem 55, com/sem 9
    const variations = [];
    const digits = phone.replace(/\D/g, '');
    
    // Determinar versão local (sem 55)
    let local = digits;
    if (local.startsWith('55') && local.length > 11) {
      local = local.substring(2);
    }
    
    // Adicionar variações COM e SEM 55
    // E também COM e SEM o 9 do celular
    
    if (local.length === 11 && local[2] === '9') {
      // Formato: 67992414371 (11 dígitos, com 9 do celular)
      variations.push(local);                                    // 67992414371
      variations.push('55' + local);                             // 5567992414371
      const without9 = local.substring(0, 2) + local.substring(3);
      variations.push(without9);                                 // 6792414371
      variations.push('55' + without9);                          // 556792414371
    } else if (local.length === 10) {
      // Formato: 6792414371 (10 dígitos, sem 9 do celular)
      variations.push(local);                                    // 6792414371
      variations.push('55' + local);                             // 556792414371
      const with9 = local.substring(0, 2) + '9' + local.substring(2);
      variations.push(with9);                                    // 67992414371
      variations.push('55' + with9);                             // 5567992414371
    } else {
      // Outros formatos - tentar como está
      variations.push(digits);
      if (digits.startsWith('55')) {
        variations.push(digits.substring(2));
      } else {
        variations.push('55' + digits);
      }
    }
    
    // Remover duplicatas
    return [...new Set(variations)];
  }
  
  async function fetchClientData(phone) {
    const dataDiv = document.getElementById('izglp-client-data');
    const syncBtn = document.getElementById('izglp-btn-sync');
    if (!dataDiv) return;
    
    const variations = getPhoneVariations(phone);
    log(`🔍 Tentando variações: ${variations.join(', ')}`);
    
    try {
      let client = null;
      
      // Tentar cada variação até encontrar
      for (const variant of variations) {
        const url = `${API_URL}/api/customer/search?q=${variant}&type=phone&api_key=${apiKey || 'Moskogas0909'}`;
        const response = await fetch(url);
        const clients = await response.json();
        
        if (clients && clients.length > 0) {
          client = clients[0];
          log(`✅ Cliente encontrado com ${variant}: ${client.name}`);
          break;
        }
      }
      
      if (client) {
        const c = client;
        
        let html = '';
        
        // Nome
        if (c.name) {
          html += `<div class="izglp-data-row"><span class="izglp-data-icon">👤</span><span class="izglp-data-text"><strong>${c.name}</strong></span></div>`;
        }
        
        // Endereço
        if (c.address_line) {
          html += `<div class="izglp-data-row"><span class="izglp-data-icon">📍</span><span class="izglp-data-text">${c.address_line}</span></div>`;
        }
        
        // Bairro
        if (c.bairro) {
          html += `<div class="izglp-data-row"><span class="izglp-data-icon">🏘️</span><span class="izglp-data-text">${c.bairro}</span></div>`;
        }
        
        // Complemento
        if (c.complemento) {
          html += `<div class="izglp-data-row"><span class="izglp-data-icon">🏠</span><span class="izglp-data-text">${c.complemento}</span></div>`;
        }
        
        // Referência
        if (c.referencia) {
          html += `<div class="izglp-data-row"><span class="izglp-data-icon">📌</span><span class="izglp-data-text">${c.referencia}</span></div>`;
        }
        
        // Última compra
        if (c.ultima_compra_glp) {
          html += `<div class="izglp-data-row"><span class="izglp-data-icon">📦</span><span class="izglp-data-text">Última: ${c.ultima_compra_glp}</span></div>`;
        }
        
        if (!html) {
          html = `<div class="izglp-not-found">Cliente sem dados adicionais</div>`;
        }
        
        dataDiv.innerHTML = html;
        
        // Mostrar botão de sincronização
        if (syncBtn) {
          syncBtn.style.display = 'flex';
        }
        
        // Sincronizar automaticamente com IzChat
        autoSyncWithIzChat(phone, c);
        
        log(`📋 Dados carregados: ${c.name}`);
      } else {
        dataDiv.innerHTML = `<div class="izglp-not-found">❓ Cliente não cadastrado no App</div>`;
        if (syncBtn) syncBtn.style.display = 'none';
      }
    } catch (e) {
      log(`❌ Erro ao buscar cliente: ${e.message}`);
      dataDiv.innerHTML = `<div class="izglp-not-found">⚠️ Erro ao buscar dados</div>`;
    }
  }
  
  // ══════════════════════════════════════════════════════════════════════════════
  // SINCRONIZAR COM IZCHAT
  // ══════════════════════════════════════════════════════════════════════════════
  
  async function autoSyncWithIzChat(phone, client) {
    if (!client || !client.name) return;
    
    try {
      const url = `${API_URL}/api/izchat/contacts/sync?api_key=${apiKey || 'Moskogas0909'}`;
      const response = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ phone_digits: phone })
      });
      
      const result = await response.json();
      
      if (result.ok || result.synced) {
        log(`✅ Cliente sincronizado com IzChat: ${client.name}`);
        
        // Mostrar indicador de sincronizado
        const panel = document.getElementById(PANEL_ID);
        if (panel) {
          let syncedDiv = panel.querySelector('.izglp-synced');
          if (!syncedDiv) {
            syncedDiv = document.createElement('div');
            syncedDiv.className = 'izglp-synced';
            panel.appendChild(syncedDiv);
          }
          syncedDiv.textContent = '✅ Sincronizado com IzChat';
        }
      }
    } catch (e) {
      log(`⚠️ Erro ao sincronizar: ${e.message}`);
    }
  }
  
  async function syncClient(phone) {
    const syncBtn = document.getElementById('izglp-btn-sync');
    if (!syncBtn) return;
    
    syncBtn.disabled = true;
    syncBtn.textContent = '⏳ Sincronizando...';
    
    try {
      const url = `${API_URL}/api/izchat/contacts/sync?api_key=${apiKey || 'Moskogas0909'}`;
      const response = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ phone_digits: phone })
      });
      
      const result = await response.json();
      
      if (result.ok || result.synced) {
        syncBtn.textContent = '✅ Sincronizado!';
        log(`✅ Sincronização manual concluída`);
        
        // Mostrar indicador
        const panel = document.getElementById(PANEL_ID);
        if (panel) {
          let syncedDiv = panel.querySelector('.izglp-synced');
          if (!syncedDiv) {
            syncedDiv = document.createElement('div');
            syncedDiv.className = 'izglp-synced';
            panel.appendChild(syncedDiv);
          }
          syncedDiv.textContent = '✅ Dados atualizados no IzChat';
        }
      } else {
        syncBtn.textContent = '❌ Erro';
      }
    } catch (e) {
      syncBtn.textContent = '❌ Erro';
      log(`❌ Erro na sincronização: ${e.message}`);
    }
    
    setTimeout(() => {
      syncBtn.disabled = false;
      syncBtn.textContent = '🔄 Sincronizar com IzChat';
    }, 3000);
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
          const panel = document.getElementById(PANEL_ID);
          if (panel) panel.remove();
        }
        sendResponse({ ok: true });
      } 
      else if (request.action === 'refresh') {
        const panel = document.getElementById(PANEL_ID);
        if (panel) panel.remove();
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
