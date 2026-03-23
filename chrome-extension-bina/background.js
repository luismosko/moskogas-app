// MoskoGás Bina - Background Service Worker v1.0.0

// Quando a extensão é instalada
chrome.runtime.onInstalled.addListener((details) => {
  if (details.reason === 'install') {
    console.log('MoskoGás Bina instalada!');
    
    // Definir configurações padrão
    chrome.storage.sync.set({
      bina_enabled: true,
      bina_position: 'right'
    });
  }
});

// Listener para mensagens
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'openMoskoGas') {
    chrome.tabs.create({
      url: `https://moskogas-app.pages.dev/pedido.html?phone=${request.phone}`
    });
    sendResponse({ ok: true });
  }
  return true;
});

// Atalho de teclado (opcional)
chrome.commands?.onCommand?.addListener((command) => {
  if (command === 'toggle-bina') {
    chrome.storage.sync.get(['bina_enabled'], (result) => {
      const newValue = !result.bina_enabled;
      chrome.storage.sync.set({ bina_enabled: newValue });
      
      // Notificar todas as tabs do IzChat
      chrome.tabs.query({ url: '*://chat.izchat.com.br/*' }, (tabs) => {
        for (const tab of tabs) {
          chrome.tabs.sendMessage(tab.id, { 
            action: 'setEnabled', 
            enabled: newValue 
          }).catch(() => {});
        }
      });
    });
  }
});
