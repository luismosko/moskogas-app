// MoskoGás Bina - Popup Script v1.0.0

document.addEventListener('DOMContentLoaded', async () => {
  const apiKeyInput = document.getElementById('api-key');
  const toggleEnabled = document.getElementById('toggle-enabled');
  const btnSave = document.getElementById('btn-save');
  const btnRefresh = document.getElementById('btn-refresh');
  const pageStatus = document.getElementById('page-status');
  const phoneStatus = document.getElementById('phone-status');
  const alertNoKey = document.getElementById('alert-no-key');
  const alertSuccess = document.getElementById('alert-success');
  
  // Carregar configurações salvas
  const stored = await chrome.storage.sync.get(['moskogas_api_key', 'bina_enabled']);
  
  if (stored.moskogas_api_key) {
    apiKeyInput.value = stored.moskogas_api_key;
  } else {
    alertNoKey.classList.remove('hidden');
  }
  
  toggleEnabled.checked = stored.bina_enabled !== false;
  
  // Verificar página atual
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  
  if (tab && tab.url) {
    if (tab.url.includes('chat.izchat.com.br')) {
      pageStatus.textContent = '✅ IzChat';
      pageStatus.classList.add('active');
      
      // Tentar obter status do content script
      try {
        const response = await chrome.tabs.sendMessage(tab.id, { action: 'getStatus' });
        if (response) {
          if (response.currentPhone) {
            phoneStatus.textContent = formatPhone(response.currentPhone);
            phoneStatus.classList.add('active');
          } else {
            phoneStatus.textContent = 'Nenhum';
          }
        }
      } catch (e) {
        phoneStatus.textContent = '—';
      }
    } else if (tab.url.includes('moskogas')) {
      pageStatus.textContent = '🏠 MoskoGás';
    } else {
      pageStatus.textContent = '❌ Outra página';
      pageStatus.classList.add('inactive');
    }
  }
  
  // Salvar configurações
  btnSave.addEventListener('click', async () => {
    const apiKey = apiKeyInput.value.trim();
    const enabled = toggleEnabled.checked;
    
    await chrome.storage.sync.set({
      moskogas_api_key: apiKey,
      bina_enabled: enabled
    });
    
    // Notificar content script
    if (tab && tab.url && tab.url.includes('chat.izchat.com.br')) {
      try {
        await chrome.tabs.sendMessage(tab.id, { 
          action: 'setEnabled', 
          enabled 
        });
      } catch (e) {
        // Content script pode não estar carregado ainda
      }
    }
    
    // Mostrar sucesso
    alertNoKey.classList.add('hidden');
    alertSuccess.classList.remove('hidden');
    setTimeout(() => alertSuccess.classList.add('hidden'), 3000);
  });
  
  // Atualizar bina
  btnRefresh.addEventListener('click', async () => {
    if (tab && tab.url && tab.url.includes('chat.izchat.com.br')) {
      try {
        await chrome.tabs.sendMessage(tab.id, { action: 'refresh' });
        btnRefresh.textContent = '✅ Atualizado!';
        setTimeout(() => {
          btnRefresh.innerHTML = '🔄 Atualizar Bina';
        }, 2000);
      } catch (e) {
        btnRefresh.textContent = '❌ Erro';
        setTimeout(() => {
          btnRefresh.innerHTML = '🔄 Atualizar Bina';
        }, 2000);
      }
    } else {
      alert('Abra o IzChat primeiro!');
    }
  });
  
  // Toggle ativado/desativado
  toggleEnabled.addEventListener('change', async () => {
    const enabled = toggleEnabled.checked;
    
    await chrome.storage.sync.set({ bina_enabled: enabled });
    
    if (tab && tab.url && tab.url.includes('chat.izchat.com.br')) {
      try {
        await chrome.tabs.sendMessage(tab.id, { 
          action: 'setEnabled', 
          enabled 
        });
      } catch (e) {
        // Ignorar
      }
    }
  });
});

function formatPhone(phone) {
  if (!phone) return '';
  const digits = phone.replace(/\D/g, '');
  if (digits.length === 13) {
    return `(${digits.slice(2,4)}) ${digits.slice(4,9)}-${digits.slice(9)}`;
  }
  if (digits.length === 12) {
    return `(${digits.slice(2,4)}) ${digits.slice(4,8)}-${digits.slice(8)}`;
  }
  return phone;
}
