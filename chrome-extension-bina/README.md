# 🔥 MoskoGás Bina - Extensão Chrome

> Identificador de clientes para IzChat

## 📋 O que faz

Quando você está no IzChat conversando com um cliente, a extensão:

1. **Detecta automaticamente** o telefone da conversa
2. **Busca no MoskoGás** os dados do cliente
3. **Mostra um painel flutuante** com:
   - 👤 Nome do cliente
   - 📍 Endereço completo
   - 🏘️ Bairro
   - 📦 Última compra
4. **Botões de ação rápida**:
   - 🛒 Novo Pedido (abre o MoskoGás com dados preenchidos)
   - 📋 Ver Histórico

## 🚀 Instalação

### Passo 1: Baixar a extensão

A pasta `chrome-extension-bina` contém todos os arquivos necessários.

### Passo 2: Ativar modo desenvolvedor no Chrome

1. Abra o Chrome
2. Acesse: `chrome://extensions`
3. Ative o **"Modo do desenvolvedor"** (canto superior direito)

### Passo 3: Carregar a extensão

1. Clique em **"Carregar sem compactação"**
2. Selecione a pasta `chrome-extension-bina`
3. A extensão aparecerá na lista

### Passo 4: Configurar API Key

1. Clique no ícone da extensão 🔥 na barra do Chrome
2. Cole sua **API Key** do MoskoGás
3. Clique em **"Salvar Configurações"**

> **Onde pegar a API Key?**  
> No MoskoGás, vá em Config → API Key, ou peça ao administrador.

## 🎯 Como usar

1. Abra o IzChat: https://chat.izchat.com.br
2. Clique em uma conversa com um cliente
3. O painel da Bina aparece automaticamente no canto direito
4. Veja os dados do cliente e use os botões de ação

## ⚙️ Funcionalidades

| Recurso | Descrição |
|---------|-----------|
| 🔍 Detecção automática | Identifica o telefone na conversa |
| 📱 Dados completos | Nome, endereço, bairro, última compra |
| 🛒 Novo pedido | Abre tela de pedido com dados preenchidos |
| 📋 Histórico | Consulta pedidos anteriores do cliente |
| ➕ Cadastrar | Opção para clientes não cadastrados |
| 🔄 Arrastar | Painel pode ser movido para qualquer lugar |
| ➖ Minimizar | Botão para minimizar o painel |

## 🔧 Solução de Problemas

### Painel não aparece

- Verifique se está no IzChat (chat.izchat.com.br)
- Clique no ícone da extensão e verifique se está ativada
- Recarregue a página (F5)

### "Cliente não cadastrado"

- O telefone não existe no MoskoGás
- Clique em "Cadastrar e Fazer Pedido" para adicionar

### "Erro ao buscar"

- Verifique sua conexão com a internet
- Confirme se a API Key está correta
- Tente recarregar a página

## 📁 Arquivos da Extensão

```
chrome-extension-bina/
├── manifest.json        # Configuração da extensão
├── content.js           # Script que roda no IzChat
├── content-styles.css   # Estilos do painel
├── popup.html           # Popup de configurações
├── popup.js             # Lógica do popup
├── background.js        # Service worker
└── icons/
    ├── icon16.png
    ├── icon48.png
    └── icon128.png
```

## 🔒 Permissões

A extensão precisa de:

- **chat.izchat.com.br**: Para injetar o painel da bina
- **api.moskogas.com.br**: Para buscar dados dos clientes
- **storage**: Para salvar suas configurações

## 📝 Versão

- **v1.0.0** (22/03/2026) - Versão inicial

---

**Desenvolvido para MoskoGás** 🔥
