# 🔥 IZGLP — Extensão Chrome v2.0.0

> Sistema integrado de gestão de pedidos de gás

## 📋 Funcionalidades

### 📦 Hub Ultragaz
- Monitora pedidos do Hub Ultragaz automaticamente
- Cria pedidos no IZGLP automaticamente
- Detecta cancelamentos e sincroniza
- Varredura a cada 1 minuto
- Notificações de novos pedidos
- Botão para pausar varredura

### 📞 Bina Virtual (IzChat)
- Painel flutuante no IzChat
- Detecta telefone da conversa automaticamente
- Mostra dados do cliente:
  - 👤 Nome
  - 📍 Endereço e bairro
  - 📦 Última compra
- Botões de ação rápida:
  - 🛒 Novo Pedido
  - 📋 Histórico
- Cadastro rápido para clientes novos

---

## 🚀 Instalação

### Passo 1: Baixar a extensão

Extraia o arquivo `izglp-extension.zip` ou use a pasta `izglp-extension` do repositório.

### Passo 2: Ativar modo desenvolvedor no Chrome

1. Abra o Chrome
2. Acesse: `chrome://extensions`
3. Ative o **"Modo do desenvolvedor"** (canto superior direito)

### Passo 3: Carregar a extensão

1. Clique em **"Carregar sem compactação"**
2. Selecione a pasta `izglp-extension`
3. A extensão aparecerá na lista

### Passo 4: Configurar API Key

1. Clique no ícone 🔥 da extensão na barra do Chrome
2. Vá na aba **Config**
3. Cole a **API Key**: `Moskogas0909`
4. Clique em **"Salvar e Conectar"**

---

## 🎯 Como usar

### Hub Ultragaz

1. Abra o Hub: `https://hub.ultragaz.com.br`
2. Faça login normalmente
3. A extensão monitora automaticamente os pedidos
4. Novos pedidos são criados no IZGLP automaticamente
5. Você receberá notificações quando houver pedidos novos

### Bina Virtual

1. Abra o IzChat: `https://chat.izchat.com.br`
2. Clique em uma conversa
3. O painel da Bina aparece no canto direito
4. Veja os dados do cliente e use os botões de ação

---

## 📁 Estrutura de Arquivos

```
izglp-extension/
├── manifest.json        # Configuração da extensão
├── background.js        # Service worker (lógica principal)
├── content-hub.js       # Script do Hub Ultragaz
├── content-bina.js      # Script do IzChat (Bina)
├── content-bina.css     # Estilos do painel Bina
├── popup.html           # Popup da extensão
├── popup.js             # Lógica do popup
├── README.md            # Este arquivo
└── icons/
    ├── icon16.png
    ├── icon48.png
    └── icon128.png
```

---

## 🔧 Solução de Problemas

### Hub não está sincronizando

- Verifique se a aba do Hub está aberta
- Clique em "Varrer Agora" no popup
- Verifique se a API Key está correta na aba Config

### Bina não mostra dados do cliente

- Verifique se está no IzChat
- Clique em "Atualizar Bina" no popup
- Verifique se a Bina está ativada (toggle na aba Bina)

### "API Key inválida"

- Verifique se a API Key está correta
- A API Key padrão é: `Moskogas0909`
- Se o erro persistir, verifique a conexão com a internet

---

## 🔒 Permissões

A extensão precisa de acesso a:

- `hub.ultragaz.com.br` — Monitorar pedidos do Hub
- `chat.izchat.com.br` — Injetar painel da Bina
- `api.moskogas.com.br` — Comunicar com o backend IZGLP
- `moskogas-app.pages.dev` — Abrir páginas do sistema

---

## 📝 Changelog

### v2.0.0 (22/03/2026)
- Extensão unificada: Hub + Bina
- Nova identidade visual IZGLP
- Interface com abas
- Melhorias de performance

### v1.1.6 (anterior)
- Apenas Hub Ultragaz

---

**Desenvolvido para IZGLP** 🔥  
Mosko Ltda © 2026
