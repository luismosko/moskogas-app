# 🤖 Robô Ultragaz × MoskoGás — Documentação Completa

> **Atualizado em:** 09/03/2026  
> **Status:** ✅ Completo e rodando na VPS DigitalOcean

---

## ⚠️ IMPORTANTE — NÃO RECRIAR

O robô **já está completo e funcional**. Não recriar, não reescrever.  
Se Claude perguntar "quer que eu crie o robô?", a resposta é **NÃO** — ele já existe aqui.

---

## 🏗️ Arquitetura

```
Hub Ultragaz (portal web)
       │
       │  Playwright (Chromium headless)
       │  → login automático
       │  → captura URL assinada do WebSocket AWS
       ▼
VPS DigitalOcean (Droplet 555524687)
  Node.js + PM2 → ultragaz-robot/src/index.js
       │
       │  WebSocket em tempo real
       │  → evento newOrder → GET_SELECTS (detalhes)
       │  → varredura automática a cada 5min
       ▼
POST https://api.moskogas.com.br/api/ultragaz/pedido
       │  Header: X-API-KEY: Moskogas0909
       ▼
Cloudflare Worker (moskogas-backend-v2)
  → Cria order com status='novo', vendedor_nome='Ultragaz Hub'
  → Idempotência dupla: SQLite local + D1
       ▼
shared.js (polling 15s em todas as telas)
  → Alerta laranja no topo + beep sonoro
  → Botão "Ver na Gestão" → gestao.html?ultragaz=1
```

---

## 📁 Estrutura de Arquivos

```
ultragaz-robot/
├── src/
│   ├── index.js        ← Loop principal, orquestrador
│   ├── browser.js      ← Login Playwright, getWebsocketInfo, getPendingOrders
│   ├── websocket.js    ← Conexão WS, listener eventos, varredura, heartbeat
│   ├── moskogas.js     ← Envia pedido para API MoskoGás
│   ├── db.js           ← SQLite local (idempotência + fila de retry)
│   └── imap-reader.js  ← Leitura 2FA por email IMAP (Gmail)
├── .env.example        ← Template de variáveis de ambiente
├── package.json        ← Dependências: playwright, ws, better-sqlite3, dotenv
├── README.md           ← Instalação rápida
└── DOCUMENTACAO.md     ← Este arquivo
```

---

## 🔑 Configuração na VPS

### Arquivo `.env` (na VPS, em `/root/moskogas-app/ultragaz-robot/.env`)
```env
MOSKOGAS_API_URL=https://api.moskogas.com.br
MOSKOGAS_API_KEY=Moskogas0909
SESSION_RENEWAL_MS=21600000   # 6 horas
LOG_LEVEL=info

# Gmail para leitura do 2FA (opcional)
GMAIL_USER=luismosko@gmail.com
GMAIL_APP_PASSWORD=xxxx xxxx xxxx xxxx
```

> **As credenciais do Hub Ultragaz ficam no `config.html`** — o robô busca via `GET /api/ultragaz/config`.  
> NÃO colocar login/senha do Hub no `.env`.

---

## 🚀 Comandos PM2 (na VPS)

```bash
pm2 status                          # Ver status do processo
pm2 logs ultragaz-robot             # Ver logs em tempo real
pm2 logs ultragaz-robot --lines 100 # Últimas 100 linhas
pm2 restart ultragaz-robot          # Reiniciar
pm2 stop ultragaz-robot             # Parar
pm2 start src/index.js --name ultragaz-robot  # Iniciar (se parado)
```

---

## 🔄 Fluxo Detalhado do Robô

### 1. Inicialização
- Busca credenciais do Hub em `GET /api/ultragaz/config` (painel MoskoGás)
- Marca status como `aguardando_login` via `POST /api/ultragaz/hub-status`
- **Aguarda operador clicar "Iniciar Login" no `config.html`** (polling `GET /api/ultragaz/login-request`)

### 2. Login no Hub
- Playwright abre Chromium headless
- Navega para `hub.ultragaz.com.br`
- Preenche email + senha (múltiplos seletores para robustez)
- Se houver 2FA: aguarda `GET /api/ultragaz/2fa-code` (operador digita no painel OU imap-reader.js lê do email)
- Captura cookies de sessão

### 3. WebSocket
- Extrai URL assinada do WebSocket AWS da página do Hub
- Conecta com `ws` (Node.js)
- Evento `newOrder` / `newOrderUG` → busca detalhes via `GET_SELECTS` → envia para MoskoGás
- Ping a cada 3min50s (mantém conexão viva — servidor fecha em 4min sem atividade)
- Heartbeat a cada 3min → atualiza `hub-status` no D1 (evita falso "desconectado" na UI)

### 4. Varredura Automática
- A cada 5 minutos, percorre abas do Hub: "Em Aberto", "Agendados", "Em Andamento"
- Processa pedidos que chegaram antes da conexão WS
- Operador pode disparar varredura manual pelo painel (botão → `POST /api/ultragaz/scan-orders`)

### 5. Idempotência (dupla proteção)
- **Camada 1:** SQLite local (`db.js`) — evita reprocessar na mesma instância
- **Camada 2:** D1 (`ultragaz_orders`) — worker ignora `ultragaz_order_id` duplicado

### 6. Fila de Retry
- Se envio falhar (rede/timeout), pedido vai para fila SQLite
- Retry automático a cada 30 segundos, até 5 tentativas

### 7. Renovação de Sessão
- A cada 6 horas (configurável via `SESSION_RENEWAL_MS`)
- Se WebSocket retornar 401 duas vezes seguidas → re-login automático (sem precisar do operador)

---

## 📡 Endpoints Worker Relacionados

| Endpoint | Quem usa | Função |
|----------|----------|--------|
| `GET /api/ultragaz/config` | Robô | Busca credenciais do Hub |
| `POST /api/ultragaz/config` | Admin (config.html) | Salva credenciais |
| `POST /api/ultragaz/start-login` | Admin (config.html) | Sinaliza para robô iniciar login |
| `GET /api/ultragaz/login-request` | Robô | Verifica se há solicitação de login |
| `DELETE /api/ultragaz/login-request` | Robô | Consome solicitação após receber |
| `GET /api/ultragaz/2fa-code` | Robô | Busca código 2FA digitado pelo operador |
| `POST /api/ultragaz/2fa-code` | Admin / imap-reader | Salva código 2FA |
| `DELETE /api/ultragaz/2fa-code` | Robô | Limpa código após usar |
| `GET /api/ultragaz/hub-status` | UI (config.html) | Lê status de conexão |
| `POST /api/ultragaz/hub-status` | Robô | Atualiza status (heartbeat) |
| `POST /api/ultragaz/scan-orders` | Admin (config.html) | Solicita varredura manual |
| `GET /api/ultragaz/scan-orders` | Robô | Verifica se há varredura pendente |
| `POST /api/ultragaz/robot-log` | Robô | Salva log de diagnóstico |
| `GET /api/ultragaz/robot-log` | Admin (config.html) | Lê último log do robô |
| `POST /api/ultragaz/pedido` | Robô | **Cria pedido no MoskoGás** |
| `GET /api/ultragaz/orders` | Admin | Lista pedidos recebidos |
| `GET/POST /api/ultragaz/product-map` | Admin / Robô | Mapa SKU Hub → MoskoGás |

---

## 🗺️ Mapa de Produtos (ultragaz_product_map)

O robô envia SKUs do Hub (`P13`, `P20`, `P45`, `AGUA20L`) e o worker resolve o nome/preço pelo mapa.

**Para limpar e refazer o seed com preços atuais:**
```sql
DELETE FROM ultragaz_product_map;
-- Na próxima chamada POST /api/ultragaz/pedido, o seed automático recria
```

---

## 🧾 Mapa de Pagamentos Hub → MoskoGás

| Hub envia | Sistema recebe |
|-----------|---------------|
| `dinheiro` / `cash` | `dinheiro` |
| `débito` / `debito` | `debito` |
| `crédito` / `credito` | `credito` |
| `pix` | `pix_vista` |
| `mensali` | `mensalista` |
| `vale gás` / `parceria` / `boleto` / `orgão` | `boleto_orgao` |
| `vale_gas` / `voucher` | `vale_gas_ultragaz` |
| qualquer outro | `boleto_orgao` |

Label na gestão.html: `vale_gas_ultragaz` → `🟠 Vale UG`

---

## 🐛 Diagnóstico de Problemas

### Robô não conecta / não faz login
1. Verificar se `config.html → Ultragaz Hub` tem login/senha preenchidos
2. Clicar "Iniciar Login" no painel
3. Ver log: `pm2 logs ultragaz-robot`
4. Ver `GET /api/ultragaz/robot-log` — mostra URL, inputs encontrados na página de login

### Pedidos chegam mas sem produtos/preços
- Rodar: `DELETE FROM ultragaz_product_map;` no D1
- Na próxima vez que um pedido chegar, seed automático recria com preços do `app_products`

### WebSocket cai frequentemente
- Normal — o servidor do Hub fecha conexões ociosas a cada ~4min
- O robô faz ping a cada 3min50s e reconecta automaticamente com backoff exponencial

### Status mostra "desconectado" mesmo o robô rodando
- O heartbeat atualiza a cada 3min — aguardar até 3min após restart
- Verificar se o `.env` tem `MOSKOGAS_API_KEY` correto

---

## 📦 Instalação Limpa (se precisar reinstalar na VPS)

```bash
ssh root@IP_DA_VPS

# Atualizar código
cd /root
git clone https://ghp_TOKEN@github.com/luismosko/moskogas-app.git
cd moskogas-app/ultragaz-robot

# Dependências
npm install
npx playwright install chromium
npx playwright install-deps chromium

# .env
cp .env.example .env
nano .env   # preencher MOSKOGAS_API_KEY=Moskogas0909

# PM2
npm install -g pm2
pm2 start src/index.js --name ultragaz-robot
pm2 startup
pm2 save
```

---

---

## 🔔 Alerta no MoskoGás (shared.js + gestao.html)

> Esta seção documenta o lado **frontend** da integração — o alerta laranja que aparece em todas as telas quando chega um pedido do Hub.

### Como funciona

Um IIFE (função auto-executável isolada) injeta um loop de polling em **todas as páginas** do MoskoGás via `shared.js`. Não precisa de código extra em cada HTML — basta importar o shared.js.

```
shared.js (carregado em todas as páginas)
  └─ IIFE auto-inicia no DOMContentLoaded
       └─ startUltragazPolling(15000ms)
            └─ _checkUltragazAlerts() a cada 15s
                 └─ GET /api/orders/list?status=NOVO&limit=20
                      └─ filtra vendedor_nome === 'Ultragaz Hub'
                           └─ pedidos novos → _showUGBanner(order)
```

### Comportamento do Banner

- **Posição:** `position:fixed; top:0; z-index:999999` — empurra a página 52px para baixo
- **Visual:** fundo laranja pulsante (#ea580c), animação slide-in + shake no ícone
- **Conteúdo:** nome do cliente, produtos, total, endereço
- **Botões:** "✅ Ver na Gestão" + "×" fechar
- **Sons:** 3 beeps via AudioContext (440, 550, 660 Hz)
- **Auto-remove:** após 45 segundos
- **Anti-duplicata:** `Set` de sessão (`_ultragazSeen`) — não repete o mesmo pedido na mesma aba

### Botão "Ver na Gestão"

Redireciona para `gestao.html?ultragaz=1`

**O `?ultragaz=1` faz o gestao.html:**
1. Limpar o filtro de data (mostra pedidos de qualquer dia, não só hoje)
2. Ativar apenas o filtro de status `NOVO`
3. Exibir toast "Mostrando pedidos NOVO do Hub Ultragaz"

Sem esse comportamento, o pedido "sumia" da gestão porque o filtro padrão era "hoje" e pedidos antigos não apareciam.

### Variável global exposta

```javascript
window._ultragazGlobal = {
  start: startUltragazPolling,   // inicia polling
  check: _checkUltragazAlerts,   // força checagem imediata
  seen: _ultragazSeen             // Set com IDs já exibidos
}
```

---

### ⚠️ Bugs históricos corrigidos (para não repetir)

| # | Bug | Causa | Fix aplicado |
|---|-----|-------|-------------|
| 1 | Polling falhava silenciosamente | `apiCall()` não existe — função correta é `api()` | `shared.js` v1.24.0 |
| 2 | `data.orders` undefined | `orders/list` retorna array direto, não `{orders:[]}` | `Array.isArray(data) ? data : (data.orders \|\| [])` |
| 3 | "Ver na Gestão" abria e o pedido sumia | Filtro "Hoje" escondia pedidos do dia anterior | `?ultragaz=1` limpa filtro de data — `gestao.html` v2.9.13 |
| 4 | Pedidos não apareciam no filtro NOVO | `status='NOVO'` maiúsculo vs `activeStatuses.has('novo')` minúsculo | Normalizado para minúsculo no worker v2.49.40 |
| 5 | Items com nome/qty errados | Hub envia `{produto, quantidade}`, sistema esperava `{name, qty}` | Conversão automática no worker v2.49.41 |
| 6 | `boleto_orgao` inválido como pagamento | Hub envia nomes diferentes | Mapa de normalização `PG_MAP_HUB` no worker v2.49.42 |
| 7 | Preço R$0,00 nos itens | Hub não manda preço unitário | Busca no `app_products`; fallback distribuição proporcional — worker v2.49.43 |

---

### Regras importantes para NÃO quebrar

1. **NUNCA substituir `api()` por `apiCall()` ou `fetch()` direto** no IIFE do alerta — `api()` é a função do shared.js que já tem auth + base URL
2. **`orders/list` retorna array direto** — não tem wrapper `{orders: []}`. Sempre usar: `Array.isArray(data) ? data : (data.orders || [])`
3. **`?ultragaz=1` é obrigatório** no link "Ver na Gestão" — sem ele o atendente não vê o pedido
4. O IIFE usa `_ultragazSeen` (Set) para anti-duplicata — o Set se perde ao recarregar a página, mas isso é intencional (novo load = novo alerta se pedido ainda NOVO)

---

## 📋 Tabelas D1 Relacionadas

```sql
-- Pedidos recebidos do Hub
CREATE TABLE ultragaz_orders (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ultragaz_order_id TEXT UNIQUE NOT NULL,
  moskogas_order_id INTEGER,
  event_type TEXT,
  customer_name TEXT,
  address_line TEXT,
  items_json TEXT,
  total_value REAL,
  tipo_pagamento TEXT,
  raw_payload TEXT,
  status TEXT DEFAULT 'recebido',
  created_at INTEGER DEFAULT (unixepoch()),
  processed_at INTEGER
);

-- Mapa SKU Hub → Produto MoskoGás
CREATE TABLE ultragaz_product_map (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ultragaz_sku TEXT NOT NULL UNIQUE,   -- ex: 'P13', 'P20', 'P45', 'AGUA20L'
  moskogas_name TEXT NOT NULL,
  moskogas_product_id INTEGER,
  bling_id TEXT,
  price_override REAL,
  ativo INTEGER DEFAULT 1,
  created_at INTEGER DEFAULT (unixepoch()),
  updated_at INTEGER DEFAULT (unixepoch())
);
```
