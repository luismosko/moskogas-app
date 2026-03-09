# INSTRUÇÕES DO PROJETO — MoskoGás v7.0
> **Atualizado em:** 09/03/2026 | **Worker:** v2.49.43 | **shared.js:** v1.24.2

---

## 🔌 CONEXÃO NO INÍCIO DE CADA SESSÃO (OBRIGATÓRIO)

```bash
# 1. Tokens salvos em /mnt/project/Cloudflare_API_Token.txt
#    Cloudflare: ver /mnt/project/Cloudflare_API_Token.txt
#    GitHub:     ver /mnt/project/Cloudflare_API_Token.txt

# 2. Clonar repo (substituir GH_TOKEN pelo token do arquivo acima)
git clone https://GH_TOKEN@github.com/luismosko/moskogas-app.git
cd moskogas-app
git config user.email "luismosko@gmail.com"
git config user.name "Luis Mosko"

# 3. Se for trabalhar com Ultragaz/robô → ler primeiro:
cat ultragaz-robot/DOCUMENTACAO.md
```

> Tokens podem expirar — pedir novo ao Luis se clone falhar.  
> Deploy via **GitHub Actions automático** no push — nunca usar Quick Edit nem wrangler manual.

---

## ⚠️ REGRAS CRÍTICAS

### Versionamento (OBRIGATÓRIO)
- **HTML:** badge visível + `<title>` + `<h1>` — **3 LUGARES!**
- **worker.js:** comentário `// v2.X.Y` no topo
- **shared.js:** comentário `// v1.X.Y` no topo
- **NUNCA entregar sem versão atualizada**

### Infraestrutura (NÃO QUEBRAR)
```
Backend:    https://api.moskogas.com.br
Worker:     moskogas-backend-v2 (ES Module)
D1:         moskogas_ops — ID: 2c8c3bef-f365-45bd-88f6-bfa2ebecd7d5 — binding: DB
R2:         moskogas-comprovantes — binding: BUCKET
Frontend:   moskogas-app.pages.dev (GitHub Pages)
Repo:       github.com/luismosko/moskogas-app
CF Account: ae0dc6d28847a1ad468a236ca60c5f42
```

### Padrão requireAuth (NÃO ERRAR)
```javascript
// ✅ CORRETO
const authCheck = await requireAuth(request, env);
if (authCheck instanceof Response) return authCheck;
const user = authCheck;

// ❌ ERRADO — causa crash (requireAuth retorna objeto truthy no sucesso)
if (authErr) return authErr;
```

### ⚠️ Bindings Cloudflare
Nunca rodar `wrangler deploy` sem config correta. Se bindings sumirem:
Cloudflare → Workers → moskogas-backend-v2 → Bindings → Add:
- D1: `DB` = `moskogas_ops`
- R2: `BUCKET` = `moskogas-comprovantes`

### Cidade = Campo Grande/MS
NÃO exibir campos Cidade/UF. Hardcoded: `cidade="Campo Grande"`, `uf="MS"`.

---

## 🔐 AUTENTICAÇÃO

| Role | Acesso |
|------|--------|
| Admin | Total — todas as páginas |
| Gerente | Gestão ampla — sem acesso a usuários admin |
| Atendente | Pedidos, gestão, pagamentos, contratos, vales |
| Entregador | entregador.html apenas |

- Token JWT 24h em `localStorage` (`mg_session_token`, `mg_user`)
- Senhas: PBKDF2 100k iterações SHA-256
- Rate limit: 5 falhas/15min por IP
- Recuperação de senha: OTP 6 dígitos por WhatsApp+Email (15min)

---

## 🔄 STATUS DO PEDIDO

| Status | Cor | Significado |
|--------|-----|-------------|
| `novo` | 🔴 | Sem entregador |
| `encaminhado` | 🟡 | Entregador escolhido |
| `whats_enviado` | 🟢 | IzChat confirmou |
| `entregue` | 🔵 | Finalizado — cria Bling |
| `cancelado` | ⚪ | Cancelado — motivo obrigatório |

> **Bling só é criado ao marcar ENTREGUE** — nunca ao criar pedido.

---

## 📊 PAGAMENTOS

| Tipo | Cria Bling? | Pago? | Em Pagamentos? |
|------|-------------|-------|----------------|
| dinheiro / pix_vista / debito / credito | ✅ ao entregar | ✅ | ❌ |
| pix_receber | ✅ ao entregar | ❌ | ✅ |
| mensalista / boleto_orgao | ❌ só no lote | ❌ | ✅ |

---

## 🎨 REGRAS DE UX

1. **Modais NUNCA fecham ao clicar fora** — só X, Cancelar ou Salvar
2. **Toasts grandes** — fundo colorido, animação slide-in, 3s
3. **Versão visível** — badge em todas as páginas
4. **Foto obrigatória** na entrega (admin pode pular)
5. **Loading overlay** em toda ação assíncrona — `showLoading()`
6. **`orders/list` retorna array direto** — `Array.isArray(data) ? data : (data.orders || [])`

---

## 📁 ARQUIVOS E VERSÕES (09/03/2026)

| Arquivo | Versão | Função |
|---------|--------|--------|
| worker.js | **v2.49.43** | Backend principal |
| shared.js | **v1.24.2** | Auth, api(), toast, alerta Ultragaz |
| gestao.html | **v2.9.15** | Gestão de pedidos |
| pedido.html | v2.11.43 | Inserção de pedido |
| pagamentos.html | v1.9.14 | Pagamentos pendentes |
| config.html | v2.14.2 | Configurações + painel Ultragaz |
| entregador.html | v2.6.6 | Painel entregador |
| relatorio.html | v1.2.7 | Relatórios |
| usuarios.html | v1.6.1 | Gestão usuários |
| contratos.html | v1.1.8 | Contratos comodato + Assinafy |
| vales.html | v1.1.4 | Vale Gás |
| avaliacoes.html | v1.2.0 | Avaliações/satisfação |
| estoque.html | v1.2.2 | Controle de estoque |
| empenhos.html | v1.0.2 | Empenhos governamentais |
| dashboard.html | v1.0.2 | Dashboard |
| login.html | v1.3.0 | Login |
| nav.html | v1.1.0 | Navegação |
| teste-ultragaz.html | — | Simulador de pedido Hub (P13/P20/P45) |

---

## 🤖 INTEGRAÇÃO ULTRAGAZ HUB

> ⚠️ **O robô JÁ EXISTE e está COMPLETO. NÃO recriar, NÃO reescrever.**  
> Código em `ultragaz-robot/` — documentação completa em `ultragaz-robot/DOCUMENTACAO.md`

### Arquitetura Completa

```
Hub Ultragaz (portal web)
       │ Playwright (Chromium headless) — login automático
       │ Captura URL assinada do WebSocket AWS
       ▼
VPS DigitalOcean — Droplet ID: 555524687
  Node.js + PM2 → ultragaz-robot/src/index.js
       │ WebSocket em tempo real
       │ evento newOrder → GET_SELECTS (detalhes completos)
       │ varredura automática a cada 5min (abas: Em Aberto, Agendados, Andamento)
       ▼
POST https://api.moskogas.com.br/api/ultragaz/pedido
  Header: X-API-KEY: Moskogas0909
       │ Idempotência dupla: SQLite local (VPS) + D1 (worker)
       ▼
Cloudflare Worker — cria order: status='novo', vendedor_nome='Ultragaz Hub'
       ▼
shared.js — polling 15s em TODAS as telas
  → Alerta laranja fixo no topo + beep sonoro
  → Botão "Ver na Gestão" → gestao.html?ultragaz=1
```

### Arquivos do Robô (pasta `ultragaz-robot/`)

| Arquivo | Função |
|---------|--------|
| `src/index.js` | Orquestrador — loop principal, retry queue, graceful shutdown |
| `src/browser.js` | Login Playwright, captura URL WebSocket, varredura de abas |
| `src/websocket.js` | Conexão WS, listener de eventos, ping, heartbeat, scan periódico |
| `src/moskogas.js` | Envia pedido para API MoskoGás, mapeia produtos e pagamentos |
| `src/db.js` | SQLite local — idempotência e fila de retry |
| `src/imap-reader.js` | Lê código 2FA do Gmail via IMAP |
| `.env.example` | Template de variáveis |

### .env na VPS (`/root/moskogas-app/ultragaz-robot/.env`)

```env
MOSKOGAS_API_URL=https://api.moskogas.com.br
MOSKOGAS_API_KEY=Moskogas0909
SESSION_RENEWAL_MS=21600000    # 6 horas
GMAIL_USER=luismosko@gmail.com
GMAIL_APP_PASSWORD=xxxx xxxx xxxx xxxx
```

> Credenciais do Hub ficam no `config.html` — robô busca via `GET /api/ultragaz/config`.  
> **Nunca colocar login/senha do Hub no .env.**

### Comandos PM2 (SSH na VPS)

```bash
pm2 status                           # ver se está rodando
pm2 logs ultragaz-robot              # logs em tempo real
pm2 logs ultragaz-robot --lines 100  # últimas 100 linhas
pm2 restart ultragaz-robot           # reiniciar
pm2 start src/index.js --name ultragaz-robot  # iniciar do zero
```

### Fluxo de Inicialização do Robô

1. Busca credenciais: `GET /api/ultragaz/config`
2. Aguarda operador clicar **"Iniciar Login"** no `config.html` (polling `login-request`)
3. Playwright faz login no Hub (múltiplos seletores para robustez)
4. Se 2FA: aguarda `GET /api/ultragaz/2fa-code` (operador digita ou Gmail IMAP)
5. Captura URL assinada do WebSocket AWS
6. Conecta WS → processa eventos `newOrder` / `newOrderUG`
7. Varredura inicial de pedidos em aberto
8. Heartbeat a cada 3min → atualiza `hub-status` no D1
9. Renovação automática de sessão a cada 6h

### Endpoints Worker — Ultragaz

| Endpoint | Quem usa | Função |
|----------|----------|--------|
| `GET /api/ultragaz/config` | Robô | Busca credenciais do Hub |
| `POST /api/ultragaz/config` | Admin | Salva credenciais |
| `POST /api/ultragaz/start-login` | Admin (config.html) | Solicita login ao robô |
| `GET/DELETE /api/ultragaz/login-request` | Robô | Verifica/consome solicitação |
| `GET/POST/DELETE /api/ultragaz/2fa-code` | Robô / Admin | Código 2FA |
| `GET/POST /api/ultragaz/hub-status` | Robô / UI | Status de conexão |
| `POST /api/ultragaz/scan-orders` | Admin | Solicita varredura manual |
| `GET /api/ultragaz/scan-orders` | Robô | Verifica/consome solicitação |
| `GET/POST /api/ultragaz/robot-log` | Robô / Admin | Log de diagnóstico |
| **`POST /api/ultragaz/pedido`** | **Robô** | **Cria pedido no MoskoGás** |
| `GET /api/ultragaz/orders` | Admin | Lista pedidos recebidos |
| `GET/POST/DELETE /api/ultragaz/product-map` | Admin | Mapa SKU Hub → produto |

### Mapa de Produtos (`ultragaz_product_map`)

Robô envia SKU do Hub → worker resolve nome e preço pelo mapa.  
Seed automático na primeira chegada (busca preço em `app_products`).

```sql
-- Limpar para forçar re-seed com preços atuais:
DELETE FROM ultragaz_product_map;
```

### Mapa de Pagamentos Hub → MoskoGás

| Hub envia | Sistema recebe |
|-----------|---------------|
| `dinheiro` / `cash` | `dinheiro` |
| `débito` | `debito` |
| `crédito` | `credito` |
| `pix` | `pix_vista` |
| `mensali` | `mensalista` |
| `vale gás` / `parceria` / `boleto` / `orgão` | `boleto_orgao` |
| `vale_gas` / `voucher` | `vale_gas_ultragaz` → label `🟠 Vale UG` |
| outros | `boleto_orgao` (padrão) |

---

## 🔔 ALERTA ULTRAGAZ NO MOSKOGAS (shared.js + gestao.html)

### Como funciona

IIFE auto-executável no `shared.js` — ativa em **todas as páginas** automaticamente:

```
shared.js carregado → IIFE inicia no DOMContentLoaded
  └─ startUltragazPolling() — polling a cada 15s
       └─ GET /api/orders/list?status=NOVO&limit=20
            └─ filtra vendedor_nome === 'Ultragaz Hub'
                 └─ pedidos não vistos → _showUGBanner(order)
```

### Banner laranja

- `position:fixed; top:0; z-index:999999` — empurra página 52px
- Fundo `#ea580c` pulsante + animação slide-in + shake no ícone
- Conteúdo: nome do cliente · produtos · total · endereço
- 3 beeps via AudioContext (440 → 550 → 660 Hz)
- Auto-remove em 45s, botão X manual
- Anti-duplicata por `Set` de sessão (`_ultragazSeen`)

### Botão "Ver na Gestão" → `gestao.html?ultragaz=1`

O parâmetro `?ultragaz=1` é **obrigatório**. Sem ele o pedido "some":

| Sem `?ultragaz=1` | Com `?ultragaz=1` |
|-------------------|-------------------|
| Filtro "Hoje" ativo → pedido não aparece | Filtro de data removido |
| Todos os status | Só status NOVO |
| — | Toast "Mostrando pedidos NOVO do Hub Ultragaz" |

### Variável global

```javascript
window._ultragazGlobal = {
  start: startUltragazPolling,
  check: _checkUltragazAlerts,  // força checagem imediata
  seen:  _ultragazSeen           // Set de IDs já exibidos
}
```

### ⚠️ Bugs históricos — NÃO repetir

| # | Bug | Causa | Fix |
|---|-----|-------|-----|
| 1 | Polling silenciosamente quebrado | `apiCall()` não existe | Usar `api()` — shared.js v1.24.0 |
| 2 | `data.orders` undefined | `orders/list` retorna array, não `{orders:[]}` | `Array.isArray(data) ? data : (data.orders\|\|[])` |
| 3 | Pedido sumia ao abrir gestão | Filtro "Hoje" escondia pedidos | `?ultragaz=1` — gestao.html v2.9.13 |
| 4 | Pedidos não apareciam no filtro NOVO | `status='NOVO'` maiúsculo vs `.has('novo')` | Status minúsculo no worker v2.49.40 |
| 5 | Items com nome/qty errados | Hub envia `{produto,quantidade}`, sistema esperava `{name,qty}` | Conversão no worker v2.49.41 |
| 6 | Forma de pagamento inválida | Hub envia nomes livres | `PG_MAP_HUB` no worker v2.49.42 |
| 7 | Preço R$0,00 | Hub não manda preço unitário | Busca `app_products` + proporcional — v2.49.43 |

### Regras absolutas para o alerta

1. **NUNCA** usar `apiCall()` ou `fetch()` direto no IIFE — somente `api()`
2. **SEMPRE** tratar retorno: `Array.isArray(data) ? data : (data.orders || [])`
3. **SEMPRE** usar `?ultragaz=1` no link "Ver na Gestão"
4. O `_ultragazSeen` se perde ao recarregar — intencional (novo alerta se pedido ainda NOVO)

---

## 🐛 DIAGNÓSTICO ULTRAGAZ

### Robô não inicia login
1. `config.html → Ultragaz Hub` — verificar se login/senha preenchidos
2. Clicar "Iniciar Login" no painel
3. `pm2 logs ultragaz-robot` na VPS
4. `GET /api/ultragaz/robot-log` — mostra URL e inputs da página de login

### Pedidos chegam sem preços
```sql
DELETE FROM ultragaz_product_map;  -- seed automático na próxima chegada
```

### WebSocket cai constantemente
- Normal — Hub fecha ociosas em ~4min. Robô reconecta com backoff exponencial.

### Status "desconectado" mesmo rodando
- Heartbeat a cada 3min — aguardar até 3min após restart
- Verificar `MOSKOGAS_API_KEY` no `.env` da VPS

### Alerta não aparece no browser
- Verificar console do browser — `window._ultragazGlobal` deve existir
- Confirmar que `shared.js` v1.24.2+ está sendo carregado
- Testar manualmente: `window._ultragazGlobal.check()`
- Usar `teste-ultragaz.html` para disparar pedido de teste

---

## 📋 REGRAS GERAIS — ERROS CONHECIDOS

1. `/nfce` ou `/nfces` → NÃO EXISTE na API Bling v3
2. Versão em 1 lugar → obrigatório 3 lugares (title, h1, badge)
3. `apiCall()` → não existe, usar `api()`
4. `pedido_numero` → usar `bling_pedido_id`
5. Modal fecha ao clicar fora → usar padrão shared.js
6. `if (authErr) return authErr` → usar `if (authCheck instanceof Response) return authCheck`
7. Chamar IzChat diretamente → SEMPRE `sendWhatsApp(env, to, msg, { category })`
8. Enviar WhatsApp sem category → SEMPRE passar `{ category: 'xxx' }`
9. `wrangler.jsonc` com nome errado → sempre `moskogas-backend-v2`
10. Quick Edit no Cloudflare → diverge do GitHub, pode apagar bindings

---

## 🚀 WORKFLOW DE DEPLOY

```bash
# 1. Editar arquivos (sempre incrementar versão)
# 2. Commitar e fazer push
git add .
git commit -m "feat: descrição v2.X.Y"
git push

# 3. GitHub Actions faz deploy automático
# 4. Verificar badge de versão na página
# 5. Salvar cópia em /mnt/user-data/outputs/ se worker.js foi alterado
```

### wrangler.jsonc (NÃO ALTERAR)
```json
{
  "name": "moskogas-backend-v2",
  "main": "worker.js",
  "compatibility_date": "2025-09-27",
  "compatibility_flags": ["nodejs_compat"],
  "d1_databases": [{ "binding": "DB", "database_name": "moskogas_ops", "database_id": "2c8c3bef-f365-45bd-88f6-bfa2ebecd7d5" }],
  "r2_buckets": [{ "binding": "BUCKET", "bucket_name": "moskogas-comprovantes" }]
}
```

---

## 📌 REFERÊNCIAS RÁPIDAS

| O que precisa | Onde está |
|---------------|-----------|
| Documentação robô Ultragaz (completa) | `ultragaz-robot/DOCUMENTACAO.md` |
| Instruções gerais do projeto | `INSTRUCOES_PROJETO_v7.md` (este arquivo) |
| Tokens Cloudflare + GitHub | `/mnt/project/Cloudflare_API_Token.txt` |
| Status da VPS | cloud.digitalocean.com/droplets/555524687 |
| Painel Ultragaz Hub | config.html → seção Ultragaz Hub |
| Teste de pedido simulado | `moskogas-app.pages.dev/teste-ultragaz.html` |
