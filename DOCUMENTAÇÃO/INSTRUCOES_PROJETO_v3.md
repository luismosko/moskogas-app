# INSTRUÇÕES DO PROJETO — MoskoGás v3.0

## Objetivo
Sistema web ultra-rápido para gestão de pedidos de gás/água integrando Bling ERP + Cloudflare Worker/D1/R2 + IzChat (WhatsApp).

**Prioridade absoluta:** Velocidade operacional (15-30s por pedido), poucos cliques, UX para atendente.

---

## ⚠️ REGRAS CRÍTICAS

### Versionamento (OBRIGATÓRIO)
**SEMPRE incrementar versão em TODO arquivo editado:**
- HTML: badge visível + `<title>` + `<h1>` (3 LUGARES!)
- JS (worker.js): comentário `// v2.X.Y` no topo
- shared.js: comentário `// v1.X.Y` no topo
- **NUNCA entregar sem versão atualizada**

### Infraestrutura (NÃO QUEBRAR)
```
Backend: https://api.moskogas.com.br
Worker: moskogas-backend-v2 (ES Module)
D1: moskogas_ops (binding DB)
R2: moskogas-comprovantes (binding BUCKET)
Frontend: moskogas-app.pages.dev (GitHub Pages)
Repo: github.com/luismosko/moskogas-app
```

### Git Push
- Claude faz push direto via HTTPS+token (ghp_xxx)
- Token solicitado no INÍCIO de cada sessão
- Sempre salvar também em /mnt/user-data/outputs/

### Secrets Cloudflare
`BLING_CLIENT_ID`, `BLING_CLIENT_SECRET`, `IZCHAT_TOKEN`, `APP_API_KEY`, `JWT_SECRET`

### Cidade = Campo Grande/MS (SEMPRE)
- NÃO exibir campos Cidade/UF na UI
- Hardcoded: cidade="Campo Grande", uf="MS"

---

## 🔐 AUTENTICAÇÃO (v3.0)

### Roles
| Role | Acesso | Páginas |
|------|--------|---------|
| Admin | Total | Todas + usuarios.html |
| Operador | Pedidos/gestão | pedido, gestao, pagamentos, relatorio, config |
| Entregador | Entregas | entregador.html |

### Fluxo
- `index.html` → verifica token → redirect por role ou login
- JWT (24h) salvo em localStorage (`mg_session_token`, `mg_user`)
- `shared.js` gerencia auth em todas as páginas
- Worker valida JWT em todos endpoints (exceto /auth/login, /health, /api/pub/*)

---

## 📊 SISTEMA DE PAGAMENTOS

| Tipo | Cria Bling? | Marca Pago? | Em Pagamentos? |
|------|-------------|-------------|----------------|
| 💵 Dinheiro | ✅ | ✅ | ❌ |
| ⚡ PIX à vista | ✅ | ✅ | ❌ |
| ⏳ PIX a receber | ✅ | ❌ | ✅ |
| 📅 Mensalista | ❌ | ❌ | ✅ |
| 🧾 Boleto/Órgão | ❌ | ❌ | ✅ |

### Lógica
```javascript
const criarBling = ['dinheiro', 'pix_vista', 'pix_receber'].includes(tipo_pagamento);
const pago = ['dinheiro', 'pix_vista'].includes(tipo_pagamento) ? 1 : 0;
```

### PATCH /api/pagamentos/:id
Se pedido não tem `bling_pedido_id`, cria venda no Bling ANTES de marcar pago=1.

### NFCe
**NÃO tem endpoint direto na API Bling v3.** Emissão em lote no painel Bling.

---

## 🔄 STATUS DO PEDIDO

| Status | Cor | Significado |
|--------|-----|-------------|
| NOVO | 🔴 Vermelho | Sem entregador |
| ENCAMINHADO | 🟡 Amarelo | Entregador escolhido |
| WHATS ENVIADO | 🟢 Verde | IzChat confirmou |
| ENTREGUE | 🔵 Azul | Finalizado |
| CANCELADO | ⚪ Cinza | Cancelado |

**Sem restrição de status:** editar pedido e trocar entregador funciona em qualquer status.

---

## 📁 ARQUIVOS E VERSÕES (17/02/2026)

| Arquivo | Versão | Função |
|---------|--------|--------|
| pedido.html | v2.7.4 | Inserção de pedido |
| gestao.html | v2.5 | Gestão + resumo produtos |
| pagamentos.html | v1.3.0 | Pagamentos pendentes |
| config.html | v2.2.0 | Ruas, bairros, produtos |
| relatorio.html | v1.1.0 | Relatórios |
| entregador.html | s/v | Painel entregador |
| print.html | s/v | Recibo A4 (2 vias) |
| login.html | v1.0.0 | Login |
| index.html | - | Redirect por role |
| usuarios.html | v1.2.0 | Gestão usuários (admin) |
| shared.js | v1.3.0 | Utilitários (auth, api, toast) |
| worker.js | v2.8.0+ | Backend (wrangler deploy) |

---

## 🗄️ SCHEMA D1

### `orders`
```sql
id, phone_digits, customer_name, address_line, bairro,
complemento, referencia, items_json, total_value, notes,
status, sync_status, driver_name_cache, created_at,
bling_pedido_id, bling_pedido_num,
tipo_pagamento TEXT, pago INTEGER DEFAULT 0, vendedor TEXT
```

### `customers_cache`
```sql
phone_digits PRIMARY KEY, name, address_line, bairro,
complemento, referencia, bling_contact_id
```

### `users`
```sql
id, username UNIQUE, password_hash, display_name,
role (admin/operador/entregador), active, created_at
```

### `bling_tokens`
```sql
id=1, access_token, refresh_token, expires_in, obtained_at
```

---

## 🔌 BLING API v3

Base: `https://www.bling.com.br/Api/v3`
Docs: https://developer.bling.com.br/home
Auth: OAuth 2.0 | Headers: `Authorization: Bearer {token}`, `enable-jwt: 1`

### IDs
- Consumidor Final: `726746364`
- Dinheiro: 23368 | PIX: 23465 | Débito: 23369 | Crédito: 23370 | Fiado: 23373

### Token
Refresh automático via cron `0 */5 * * *`. Check silencioso a cada 60s no pedido.html com auto-recovery.

---

## 📱 IZCHAT (WhatsApp)
```javascript
POST /izchat/notificar-entrega
{ order_id, driver_phone, message, observacao }
```

---

## 🎨 REGRAS DE UX (SEMPRE SEGUIR)

1. **Modais NUNCA fecham ao clicar fora** — Só por X, Cancelar ou Salvar
2. **Toasts grandes** — Fundo colorido, animação slide-in, duração 3s
3. **Tooltips** — title em todos botões de ação
4. **Redirect** — Após salvar pedido → gestao.html (1.2s delay)
5. **Consumidor Final** — Sem endereço obrigatório na edição
6. **Versão visível** — Badge em todas as páginas
7. **Cidade hardcoded** — Sem campos cidade/UF

---

## ❌ ERROS CONHECIDOS (NÃO REPETIR)

1. Usar `/nfce` ou `/nfces` → NÃO EXISTE
2. Esquecer versão → Atualizar nos 3 LUGARES
3. Usar `pedido_numero` ao invés de `bling_pedido_id`
4. Criar webhook de NFCe → Complexidade desnecessária
5. Form reset sem null check → `if (el) el.value = ''`
6. Modal fecha ao clicar fora → Usar shared.js
7. Token Bling sem recovery → Check silencioso
8. Sem parseInt/parseFloat → items_json pode ter strings
9. Versão em 1 lugar só → 3 lugares (title, h1, badge)

---

## 🚀 WORKFLOW DE DEPLOY

1. Incrementar versão em TODOS arquivos editados
2. Testar: `wrangler dev` | Live Server
3. Deploy worker: `wrangler deploy`
4. Git push HTMLs (Claude via HTTPS+token)
5. Verificar versão no badge

---

## 📋 ENDPOINTS COMPLETOS

### Autenticação
- POST /auth/login | POST /auth/logout | GET /auth/me
- GET /usuarios | POST /usuarios | PATCH /usuarios/:id

### Pedidos
- POST /api/order/create | GET /api/orders
- PATCH /api/order/:id/update | /status | /select-driver | /cancel

### Pagamentos
- GET /api/pagamentos | PATCH /api/pagamentos/:id
- POST /api/pagamentos/gerar-nfe

### Bling & IzChat
- GET /bling/oauth/start | /callback | /ping
- GET /api/bling/diagnostico
- POST /izchat/notificar-entrega | GET /izchat/teste

### Clientes & Config
- GET /api/customers/search?phone= | /drivers | /products | /streets
- POST /api/streets/import
