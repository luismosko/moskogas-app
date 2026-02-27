# INSTRUÇÕES DO PROJETO — MoskoGás v4.0
> **Atualizado em:** 24/02/2026 | **Worker:** v2.38.2

## Objetivo
Sistema web ultra-rápido para gestão de pedidos de gás/água integrando Bling ERP + Cloudflare Worker/D1/R2 + IzChat (WhatsApp) + Backup Google Drive + Relatório diário por E-mail.

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

Backup: https://moskogas-backup.luismosko.workers.dev
Worker Backup: moskogas-backup (separado)
Google Drive: luismosko@gmail.com → pasta "MoskoGás Backup"
```

### Git Push
- Claude faz push direto via HTTPS+token (ghp_xxx)
- Token solicitado no INÍCIO de cada sessão
- Sempre salvar também em /mnt/user-data/outputs/
- **SEMPRE incluir worker.js no push do GitHub**

### Secrets Cloudflare
**Worker principal:** `BLING_CLIENT_ID`, `BLING_CLIENT_SECRET`, `IZCHAT_TOKEN`, `APP_API_KEY`, `JWT_SECRET`, `PUSHINPAY_TOKEN`, `RESEND_API_KEY`
**Worker backup:** `GDRIVE_CLIENT_ID`, `GDRIVE_CLIENT_SECRET`, `APP_API_KEY`

### Cidade = Campo Grande/MS (SEMPRE)
- NÃO exibir campos Cidade/UF na UI
- Hardcoded: cidade="Campo Grande", uf="MS"

---

## 🔐 AUTENTICAÇÃO

### Roles
| Role | Acesso | Páginas |
|------|--------|---------|
| Admin | Total | Todas + usuarios.html + config permissões |
| Atendente | Pedidos/gestão | pedido, gestao, pagamentos, relatorio, config, dashboard, consulta, contratos |
| Entregador | Entregas | entregador.html |

### Fluxo
- `index.html` → verifica token → redirect por role ou login
- Token de sessão (24h) salvo em localStorage (`mg_session_token`, `mg_user`)
- `shared.js` gerencia auth em todas as páginas
- Worker valida sessão em todos endpoints (exceto /api/auth/login, /health, /api/pub/*, /api/relatorio/*)

### Segurança
- Senhas com PBKDF2 (100k iterações, SHA-256)
- Rate limiting: 5 falhas login/15min por IP = bloqueio
- Desativar usuário invalida sessões imediatamente
- API key como fallback admin (setup inicial)
- Permissões dinâmicas via `app_config`
- Troca de senha: PATCH /api/auth/me/senha (todos os roles)
- Atendente pode criar/editar atendentes e entregadores, mas NÃO admins

---

## 📊 SISTEMA DE PAGAMENTOS

| Tipo | Cria Bling? | Marca Pago? | Em Pagamentos? |
|------|-------------|-------------|----------------|
| 💵 Dinheiro | ✅ (ao entregar) | ✅ | ❌ |
| ⚡ PIX à vista | ✅ (ao entregar) | ✅ | ❌ |
| ⏳ PIX a receber | ✅ (ao entregar) | ❌ | ✅ |
| 💳 Débito | ✅ (ao entregar) | ✅ | ❌ |
| 💳 Crédito | ✅ (ao entregar) | ✅ | ❌ |
| 📅 Mensalista | ❌ (só no lote) | ❌ | ✅ |
| 🧾 Boleto/Órgão | ❌ (só no lote) | ❌ | ✅ |

### Lógica
**Bling só é criado ao marcar ENTREGUE** (nunca ao criar pedido).
```javascript
const criarBling = ['dinheiro', 'pix_vista', 'pix_receber', 'debito', 'credito'].includes(tipo);
const pago = ['dinheiro', 'pix_vista', 'debito', 'credito'].includes(tipo) ? 1 : 0;
```

---

## 💳 PIX PUSHINPAY (v2.34.0+)

Substituiu o sistema Cora PIX.

- **API:** `https://api.pushinpay.com.br`
- **Secret:** `PUSHINPAY_TOKEN` no Cloudflare
- **Endpoints:**
  - `POST /api/pix/cashIn` → gera QR Code + link pagamento
  - `POST /api/pix/webhook` → recebe confirmação de pagamento automática
- **Fluxo:** Criar cobrança → enviar QR por WhatsApp → webhook confirma → marca pago automaticamente

---

## 📧 RELATÓRIO DIÁRIO POR E-MAIL (v2.29.0)

### Configuração
- Acesse **config.html → Relatório Diário por E-mail**
- **Resend API** (resend.com) para envio
- Secret: `RESEND_API_KEY` no Cloudflare (ou salvo em app_config)

### Funcionalidades
- Resumo HTML dos pedidos do dia anterior
- CSV anexo com todos os pedidos
- Opção de incluir/excluir cancelados
- Cron configurável (padrão 03:00 BRT / 06:00 UTC)
- Múltiplos e-mails de destino (um por linha)
- Botão "Enviar Teste (Ontem)" para teste imediato

### Endpoints
- `GET /api/relatorio/email-config` — config atual (admin)
- `POST /api/relatorio/email-config` — salvar config (admin)
- `POST /api/relatorio/enviar-teste` — envio manual imediato

---

## 🔄 STATUS DO PEDIDO

| Status | Cor | Significado |
|--------|-----|-------------|
| NOVO | 🔴 Vermelho | Sem entregador |
| ENCAMINHADO | 🟡 Amarelo | Entregador escolhido |
| WHATS ENVIADO | 🟢 Verde | IzChat confirmou |
| ENTREGUE | 🔵 Azul | Finalizado (cria Bling, exige foto) |
| CANCELADO | ⚪ Cinza | Cancelado (motivo obrigatório) |

**Sem restrição rígida:** editar, trocar entregador e reverter funciona em qualquer status.
Cancelar/reverter exigem motivo + log de auditoria.
Cancelamento pós-entrega e reversões por não-admin → alerta WhatsApp ao admin.

---

## 📱 WHATSAPP SAFETY LAYER (v2.27.0) — ⚠️ OBRIGATÓRIO

### Regra Fundamental
**TODA mensagem WhatsApp do sistema DEVE passar por `sendWhatsApp()` com category.**
NUNCA chamar `fetch()` diretamente para a API IzChat.

```javascript
// ✅ CORRETO
await sendWhatsApp(env, to, message, { category: 'entrega' });

// ❌ PROIBIDO
await fetch('https://chatapi.izchat.com.br/api/messages/send', ...);
```

### 6 Barreiras de Proteção
| # | Barreira | Default |
|---|----------|---------|
| 1 | Circuit Breaker | 30min pausa se 429/bloqueio |
| 2 | Horário Comercial | 8h-18h BRT |
| 3 | Rate Limit Global | 25/min, 100/h, 200/dia |
| 4 | Intervalo entre msgs | 4 segundos |
| 5 | Cooldown por número | 12h entre lembretes |
| 6 | Variação de mensagem | Auto em lembretes |

### Categorias
| Categoria | Safety? | Onde usa |
|-----------|---------|---------|
| `entrega` | ✅ normal | Notificação ao entregador |
| `lembrete_pix` | ✅ + cooldown + variação | Cobrança PIX |
| `contrato` | ✅ normal | Assinatura comodato |
| `admin_alerta` | ❌ skipSafety | Alertas cancelamento/reversão |
| `teste` | ❌ skipSafety | Endpoint de teste |

---

## 📲 LEMBRETES PIX (v2.26.0+)

### Envio
- Manual por pedido (botão 📱 na tela pagamentos)
- Bulk: selecionar vários → "📱 Enviar Lembretes"
- Cron: automático diário (configurável)

### Melhorias v2.28.1
- Saudação variada (bom dia/boa tarde/boa noite)
- Suporte a `{ontem}` e `{chave_pix}` no template
- Delay 60s anti-ban entre envios

### Endpoints
- GET/POST /api/lembretes/config
- POST /api/lembretes/enviar/:orderId
- POST /api/lembretes/enviar-bulk
- GET /api/lembretes/pedido/:orderId
- GET /api/lembretes/pendentes

---

## 🔌 VENDA EXTERNA (v2.30.0)

Entregador pode criar + entregar pedido em 1 passo pelo app entregador.html.
- Ideal para vendas presenciais sem atendente
- Cria o pedido e já marca como entregue com foto
- Cria venda no Bling automaticamente

---

## ⭐ QR CODE AVALIAÇÃO GOOGLE (v2.30.0)

- Endpoint `GET /api/pub/qr-avaliacao` → retorna QR code SVG público
- Configurável via `app_config key: google_review_url`
- Exibido na tela do entregador após entrega confirmada

---

## 📋 CONTRATOS COMODATO (v2.25.0)

### Fluxo
1. Criar contrato (draft)
2. Gerar PDF a partir do template HTML configurável
3. Upload para Assinafy → URLs de assinatura
4. Enviar links por WhatsApp para signatários
5. Receber webhooks (document_uploaded, signer_signed, document_ready)
6. Baixar PDF assinado → salvar no R2

### Status: draft → pending_signatures → signed | canceled

### Integração Assinafy
- API: https://api.assinafy.com.br/v1
- Fix v2.28.5: reusa signer existente se e-mail já cadastrado

### Endpoints
- GET/POST /api/contratos
- GET/PATCH /api/contratos/:id
- POST /api/contratos/:id/gerar-pdf | /enviar-assinafy | /reenviar-whatsapp | /cancelar
- GET/POST /api/contratos/config
- POST /api/webhooks/assinatura

---

## 👥 IMPORTAÇÃO GLP MASTER (24/02/2026)

### O que foi feito
- **15.981 clientes** importados do banco PostgreSQL do GLP Master para `customers_cache`
- Telefones normalizados para formato internacional `5567XXXXXXXXX`
- Inseridos os campos novos `ultima_compra_glp` e `origem`
- **313 endereços** da PREFEITURA SAS (66) e SEMED (247) importados para `customer_addresses`

### Normalização de telefones
```
(67) 9555-3333  → 8 dígitos após DDD → inserir 9 → 5567995553333
(67) 99555-3333 → 11 dígitos → ok   → 5567995553333
Sem telefone ou inválido → descartado
```

### Descartados
- 672 sem telefone
- 90 com telefone inválido (< 10 dígitos)

### Campos adicionados em customers_cache
- `ultima_compra_glp TEXT` — data da última compra no GLP Master
- `origem TEXT DEFAULT 'manual'` — valores: 'manual', 'glp_master', 'bling'

### SEMED
- Telefone placeholder: `5567999000001` (corrigir para o real quando disponível)
- 247 unidades/escolas cadastradas como endereços alternativos

### Uso futuro
- Filtrar clientes inativos (sem compra há X dias) para campanhas WhatsApp
- Campo `ultima_compra_glp` como base para reativação de clientes

---

## 📁 ARQUIVOS E VERSÕES (24/02/2026)

| Arquivo | Versão | Função |
|---------|--------|--------|
| pedido.html | v2.11.4 | Inserção de pedido |
| gestao.html | v2.9.0 | Gestão + resumo produtos |
| pagamentos.html | v1.9.6 | Pagamentos pendentes + lembretes PIX |
| config.html | v2.11.3 | Ruas, bairros, produtos, permissões, lembretes, contratos, relatório e-mail |
| contratos.html | v1.1.8 | Contratos comodato + Assinafy |
| relatorio.html | v1.2.3 | Relatórios |
| entregador.html | v2.6.3 | Painel entregador (foto obrigatória + venda externa) |
| dashboard.html | v1.0.1 | Dashboard visual (KPIs, gráficos) |
| consulta-pedidos.html | v1.0.7 | Consulta avançada de pedidos |
| auditoria.html | v1.1.0 | Auditoria Bling + logs |
| login.html | v1.2.0 | Login |
| usuarios.html | v1.4.1 | Gestão usuários (admin) |
| nav.html | v1.0.0 | Template de navegação |
| shared.js | v1.10.0 | Utilitários (auth, api, toast, nav, loading) |
| worker.js | v2.38.2 | Backend (wrangler deploy) |
| backup-worker.js | v1.1.0 | Backup Google Drive (worker separado) |
| print.html | s/v | Recibo A4 (2 vias) |
| index.html | — | Redirect por role |

---

## 🗄️ SCHEMA D1

### `orders`
```sql
id, phone_digits, customer_name, address_line, bairro,
complemento, referencia, items_json, total_value, notes,
status, sync_status, driver_id, driver_name_cache, driver_phone_cache,
created_at INTEGER (unixepoch), delivered_at, canceled_at, updated_at,
bling_pedido_id, bling_pedido_num,
tipo_pagamento TEXT, pago INTEGER DEFAULT 0,
vendedor_id INTEGER, vendedor_nome TEXT,
forma_pagamento_key TEXT, forma_pagamento_id INTEGER,
foto_comprovante TEXT, observacao_entregador TEXT,
tipo_pagamento_original TEXT, cancel_motivo TEXT
```

### `app_users`
```sql
id, nome, login UNIQUE, senha_hash, senha_salt,
role (admin/atendente/entregador),
bling_vendedor_id, bling_vendedor_nome, telefone,
pode_entregar INTEGER, recebe_whatsapp INTEGER,
ativo INTEGER DEFAULT 1, created_at, updated_at
```

### `customers_cache`
```sql
phone_digits PRIMARY KEY, name, address_line, bairro,
complemento, referencia, bling_contact_id, cpf_cnpj,
email, email_nfe, tipo_pessoa, updated_at,
ultima_compra_glp TEXT DEFAULT '',   -- ← NOVO (v2.38.2)
origem TEXT DEFAULT 'manual'         -- ← NOVO (v2.38.2) valores: manual|glp_master|bling
```

### `customer_addresses`
```sql
id, phone_digits, obs, address_line, bairro, complemento, referencia, created_at
```

### `contracts` (v2.25.0)
```sql
id, numero UNIQUE, status, tipo_pessoa, razao_social, cnpj_cpf,
endereco, cidade, uf, cep,
responsavel_nome, responsavel_cpf, responsavel_email, responsavel_telefone,
itens_json, comodante_snapshot, testemunhas_snapshot, template_html,
generated_pdf_key, signed_pdf_key,
assinafy_doc_id, assinafy_assignment_id, assinafy_error,
created_by, created_by_nome, created_at, updated_at, signed_at, canceled_at, cancel_motivo
```

### `contract_signers` (v2.25.0)
```sql
id, contract_id FK, role, nome, cpf, telefone, email,
assinafy_signer_id, signing_url, signed_at, status, whatsapp_sent_at, reject_reason
```

### `payment_reminders` (v2.26.0)
```sql
id, order_id, tipo (manual/auto), phone_sent, sent_at, sent_by, sent_by_nome,
whatsapp_ok INTEGER, whatsapp_detail TEXT
```

### `whatsapp_send_log` (v2.27.0)
```sql
id, phone TEXT, category TEXT, status_code INTEGER, wa_ok INTEGER,
blocked INTEGER, created_at INTEGER
```

### `app_products` (v2.24.0)
```sql
id, bling_id, name, code, price REAL, is_favorite INTEGER, sort_order,
ativo INTEGER, icon_key TEXT, created_at, updated_at
```

### `app_config`
```sql
key TEXT PRIMARY KEY, value TEXT, updated_at TEXT
-- Chaves relevantes:
-- relatorio_email (JSON: ativo, destinos, hora_utc, incluir_csv, incluir_cancelados)
-- resend_api_key
-- lembrete_pix (JSON: ativo, intervalo_horas, max_lembretes, cron_ativo, cron_hora_utc, mensagem)
-- google_review_url
-- permissoes (JSON)
-- contrato_comodante_* (dados do comodante)
```

### Outras tabelas
`auth_sessions`, `bling_tokens`, `streets_cg`, `products`, `product_favorites`,
`integration_audit`, `order_status_log`, `audit_snapshots`, `order_events`,
`login_attempts`, `contract_attachments`, `contract_events`

---

## 📌 BLING API v3

Base: `https://www.bling.com.br/Api/v3`
Auth: OAuth 2.0 | Headers: `Authorization: Bearer {token}`, `enable-jwt: 1`

### IDs
- Consumidor Final: `726746364`
- Dinheiro: 23368 | PIX Bradesco: 3138153 | PIX ITAU: 9052024 | PIX Aguardando: 9315924
- Débito: 188552 | Crédito: 188555 | Duplicata (Fiado): 188534

### Token
Refresh automático via cron `0 */5 * * *`. Check silencioso a cada 60s no pedido.html.

---

## 📱 IZCHAT (WhatsApp)
```
POST https://chatapi.izchat.com.br/api/messages/send
Headers: Authorization: Bearer {IZCHAT_TOKEN}
Body: { number: "5567999999999", body: "texto" }
```
⚠️ **SEMPRE usar `sendWhatsApp(env, to, msg, { category })` — NUNCA fetch direto!**

---

## 💾 BACKUP GOOGLE DRIVE

| Item | Valor |
|------|-------|
| Worker | moskogas-backup (separado) |
| URL | https://moskogas-backup.luismosko.workers.dev |
| Cron | 06:00 UTC (03:00 BRT) diário |
| Pasta Drive | MoskoGás Backup |
| Retenção | 180 dias |

### O que exporta
- 12 tabelas D1: orders, customers_cache, customer_addresses, app_users, app_config, order_events, order_status_log, integration_audit, audit_snapshots, bling_tokens, streets_cg, products
- Fotos R2: todas com prefixo `comprovantes/`

### Endpoints
- GET /google/auth — autorizar (1x)
- GET /google/status — verificar autorização
- GET /backup/executar — forçar manual (requer API key header)
- GET /backup/status — último backup

---

## 🎨 REGRAS DE UX (SEMPRE SEGUIR)

1. **Modais NUNCA fecham ao clicar fora** — Só por X, Cancelar ou Salvar
2. **Toasts grandes** — Fundo colorido, animação slide-in, duração 3s
3. **Tooltips** — title em todos botões de ação
4. **Redirect** — Após salvar pedido → gestao.html (1.2s delay)
5. **Consumidor Final** — Sem endereço obrigatório na edição
6. **Versão visível** — Badge em todas as páginas
7. **Cidade hardcoded** — Sem campos cidade/UF
8. **Foto obrigatória** — Entregador precisa de foto (admin pode pular)
9. **Formato foto** — WebP 1200px 85% quality + sharpen
10. **Check Bling** — Silencioso a cada 60s com auto-recovery
11. **Loading overlay** — showLoading() em TODA ação assíncrona
12. **Botão X** — Todos os modais devem ter botão X no canto

---

## ❌ ERROS CONHECIDOS (NÃO REPETIR)

1. Usar `/nfce` ou `/nfces` → NÃO EXISTE na API Bling v3
2. Esquecer versão → Atualizar nos 3 LUGARES
3. Usar `pedido_numero` ao invés de `bling_pedido_id`
4. Form reset sem null check → `if (el) el.value = ''`
5. Modal fecha ao clicar fora → Usar shared.js
6. Token Bling sem recovery → Check silencioso
7. Sem parseInt/parseFloat → items_json pode ter strings
8. Versão em 1 lugar só → 3 lugares (title, h1, badge)
9. Endpoints users sem auth → Usar requireAuth(['admin'])
10. Comparar created_at (epoch) com string → Usar epoch com offset BRT (-04:00)
11. Service Account Google em conta gratuita → Usar OAuth pessoal
12. **Chamar API IzChat diretamente → SEMPRE usar sendWhatsApp() com Safety Layer**
13. **Enviar WhatsApp sem category → SEMPRE passar { category: 'xxx' }**
14. **Loop de envio sem verificar blocked → SEMPRE checar result.blocked e parar se true**
15. RESEND_API_KEY não funciona como secret → Salvar também via POST /api/relatorio/email-config

---

## 📋 ENDPOINTS COMPLETOS

### Autenticação
- POST /api/auth/login | /logout | GET /api/auth/session
- PATCH /api/auth/me/senha
- GET /api/auth/users | POST /api/auth/users
- PATCH /api/auth/users/:id

### Pedidos
- POST /api/order/create | GET /api/orders/list
- POST /api/order/:id/update | /select-driver | /send-whatsapp
- POST /api/order/:id/mark-delivered | /cancel | /revert-status
- GET /api/order/:id | /api/order/:id/status-log

### Pagamentos
- GET /api/pagamentos | PATCH /api/pagamentos/:id
- POST /api/pagamentos/criar-vendas-bling

### PIX PushInPay (v2.34.0)
- POST /api/pix/cashIn — criar cobrança PIX
- POST /api/pix/webhook — receber confirmação (público)

### Relatório por E-mail (v2.29.0)
- GET/POST /api/relatorio/email-config
- POST /api/relatorio/enviar-teste

### Lembretes PIX (v2.26.0)
- GET/POST /api/lembretes/config
- POST /api/lembretes/enviar/:orderId | /enviar-bulk
- GET /api/lembretes/pedido/:orderId | /pendentes

### WhatsApp Safety
- GET/POST /api/whatsapp/safety-config
- GET /api/whatsapp/stats

### Contratos Comodato
- GET/POST /api/contratos
- GET/PATCH /api/contratos/:id
- POST /api/contratos/:id/gerar-pdf | /enviar-assinafy | /reenviar-whatsapp | /cancelar
- GET/POST /api/contratos/config
- POST /api/webhooks/assinatura

### Dashboard e Consulta
- GET /api/dashboard?date=
- GET /api/consulta/pedidos | /opcoes

### Auditoria
- GET /api/auditoria/diaria | /conciliacao-bling | /log-detalhado

### Clientes e Endereços
- GET /api/customer/search?q=&type= | /search-multi | /search-bling-doc
- POST /api/customer/create-bling | /upsert | /sync-bling
- GET /api/customer/last-order?phone=
- GET/POST/DELETE /api/address/*

### Produtos
- GET /api/products/search | GET/POST/DELETE /api/products/favorites
- GET/POST /api/app-products | POST /api/app-products/import-bling
- GET /api/pub/product-icon/:key (público)

### Bling, IzChat, Config
- GET /bling/oauth/start | /callback | /ping
- GET /api/bling/status | /keep-alive | /diagnostico
- GET /api/vendedores | /api/formas-pagamento
- POST /izchat/notificar-entrega | GET /izchat/teste
- GET /api/drivers | /api/streets/* | /api/pub/*
- GET/POST /api/config (admin)

---

## 📝 CHANGELOG worker.js

| Versão | Mudanças |
|--------|----------|
| v2.38.2 | customers_cache: campos ultima_compra_glp + origem para importação GLP Master |
| v2.38.1 | PushInPay PIX (substituiu Cora) + webhook + force lembrete |
| v2.34.0 | PushInPay — integração inicial (substituiu Cora) |
| v2.32.x | Índices customers_cache (performance 10k+) + reset circuit breaker WhatsApp |
| v2.31.0 | Cora PIX — cobrança automática, QR code, webhook |
| v2.30.0 | WhatsApp troca entregador + Venda externa + QR avaliação Google |
| v2.29.0 | Relatório Diário por E-mail via Resend + CSV anexo + cron |
| v2.28.5 | Fix Assinafy — reusa signer existente se email já cadastrado |
| v2.28.3 | Fix WhatsApp — formatPhoneWA auto em sendWhatsApp |
| v2.28.1 | Lembretes PIX — saudação variada, {ontem}/{chave_pix}, delay 60s anti-ban |
| v2.28.0 | Produtos — icon_key (upload ícone R2) + reorder endpoint |
| v2.27.1 | Remove assinatura/fechamento e opt-out das msgs WhatsApp |
| v2.27.0 | WhatsApp Safety Layer — anti-ban, circuit breaker, rate limit, categorias |
| v2.26.0 | Lembretes PIX — payment_reminders, envio manual/bulk/cron |
| v2.25.x | Módulo Contratos Comodato — schema, endpoints, Assinafy, IzChat |
| v2.24.0 | Último pedido cliente + app_products (preços sugeridos MoskoGás) |
| v2.23.x | Produtos favoritos — tabela product_favorites + endpoints |
| v2.22.x | Dashboard endpoint (KPIs, status, produtos, pgto, vendedores, hora) |
| v2.21.0 | Rate limiting login, troca senha, permissões atendente expandidas |
| v2.20.0 | Consulta avançada (15+ filtros, paginação, resumo) |
| v2.19.x | Permissões dinâmicas + foto WebP defaults |
| v2.18.0 | Config dinâmica (app_config) |
| v2.17.x | Bling só ao ENTREGAR + Consumidor Final padrão |
| v2.16.x | Reabrir/cancelar com motivo + auditoria status + WhatsApp admin |
| v2.15.0 | Entrega com foto obrigatória (R2) |

---

## 🚀 WORKFLOW DE DEPLOY

1. Incrementar versão em TODOS arquivos editados (3 lugares no HTML!)
2. Testar: `wrangler dev` | Live Server
3. Deploy worker: Quick Edit no Cloudflare Dashboard ou `wrangler deploy`
4. Git push HTMLs **+ worker.js** (Claude via HTTPS+token)
5. Verificar versão no badge
6. **worker.js no GitHub = fonte da verdade** — consultar ao iniciar sessão

---

## 📖 MANUTENÇÃO DA DOCUMENTAÇÃO

Atualizar quando: worker subir 3+ versões minor, nova tabela D1, novo endpoint, nova integração, novo HTML, mudança de regra de negócio.

Gerar PDF + MD atualizados e entregar para Luis substituir nos arquivos do Projeto.
