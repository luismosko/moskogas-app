# INSTRUÇÕES DO PROJETO — MoskoGás v10.0
> **Atualizado em:** 28/03/2026 | **Worker:** v2.52.81

## Objetivo
Sistema web ultra-rápido para gestão de pedidos de gás/água integrando Bling ERP + Cloudflare Worker/D1/R2 + IzChat (WhatsApp) + Backup Google Drive + Relatório diário por E-mail.

**Prioridade absoluta:** Velocidade operacional (15-30s por pedido), poucos cliques, UX para atendente.

---

## ⚠️ REGRAS CRÍTICAS

### 🔌 CONEXÃO NO INÍCIO DE CADA SESSÃO (OBRIGATÓRIO)
1. **Tokens salvos em** `/mnt/project/Cloudflare_API_Token.txt`
   - Cloudflare API Token: (ver arquivo do projeto)
   - GitHub Token: (ver arquivo do projeto)
2. **Clonar repo:** `git clone https://TOKEN@github.com/luismosko/moskogas-app.git`
3. **Configurar git:** `git config user.email "luismosko@gmail.com" && git config user.name "Luis Mosko"`
4. **SEMPRE fazer rebase antes de editar:** `git fetch origin && git rebase origin/main`
5. **API Cloudflare** não é acessível diretamente — deploy via GitHub Actions automático no push
6. Se o clone falhar, pedir novo token ao Luis (tokens podem expirar)

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
D1: moskogas_ops (binding DB)  — ID: 2c8c3bef-f365-45bd-88f6-bfa2ebecd7d5
R2: moskogas-comprovantes (binding BUCKET)
Frontend: moskogas-app.pages.dev (GitHub Pages)
Repo: github.com/luismosko/moskogas-app
Cloudflare Account ID: ae0dc6d28847a1ad468a236ca60c5f42

Backup: https://moskogas-backup.luismosko.workers.dev
Worker Backup: moskogas-backup (separado)
Google Drive: luismosko@gmail.com → pasta "MoskoGás Backup"
```

### ⚠️ CONFLITOS GIT — MÚLTIPLAS SESSÕES SIMULTÂNEAS
Luis trabalha em várias sessões Claude ao mesmo tempo. **SEMPRE:**
1. `git fetch origin && git rebase origin/main` antes de editar qualquer arquivo
2. Nunca usar `git merge` — sempre `git rebase`
3. Se conflito, resolver localmente ou pedir ao Luis

### Git Push
- Claude faz push direto via HTTPS+token (ghp_xxx) — token no arquivo do projeto
- Sempre salvar também em /mnt/user-data/outputs/
- **SEMPRE incluir worker.js no push do GitHub**

### GitHub Actions (Deploy Automático)
Workflow: `.github/workflows/deploy-worker.yml`
- Triggers: push de `worker.js` ou `wrangler.jsonc`
- Stack: `setup-node@v4` + `npm install -g wrangler` + `npx wrangler@latest deploy`
- Secrets necessários: `CLOUDFLARE_API_TOKEN` + `CLOUDFLARE_ACCOUNT_ID`
- **NUNCA usar `wrangler deploy` manual** — sempre via GitHub Actions

### Cidade = Campo Grande/MS (SEMPRE)
- NÃO exibir campos Cidade/UF na UI
- Hardcoded: cidade="Campo Grande", uf="MS"

---

## 🔐 AUTENTICAÇÃO

### Roles (hierarquia: admin > gerente > atendente > entregador)
| Role | Acesso | Páginas |
|------|--------|---------|
| Admin | Total | Todas + usuarios.html + config permissões |
| Gerente | Gestão ampla | Pedidos, gestão, pagamentos, auditoria, whatsapp safety, cria atendente/entregador; NÃO acessa usuarios admin |
| Atendente | Pedidos/gestão | pedido, gestao, pagamentos, relatorio, config, dashboard, consulta, contratos, vales |
| Entregador | Entregas | entregador.html |

### ⚠️ Padrão requireAuth (NÃO ERRAR)
```javascript
// ✅ CORRETO
const authCheck = await requireAuth(request, env);
if (authCheck instanceof Response) return authCheck;
const user = authCheck; // objeto do usuário

// ❌ ERRADO — causa crash pois requireAuth retorna objeto (truthy) no sucesso
if (authErr) return authErr;
```

---

## 📊 SISTEMA DE PAGAMENTOS

### Tipos de Pagamento
| Tipo | Cria Bling? | Marca Pago? | Em Pagamentos? |
|------|-------------|-------------|----------------|
| 💵 Dinheiro | ✅ (ao entregar) | ✅ | ❌ |
| ⚡ PIX à vista | ✅ (ao entregar) | ✅ | ❌ |
| ⏳ PIX a receber | ✅ (ao entregar) | ❌ | ✅ |
| 💳 Débito | ✅ (ao entregar) | ✅ | ❌ |
| 💳 Crédito | ✅ (ao entregar) | ✅ | ❌ |
| 📅 Mensalista | ❌ (só no lote) | ❌ | ✅ |
| 🧾 Boleto/Órgão | ❌ (só no lote) | ❌ | ✅ |

### ⚠️ COMPROVANTES — DOIS TIPOS DIFERENTES
| Campo | Quem preenche | O que é |
|-------|---------------|---------|
| `foto_comprovante` | **Entregador** | Recibo de entrega assinado pelo cliente |
| `comprovante_pagamento` | **Atendente** | Comprovante de pagamento real (PIX, boleto pago) |

**Regras no financeiro:**
- PIX/Cartão: comprovante de pagamento **obrigatório** no modal
- Dinheiro: sem comprovante, mas **e-mail de alerta** para admin
- Troca de tipo após baixa: **bloqueado** para não-admin

---

## 📱 EXTENSÃO IZGLP (Chrome)

### Funcionalidades
- 🔔 Som automático ao detectar novo pedido
- 🔢 Badge contador de alertas pendentes
- 📋 Painel de alertas com "Marcar como Visto"
- ⏱️ Scan a cada 3 minutos
- 🟠 Barra laranja para pedidos cancelados

### Arquivos
```
izglp-extension/
├── manifest.json (v2.2.5)
├── background.js (service worker)
├── popup.html / popup.js
├── content.js
├── styles.css
└── alert.mp3
```

### ⚠️ manifest.json está no .gitignore
Para commitar: `git add -f izglp-extension/manifest.json`

---

## 👥 MÚLTIPLOS CONTATOS POR CLIENTE (v2.52.78)

### Tabela `customer_contacts`
```sql
CREATE TABLE customer_contacts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  phone_digits TEXT NOT NULL,
  contact_name TEXT NOT NULL,
  contact_role TEXT DEFAULT '',
  contact_phone TEXT DEFAULT '',
  contact_email TEXT DEFAULT '',
  is_primary INTEGER DEFAULT 0,
  created_at INTEGER DEFAULT (unixepoch())
);
```

### Endpoints
| Endpoint | Método | Descrição |
|----------|--------|-----------|
| `/api/clientes/:phone/contatos` | GET | Lista contatos |
| `/api/clientes/:phone/contatos` | POST | Adiciona contato |
| `/api/clientes/:phone/contatos/:id` | PUT | Atualiza |
| `/api/clientes/:phone/contatos/:id` | DELETE | Remove |

---

## 🔄 STATUS DO PEDIDO

| Status | Cor | Significado | Ordenação |
|--------|-----|-------------|-----------|
| NOVO | 🔴 Vermelho | Sem entregador | 1º (prioridade) |
| ENCAMINHADO | 🟡 Amarelo | Entregador escolhido | 2º |
| WHATS ENVIADO | 🟢 Verde | IzChat confirmou | 3º |
| ENTREGUE | 🔵 Azul | Finalizado | 4º |
| CANCELADO | ⚪ Cinza | Cancelado | 5º |

**Ordenação padrão:** Status (prioridade) → Hora (recente primeiro dentro de cada status)

---

## 📁 ARQUIVOS E VERSÕES (28/03/2026)

| Arquivo | Versão | Função |
|---------|--------|--------|
| **worker.js** | **v2.52.81** | **Backend (deploy via GitHub Actions)** |
| gestao.html | v2.9.35 | Gestão + resumo produtos + ver foto |
| pagamentos.html | v1.10.1 | Pagamentos + comprovante + mobile |
| pedido.html | v2.11.72 | Inserção de pedido + CEP auto |
| entregador.html | v2.6.8 | Painel entregador + edição itens |
| config.html | v2.15.4 | Configurações gerais |
| clientes.html | v1.3.2 | Gestão de clientes |
| shared.js | v1.25.8 | Auth + nav + toast + banner |
| consulta-pedidos.html | v1.0.8 | Consulta avançada |
| vales.html | v1.1.4 | Controle de Vale Gás |
| contratos.html | v1.1.8 | Contratos comodato + Assinafy |
| usuarios.html | v1.6.1 | Gestão usuários (admin) |
| relatorio.html | v1.2.7 | Relatórios |
| dashboard.html | v1.0.2 | Dashboard visual |
| auditoria.html | v1.1.3 | Auditoria Bling + logs |

---

## 🗄️ SCHEMA D1 — PRINCIPAIS TABELAS

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
foto_comprovante TEXT,           -- Entregador: recibo de entrega
comprovante_pagamento TEXT,      -- Atendente: comprovante de pagamento
baixa_por_id INTEGER,            -- Quem confirmou pagamento
baixa_por_nome TEXT,
baixa_at INTEGER,
observacao_entregador TEXT,
tipo_pagamento_original TEXT, cancel_motivo TEXT,
nfce_id TEXT, nfce_numero TEXT, nfce_status TEXT
```

### `customer_contacts` (v2.52.78)
```sql
id, phone_digits, contact_name, contact_role,
contact_phone, contact_email, is_primary, created_at
```

### `ceps_cg` (v2.52.66)
```sql
cep TEXT PRIMARY KEY, logradouro TEXT, complemento TEXT, bairro TEXT
-- 9.131 CEPs de Campo Grande/MS
```

---

## 🎨 REGRAS DE UX (SEMPRE SEGUIR)

1. **Modais NUNCA fecham ao clicar fora** — Só por X, Cancelar ou Salvar
2. **Toasts grandes** — Fundo colorido, animação slide-in, duração 3s
3. **Banner sem auto-close** — Fica até o usuário fechar manualmente
4. **Versão visível** — Badge em todas as páginas
5. **Cidade hardcoded** — Sem campos cidade/UF
6. **Foto obrigatória** — Entregador precisa de foto (admin pode pular)
7. **Comprovante obrigatório** — PIX/Cartão no financeiro
8. **Loading overlay** — showLoading() em TODA ação assíncrona

---

## ❌ ERROS CONHECIDOS (NÃO REPETIR)

1. **Status D1 é lowercase** (`entregue`, não `ENTREGUE`) — case mismatch retorna vazio
2. **`requireAuth` retorna objeto no sucesso** — usar `instanceof Response`
3. **Conflitos git em sessões paralelas** — sempre `git fetch && git rebase` antes de editar
4. **`manifest.json` no `.gitignore`** — usar `git add -f`
5. **CSP bloqueia fetch em content scripts** — usar background service worker
6. **401 para falhas de API terceira** — usar 503 (401 limpa sessão do MoskoApp)
7. **Nullable flags em D1** — usar `(flag IS NULL OR flag = 0)`
8. **Clientes PJ sem telefone** — `phone_digits = 'doc_CNPJ'` (manter prefixo `doc_`)
9. **foto_comprovante ≠ comprovante_pagamento** — são campos diferentes!

---

## 📋 ENDPOINTS PRINCIPAIS

### Pagamentos (v2.52.79+)
```
GET  /api/pagamentos                    — Lista pendentes
POST /api/pagamentos/:id/confirmar      — Confirmar com comprovante
POST /api/pagamentos/:id/comprovante    — Upload avulso
GET  /api/pagamentos/:id/qrcode         — QR Code PIX
POST /api/pagamentos/:id/gerar-pix      — Gerar cobrança PIX
```

### Contatos (v2.52.78)
```
GET    /api/clientes/:phone/contatos       — Lista
POST   /api/clientes/:phone/contatos       — Adiciona
PUT    /api/clientes/:phone/contatos/:id   — Atualiza
DELETE /api/clientes/:phone/contatos/:id   — Remove
```

### CEP (v2.52.66)
```
GET /api/cep/{cep}        — Busca CEP exato
GET /api/cep/busca?q=     — Busca por nome/número
```

### Diagnóstico (temporários)
```
GET /api/pub/ver-pedido/:id
GET /api/pub/buscar-cliente?q=
GET /api/clientes/duplicados
POST /api/clientes/unificar-grupo
```

---

## 🚀 WORKFLOW DE DEPLOY

1. `git fetch origin && git rebase origin/main`
2. Incrementar versão em TODOS arquivos editados (3 lugares no HTML!)
3. Editar em `/home/claude/moskogas-app`
4. `git add . && git commit -m "v2.X.Y: descrição" && git push`
5. GitHub Actions faz deploy automático no Cloudflare
6. Verificar versão no badge e logs do Actions
7. Salvar cópia em `/mnt/user-data/outputs/`

---

## 📝 DOCUMENTAÇÃO NO REPO

| Arquivo | Conteúdo |
|---------|----------|
| `INSTRUCOES_PROJETO_MOSKOGAS_v10.md` | Este arquivo |
| `CHANGELOG_2026-03-28.md` | Changelog detalhado |
| `DOCS_BLING_NFCE_ESTOQUE.md` | NFC-e vs Pedido de Venda |
| `BLING_RATE_LIMIT_GUIDE.md` | Limites e recovery Bling |
| `BLING_NFCE_NFE_GUIDE.md` | API NFC-e descobertas |
| `IZCHAT_CRM_INTEGRACAO.md` | Integração IzChat |

---

*Documentação atualizada em 28/03/2026*
