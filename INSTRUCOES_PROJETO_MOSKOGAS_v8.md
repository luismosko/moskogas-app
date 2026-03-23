# INSTRUÇÕES DO PROJETO — MoskoGás v8.0
> **Atualizado em:** 23/03/2026 | **Worker:** v2.52.46 | **Extensão IZGLP:** v2.4.2

## Objetivo
Sistema web ultra-rápido para gestão de pedidos de gás/água integrando Bling ERP + Cloudflare Worker/D1/R2 + IzChat (WhatsApp + CRM) + Backup Google Drive + Relatório diário por E-mail.

**Prioridade absoluta:** Velocidade operacional (15-30s por pedido), poucos cliques, UX para atendente.

**Objetivo estratégico:** Vender MoskoGás como SaaS white-label para outras revendas de gás/água — escalabilidade e eficiência de API são prioridades estratégicas.

---

## ⚠️ REGRAS CRÍTICAS

### 🔌 CONEXÃO NO INÍCIO DE CADA SESSÃO (OBRIGATÓRIO)
1. **Tokens salvos em** `/mnt/project/Cloudflare_API_Token.txt`
   - Cloudflare API Token: `[VER ARQUIVO DO PROJETO]`
   - GitHub Token: `[VER ARQUIVO DO PROJETO]`
2. **Clonar repo:** `git clone https://TOKEN@github.com/luismosko/moskogas-app.git`
3. **Configurar git:** `git config user.email "luismosko@gmail.com" && git config user.name "Luis Mosko"`
4. **API Cloudflare** não é acessível diretamente — deploy via GitHub Actions automático no push
5. Se o clone falhar, pedir novo token ao Luis (tokens podem expirar)

### 📝 ATUALIZAÇÃO DE DOCUMENTAÇÃO (OBRIGATÓRIO)
**Sempre que uma correção significativa funcionar, Claude deve sugerir atualizar a documentação.**

Correções significativas incluem:
- Novo módulo ou funcionalidade
- Nova integração (ex: IzChat CRM, extensão Chrome)
- Bug fix que muda comportamento importante
- Novas tabelas D1 ou endpoints
- Mudanças em fluxos de trabalho

**Formato:** Criar nova versão do arquivo `INSTRUCOES_PROJETO_MOSKOGAS_vX.md` e entregar ao Luis para substituir nos arquivos do Projeto.

### Versionamento (OBRIGATÓRIO)
**SEMPRE incrementar versão em TODO arquivo editado:**
- HTML: badge visível + `<title>` + `<h1>` (3 LUGARES!)
- JS (worker.js): comentário `// v2.X.Y` no topo
- shared.js: comentário `// v1.X.Y` no topo
- Extensão Chrome: `manifest.json` + comentários nos .js
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

### ⚠️ LIÇÃO APRENDIDA — Google Antigravity / IAs externas
O Google Antigravity (e qualquer IA externa) pode editar o worker.js diretamente pelo Quick Edit do Cloudflare **sem atualizar o GitHub**. Isso causa:
- Worker em produção diverge do GitHub
- Bindings D1/R2 podem ser removidos se fizer novo deploy com wrangler.jsonc errado
- Sintomas: `Error 1101 Worker threw exception` + `Cannot read properties of undefined (reading 'prepare')`

**Solução imediata:**
1. Cloudflare → Workers → moskogas-backend-v2 → **Bindings** → verificar se DB e BUCKET estão presentes
2. Se bindings sumiram: Add binding → D1 → `DB` = `moskogas_ops` e R2 → `BUCKET` = `moskogas-comprovantes`
3. Colar o worker.js do GitHub no Quick Edit do Cloudflare

**Regra:** O `worker.js` do GitHub é sempre a **fonte da verdade**. Ao iniciar sessão, SEMPRE clonar o repo.

### ⚠️ SESSÕES CONCORRENTES
Múltiplas sessões Claude podem editar `worker.js` simultaneamente, causando conflitos.

**SEMPRE antes de editar:**
```bash
git fetch origin && git reset --hard origin/main
```

**Se push falhar (non-fast-forward):**
```bash
git fetch origin && git rebase origin/main && git push origin main
```

**Se rebase der conflito em worker.js:**
```bash
git rebase --abort && git reset --hard origin/main
# Re-aplicar mudanças manualmente
```

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
- **NUNCA usar `cloudflare/wrangler-action`** (buggy) — usar setup-node + npx

### Secrets Cloudflare
**Worker principal:** `BLING_CLIENT_ID`, `BLING_CLIENT_SECRET`, `IZCHAT_TOKEN`, `APP_API_KEY`, `JWT_SECRET`, `PUSHINPAY_TOKEN`, `RESEND_API_KEY`
**Worker backup:** `GDRIVE_CLIENT_ID`, `GDRIVE_CLIENT_SECRET`, `APP_API_KEY`

### Cidade = Campo Grande/MS (SEMPRE)
- NÃO exibir campos Cidade/UF na UI
- Hardcoded: cidade="Campo Grande", uf="MS"

---

## 🔌 EXTENSÃO CHROME IZGLP v2.4.2 (NOVO!)

### Conceito
Extensão Chrome unificada que combina:
1. **Hub Ultragaz Monitor** — detecta novos pedidos no Hub e envia para MoskoGás
2. **Bina Virtual IzChat** — exibe dados do cliente no painel do IzChat e permite abrir pedido com 1 clique

### Estrutura da Extensão
```
izglp-extension/
├── manifest.json        # v2.4.2, permissões Hub + IzChat
├── background.js        # Service worker unificado
├── content-hub.js       # Monitor Hub Ultragaz
├── content-bina.js      # Bina Virtual no IzChat
├── content-bina.css     # Estilos da Bina
├── popup.html           # Interface com 3 abas (Hub, Bina, Config)
├── popup.js             # Lógica unificada
└── icons/               # Ícones verdes IZGLP (16, 48, 128)
```

### Funcionalidades da Bina Virtual
- Detecta abertura do painel "Dados do contato" no IzChat
- Extrai telefone no formato `+55 (XX) XXXXX-XXXX` do painel direito
- Busca dados do cliente na API MoskoGás (com variações de telefone)
- Exibe: nome, endereço, bairro, complemento, referência, última compra
- **Botão "🛒 Abrir Pedido"** → abre `pedido.html?phone=XXXXX` com cliente pré-carregado
- **Botão "🔄 Sincronizar com IzChat"** → atualiza dados no CRM IzChat
- Sincronização automática ao abrir contato

### Tratamento de Telefone (IMPORTANTE!)
O IzChat pode mostrar telefone com 8 ou 9 dígitos após DDD. A extensão gera **todas as variações**:
```
Telefone IzChat: +55 (67) 9241-4371 → 556792414371

Variações geradas:
1. 6792414371   (10 dígitos - sem 55, sem 9)
2. 556792414371 (12 dígitos - com 55, sem 9)
3. 67992414371  (11 dígitos - sem 55, COM 9) ← Formato do banco!
4. 5567992414371 (13 dígitos - com 55, com 9)
```

### Permissões (manifest.json)
- `hub.ultragaz.com.br/*`
- `chat.izchat.com.br/*`
- `api.moskogas.com.br/*`
- `moskogas-app.pages.dev/*`
- permissions: storage, alarms, tabs, notifications, scripting, activeTab

### API Key
- Usa `Moskogas0909` (env.APP_API_KEY) para autenticação
- Passa via query param: `?api_key=Moskogas0909`

---

## 📱 INTEGRAÇÃO IZCHAT CRM (NOVO!)

### Conceito
Sincronização de dados de clientes entre MoskoGás (D1) e IzChat CRM. Permite que atendentes vejam dados do cliente direto no painel do IzChat.

### Credenciais IzChat
- **Base URL:** `https://chatapi.izchat.com.br`
- **company_token:** salvo em `app_config` key=`izchat_company_token`
- **API Docs:** `/mnt/project/Manual_Tecnico_IZChat_API_Webhooks_v1_0.pdf`

### Endpoints Implementados (Worker)
```
GET/POST /api/izchat/config           — Configurar token
GET      /api/izchat/contacts/search  — Buscar contato por telefone
GET      /api/izchat/contacts/:id     — Detalhes do contato
POST     /api/izchat/contacts/sync    — Sincronizar 1 cliente
POST     /api/izchat/contacts/sync-batch — Sincronizar em lote
GET      /api/izchat/stats            — Estatísticas de sincronização
```

### extraInfo IzChat (campos sincronizados)
```json
[
  {"name": "Endereco", "value": "Rua X, 123"},
  {"name": "Bairro", "value": "Centro"},
  {"name": "Complemento", "value": "Apto 101"},
  {"name": "Referencia", "value": "Próximo ao mercado"},
  {"name": "CPF_CNPJ", "value": "123.456.789-00"},
  {"name": "Ultima_Compra", "value": "2026-03-20"}
]
```
⚠️ **Case-sensitive!** Usar exatamente esses nomes.

### Variáveis para Automações IzChat
```
{{contact.name}}, {{contact.number}}, {{contact.email}}
{{contact.extraInfo.Endereco}}, {{contact.extraInfo.Bairro}}
{{contact.extraInfo.Complemento}}, {{contact.extraInfo.Referencia}}
{{contact.extraInfo.CPF_CNPJ}}, {{contact.extraInfo.Ultima_Compra}}
```

### Sincronização em Lote (config.html)
- Acessar: config.html → aba Integrações → IzChat CRM
- Botão "▶️ Iniciar Sincronização" processa 50 clientes por vez
- Barra de progresso mostra andamento
- Botão "⏹️ Parar" interrompe sincronização
- ~15.000 clientes no total, ~9.100 já sincronizados

---

## 🔐 AUTENTICAÇÃO

### Roles (hierarquia: admin > gerente > atendente > entregador)
| Role | Acesso | Páginas |
|------|--------|---------|
| Admin | Total | Todas + usuarios.html + config permissões |
| Gerente | Gestão ampla | Pedidos, gestão, pagamentos, auditoria, whatsapp safety, cria atendente/entregador |
| Atendente | Pedidos/gestão | pedido, gestao, pagamentos, relatorio, config, dashboard, consulta, contratos, vales |
| Entregador | Entregas | entregador.html |

### Fluxo
- `index.html` → verifica token → redirect por role ou login
- Token de sessão (24h) salvo em localStorage (`mg_session_token`, `mg_user`)
- `shared.js` gerencia auth em todas as páginas
- Worker valida sessão em todos endpoints (exceto /api/auth/login, /health, /api/pub/*, /api/relatorio/*)

### API Key (para extensões/scripts)
- Header: `X-API-KEY: Moskogas0909`
- Ou query param: `?api_key=Moskogas0909`
- Retorna role `admin` para acesso completo

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

| Tipo | Cria Bling? | Marca Pago? | Em Pagamentos? |
|------|-------------|-------------|----------------|
| 💵 Dinheiro | ✅ (ao entregar) | ✅ | ❌ |
| ⚡ PIX à vista | ✅ (ao entregar) | ✅ | ❌ |
| ⏳ PIX a receber | ✅ (ao entregar) | ❌ | ✅ |
| 💳 Débito | ✅ (ao entregar) | ✅ | ❌ |
| 💳 Crédito | ✅ (ao entregar) | ✅ | ❌ |
| 📅 Mensalista | ❌ (só no lote) | ❌ | ✅ |
| 🧾 Boleto/Órgão | ❌ (só no lote) | ❌ | ✅ |

**Bling só é criado ao marcar ENTREGUE** (nunca ao criar pedido).

---

## 🔄 STATUS DO PEDIDO

| Status | Cor | Significado |
|--------|-----|-------------|
| NOVO | 🔴 Vermelho | Sem entregador |
| ENCAMINHADO | 🟡 Amarelo | Entregador escolhido |
| WHATS ENVIADO | 🟢 Verde | IzChat confirmou |
| ENTREGUE | 🔵 Azul | Finalizado (cria Bling, exige foto) |
| CANCELADO | ⚪ Cinza | Cancelado (motivo obrigatório) |

---

## 📱 WHATSAPP SAFETY LAYER

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

---

## 📁 ARQUIVOS E VERSÕES (23/03/2026)

| Arquivo | Versão | Função |
|---------|--------|--------|
| pedido.html | v2.11.64 | Inserção de pedido + carrega cliente da URL |
| gestao.html | v2.9.12 | Gestão + resumo produtos |
| pagamentos.html | v1.9.14 | Pagamentos pendentes + lembretes PIX |
| config.html | v2.15.2 | Configurações gerais + IzChat CRM sync |
| contratos.html | v1.1.8 | Contratos comodato + Assinafy |
| relatorio.html | v1.2.7 | Relatórios |
| entregador.html | v2.6.6 | Painel entregador |
| dashboard.html | v1.0.2 | Dashboard visual |
| consulta-pedidos.html | v1.0.7 | Consulta avançada |
| auditoria.html | v1.1.3 | Auditoria Bling + logs |
| login.html | v1.3.0 | Login |
| usuarios.html | v1.6.1 | Gestão usuários (admin) |
| clientes.html | v1.0.2 | Gestão de clientes |
| vales.html | v1.1.4 | Controle de Vale Gás |
| avaliacoes.html | v1.2.0 | Avaliações / satisfação |
| estoque.html | v1.2.2 | Controle de estoque |
| empenhos.html | v1.0.2 | Empenhos governamentais |
| shared.js | v1.23.0 | Utilitários (auth, api, toast, nav) |
| **worker.js** | **v2.52.46** | **Backend (deploy via GitHub Actions)** |
| **Extensão IZGLP** | **v2.4.2** | **Hub Ultragaz + Bina Virtual IzChat** |

---

## 🗄️ SCHEMA D1 (principais tabelas)

### `customers_cache`
```sql
phone_digits PRIMARY KEY, name, address_line, bairro,
complemento, referencia, bling_contact_id, cpf_cnpj,
email, email_nfe, tipo_pessoa, updated_at,
ultima_compra_glp TEXT DEFAULT '',
origem TEXT DEFAULT 'manual'   -- manual|glp_master|bling
```

### `customer_addresses`
```sql
id, phone_digits, obs, address_line, bairro, complemento, referencia, created_at
```
⚠️ **Endereços múltiplos** ficam aqui! Se `customers_cache.address_line` estiver vazio, buscar primeiro endereço em `customer_addresses`.

### `app_config`
```sql
key TEXT PRIMARY KEY, value TEXT, updated_at TEXT
-- Chaves importantes:
--   izchat_company_token  — Token da API IzChat
--   permissoes            — JSON de permissões por role
```

---

## 📌 BLING API v3

Base: `https://www.bling.com.br/Api/v3`
Auth: OAuth 2.0 | Headers: `Authorization: Bearer {token}`, `enable-jwt: 1`

### IDs Importantes
- Consumidor Final: `726746364`
- Dinheiro: 23368 | PIX Bradesco: 3138153 | PIX ITAU: 9052024
- Débito: 188552 | Crédito: 188555 | Duplicata (Fiado): 188534

---

## 🎨 REGRAS DE UX (SEMPRE SEGUIR)

1. **Modais NUNCA fecham ao clicar fora** — Só por X, Cancelar ou Salvar
2. **Toasts grandes** — Fundo colorido, animação slide-in, duração 3s
3. **Tooltips** — title em todos botões de ação
4. **Redirect** — Após salvar pedido → gestao.html (1.2s delay)
5. **Versão visível** — Badge em todas as páginas
6. **Cidade hardcoded** — Sem campos cidade/UF
7. **Foto obrigatória** — Entregador precisa de foto (admin pode pular)
8. **Loading overlay** — showLoading() em TODA ação assíncrona

---

## ❌ ERROS CONHECIDOS (NÃO REPETIR)

1. Usar `/nfce` ou `/nfces` → NÃO EXISTE na API Bling v3
2. Esquecer versão → Atualizar nos 3 LUGARES
3. Form reset sem null check → `if (el) el.value = ''`
4. Modal fecha ao clicar fora → Usar shared.js
5. **Chamar API IzChat diretamente → SEMPRE usar sendWhatsApp() com Safety Layer**
6. **IA externa pode apagar bindings D1/R2 do Cloudflare** → Verificar bindings após intervenção
7. **requireAuth: usar `instanceof Response`** → NÃO usar `if (authErr)` — causa crash
8. **selectClient não existe** → Usar `selectCustomer(i)` ou preencher campos diretamente
9. **LIKE não encontra telefone com 9 extra** → Buscar com últimos 8 dígitos

---

## 📝 CHANGELOG (sessão 23/03/2026)

### worker.js v2.52.46
- IzChat CRM: endpoints de sync com variações de telefone
- Busca cliente por telefone enriquece com endereço de `customer_addresses`
- Sync aceita `phone_digits` ou `phone` no body

### pedido.html v2.11.64
- Carrega cliente automaticamente quando `?phone=` na URL
- Preenche TODOS os campos (nome, telefone, endereço, bairro, etc.)
- Busca com últimos 8 dígitos (fix para LIKE com 9 extra/faltante)
- Toast de sucesso ao carregar cliente

### config.html v2.15.2
- Nova seção IzChat CRM na aba Integrações
- Sincronização em lote com barra de progresso
- Botão Parar sincronização

### Extensão IZGLP v2.4.2
- Bina Virtual: exibe dados do cliente no painel IzChat
- Botão "Abrir Pedido" → abre pedido.html com cliente pré-carregado
- Botão "Sincronizar com IzChat" → atualiza dados no CRM
- Tratamento de variações de telefone (com/sem 55, com/sem 9)

---

## 🚀 WORKFLOW DE DEPLOY

1. Incrementar versão em TODOS arquivos editados (3 lugares no HTML!)
2. Editar em `/home/claude/moskogas-app` (repo clonado)
3. `git add . && git commit -m "v2.X.Y: descrição" && git push`
4. GitHub Actions faz deploy automático no Cloudflare
5. Verificar versão no badge e logs do Actions
6. Salvar cópia em `/mnt/user-data/outputs/`

### wrangler.jsonc correto (NÃO ALTERAR)
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

## 📖 MANUTENÇÃO DA DOCUMENTAÇÃO

Atualizar quando:
- Worker subir 3+ versões minor
- Nova tabela D1
- Novo endpoint
- Nova integração (extensão, API externa)
- Novo HTML
- Mudança de regra de negócio
- **Correção significativa que funcionou**

**Claude deve sugerir atualizar a documentação ao final de cada sessão produtiva!**

Gerar PDF + MD atualizados e entregar para Luis substituir nos arquivos do Projeto.
