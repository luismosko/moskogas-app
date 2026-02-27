# INSTRUÇÕES DO PROJETO — MoskoGás Backend v2

## Objetivo
Construir interface web ultra-rápida para pedidos de gás/água integrando Bling ERP + Cloudflare Worker/D1/R2 + IzChat (WhatsApp).

**Prioridade absoluta:** Velocidade operacional (15-30s por pedido), poucos cliques, UX para atendente.

---

## ⚠️ REGRAS CRÍTICAS

### Versionamento (OBRIGATÓRIO)
**SEMPRE incrementar versão em TODO arquivo editado:**
- HTML: badge visível `<title>Pedido — v2.X.Y</title>` + `<div>v2.X.Y — página</div>`
- JS (worker.js): comentário `// v2.X.Y` no topo
- **NUNCA entregar sem versão atualizada**

### Infraestrutura (NÃO QUEBRAR)
```
Backend: https://api.moskogas.com.br
Worker: moskogas-backend-v2 (ES Module)
D1: moskogas_ops (binding DB)
R2: moskogas-comprovantes (binding BUCKET)
```

**Endpoints existentes (manter funcionando):**
- GET /health | GET /bling/ping
- GET /bling/oauth/start | GET /bling/oauth/callback
- POST /izchat/notificar-entrega | GET /izchat/teste
- GET /api/pagamentos | PATCH /api/pagamentos/:id
- POST /api/order/create
- GET /api/pub/* (debug, sem auth)

**Secrets Cloudflare:** BLING_CLIENT_ID, BLING_CLIENT_SECRET, IZCHAT_TOKEN, APP_API_KEY

### Cidade = Campo Grande/MS (SEMPRE)
- NÃO exibir campos Cidade/UF na UI
- Hardcoded: cidade="Campo Grande", uf="MS"

---

## 📊 SISTEMA DE PAGAMENTOS (v2.7.0)

### Tipos de Pagamento
| Tipo | Cria Bling? | Marca Pago? | Aparece em Pagamentos? |
|------|-------------|-------------|------------------------|
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

### Emissão NFCe
**IMPORTANTE:** NFCe NÃO tem endpoint direto na API Bling v3.
- Pedidos criados via API → Operador emite NFCe 1x/dia no painel Bling (lote)
- Endpoint `/nfces` retorna 404 (não existe)
- NÃO implementar webhook de NFCe (complexidade desnecessária)

---

## 🔄 STATUS DO PEDIDO (cores padrão)

| Status | Cor | Significado |
|--------|-----|-------------|
| NOVO | 🔴 Vermelho | Sem entregador |
| ENCAMINHADO | 🟡 Amarelo | Entregador escolhido |
| WHATS ENVIADO | 🟢 Verde | IzChat confirmou envio |
| ENTREGUE | 🔵 Azul | Finalizado |
| CANCELADO | ⚪ Cinza | Cancelado |

---

## 🔌 BLING API v3

### IDs importantes
- Consumidor Final: `726746364`
- Formas de pagamento:
  - Dinheiro: 23368
  - PIX: 23465
  - Débito: 23369
  - Crédito: 23370
  - Fiado: 23373

### Endpoints usados
- POST `/pedidos/vendas` — Criar pedido
- GET `/contatos` — Buscar clientes
- POST `/contatos` — Criar cliente

### Token
- Refresh automático via cron `0 */5 * * *`
- Tabela D1: `bling_tokens` (id=1)
- Expira em 6h, renova com 1.5h de margem

---

## 📱 IZCHAT (WhatsApp)

**Envio para entregador:**
```javascript
POST /izchat/notificar-entrega
{
  order_id: 123,
  driver_phone: "5567999999999",
  message: "texto",
  observacao: "obs"
}
```

Link Google Maps sempre incluído no template.

---

## 🗄️ SCHEMA D1 (principais campos)

### `orders`
```sql
id, phone_digits, customer_name, address_line, bairro, 
complemento, referencia, items_json, total_value, notes,
status, sync_status, driver_name_cache, created_at,
bling_pedido_id, bling_pedido_num, 
tipo_pagamento TEXT, pago INTEGER DEFAULT 0
```

### `customers_cache`
```sql
phone_digits PRIMARY KEY, name, address_line, bairro, 
complemento, referencia, bling_contact_id
```

---

## ❌ ERROS JÁ COMETIDOS (NÃO REPETIR)

1. **Usar endpoint `/nfce` ou `/nfces`** → NÃO EXISTE na API v3
2. **Esquecer de incrementar versão** → SEMPRE atualizar
3. **Usar `pedido_numero` ao invés de `bling_pedido_id`** → ID interno ≠ número
4. **Criar webhook de NFCe** → Complexidade desnecessária
5. **Não copiar place_id exatamente** → Case-sensitive
6. **Form reset sem null check** → `if (el) el.value = ''`

---

## 📋 TELAS DO SISTEMA

1. **pedido.html** — Inserção de pedido (atendente)
2. **pedidos.html** — Pedidos do dia (entregador)
3. **gestao.html** — Gestão de pedidos (admin)
4. **pagamentos.html** — Gestão de pagamentos ✨ NOVO v1.0.0
5. **impressao.html** — Recibo A4 (2 vias)

---

## 🚀 WORKFLOW DE DEPLOY

1. Incrementar versão em TODOS arquivos editados
2. Testar localmente (worker: `wrangler dev`)
3. Deploy: `wrangler deploy`
4. Upload HTML → GitHub Pages
5. Verificar versão visível no badge

---

## 📞 HELP API BLING
https://developer.bling.com.br/home

**Auth:** OAuth 2.0 (PKCE flow)
**Base URL:** https://www.bling.com.br/Api/v3
**Headers:** `Authorization: Bearer {token}`, `enable-jwt: 1`
