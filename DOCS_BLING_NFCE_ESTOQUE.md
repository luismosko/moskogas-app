# 📋 DOCUMENTAÇÃO TÉCNICA — Bling, NFC-e, Estoque e Vale Gás
> **Atualizado:** 26/03/2026 | **Worker:** v2.52.64

---

## 🧾 SISTEMA DE NOTAS FISCAIS — NFC-e vs Pedido de Venda

### ⚠️ IMPORTANTE: Mudança desde v2.51.0

**A partir de v2.51.0, pagamentos À VISTA criam NFC-e diretamente, NÃO Pedido de Venda!**

| Tipo Pagamento | Cria o quê | Campo no D1 | Quando |
|----------------|------------|-------------|--------|
| 💵 Dinheiro | **NFC-e** | \`nfce_id\` | Ao marcar ENTREGUE |
| ⚡ PIX à vista | **NFC-e** | \`nfce_id\` | Ao marcar ENTREGUE |
| 💳 Débito | **NFC-e** | \`nfce_id\` | Ao marcar ENTREGUE |
| 💳 Crédito | **NFC-e** | \`nfce_id\` | Ao marcar ENTREGUE |
| ⏳ PIX a receber | **NFC-e** | \`nfce_id\` | Ao marcar ENTREGUE |
| 📅 Mensalista | **Pedido de Venda** | \`bling_pedido_id\` | Em lote (pagamentos.html) |
| 🧾 Boleto/Órgão | **Pedido de Venda** | \`bling_pedido_id\` | Em lote (pagamentos.html) |
| 🎫 Vale Gás | **NFC-e** | \`nfce_id\` | Ao marcar ENTREGUE |

### Regra de Negócio

\`\`\`javascript
// v2.51.0: Pagamentos à vista → NFC-e | Prazo → Pedido de Venda
const criarNFCe = ['dinheiro', 'pix_vista', 'pix_receber', 'debito', 'credito', 'vale_gas'].includes(tipo);
const criarPedidoVenda = ['mensalista', 'boleto', 'nfe'].includes(tipo);
\`\`\`

### Campos no Banco D1 (orders)

| Campo | Descrição |
|-------|-----------|
| \`nfce_id\` | ID da NFC-e no Bling (pagamentos à vista) |
| \`nfce_numero\` | Número da NFC-e emitida |
| \`nfce_status\` | \`pendente_emissao\` → \`emitida\` → \`autorizada\` |
| \`nfce_error\` | Erro se falhou |
| \`bling_pedido_id\` | ID do Pedido de Venda no Bling (mensalistas/boleto) |
| \`bling_pedido_num\` | Número do Pedido de Venda |

### Auditoria — Verificação Correta

Ao verificar "pedidos sem Bling", deve-se checar **AMBOS os campos**:

\`\`\`sql
-- ✅ CORRETO: Verifica NFC-e OU Pedido de Venda
SELECT * FROM orders 
WHERE status = 'entregue' 
AND nfce_id IS NULL 
AND bling_pedido_id IS NULL;

-- ❌ ERRADO: Só verifica Pedido de Venda (ignora NFC-e)
SELECT * FROM orders 
WHERE status = 'entregue' 
AND bling_pedido_id IS NULL;
\`\`\`

---

## 📦 SISTEMA DE ESTOQUE — Lançamento Automático

### Fluxo de Lançamento

1. **Ao marcar ENTREGUE** → Cria NFC-e no Bling
2. **NFC-e autorizada** → Sistema lança estoque automaticamente
3. **Cron a cada 30min** → Processa NFC-e pendentes de estoque

### Campos no Banco D1 (orders)

| Campo | Valores | Descrição |
|-------|---------|-----------|
| \`estoque_lancado\` | 0 / 1 | Flag se estoque já foi lançado no Bling |
| \`nfce_status\` | pendente/emitida/autorizada | Status da NFC-e |

### Endpoint Bling para Lançar Estoque

\`\`\`
POST /Api/v3/nfce/{id}/lancar/estoque
\`\`\`

### Respostas Possíveis

| HTTP | Significado | Ação |
|------|-------------|------|
| 200 | Lançado com sucesso | Marca \`estoque_lancado = 1\` |
| 400 + "já existe" | Estoque já havia sido lançado | Marca \`estoque_lancado = 1\` (skipped) |
| 400 outro | Erro (produto sem estoque configurado?) | Log erro |

### Cron Automático (lancarEstoqueAutomatico)

\`\`\`javascript
// Roda a cada 30 minutos
// Processa até 20 NFC-e por execução
// Critério: nfce_status IN ('emitida','autorizada') AND estoque_lancado = 0
\`\`\`

---

## 💰 SISTEMA DE CONTAS A RECEBER — Lançamento Automático

### Endpoint Bling

\`\`\`
POST /Api/v3/nfce/{id}/lancar/contas
\`\`\`

### Respostas Possíveis

| HTTP | Significado | Ação |
|------|-------------|------|
| 200 | Conta a receber criada | Sucesso |
| 400 + "já existe" | Conta já havia sido criada | Considera sucesso (skipped) |
| 400 outro | Erro | Log erro |

---

## 🎫 VALE GÁS — Heurísticas de Contagem de Produtos

### ⚠️ CONCEITO FUNDAMENTAL

Existem **dois cenários distintos** envolvendo Vale Gás:

| Cenário | O que acontece | Conta no estoque? | Campo |
|---------|----------------|-------------------|-------|
| **Venda Antecipada** | Vende o VOUCHER (papel), recebe pagamento, mas NÃO entrega produto | ❌ NÃO | \`venda_antecipada = 1\` |
| **Pagamento com Vale** | Entrega o produto, cliente paga COM o vale | ✅ SIM | \`tipo_pagamento = 'vale_gas'\` |

### Exemplos Práticos

**Cenário 1: Venda Antecipada de Vale Gás**
- Cliente: BRUNO
- Endereço: "VALE GÁS - VENDA ANTECIPADA"
- Pagamento: PIX à vista (R$ 125)
- Produto: 1x P13 (no papel, não físico)
- **Resultado:** Gera NFC-e, recebe pagamento, MAS estoque NÃO diminui
- **Campo:** \`venda_antecipada = 1\`

**Cenário 2: Pagamento com Vale Gás**
- Cliente: FUNDO ESPECIAL
- Endereço: Real (ex: "Rua das Flores, 123")
- Pagamento: Vale Gás (voucher como forma de pagamento)
- Produto: 2x P45 (entrega física)
- **Resultado:** Entrega produto, estoque DIMINUI
- **Campo:** \`tipo_pagamento = 'vale_gas'\`

### Heurísticas de Soma de Produtos

#### 1. Resumo de Produtos (gestao.html)

\`\`\`javascript
// v2.9.32: Exclui cancelados E vendas antecipadas
rows.filter(r => r.status !== 'cancelado' && !r.venda_antecipada).forEach(r => {
  // Soma quantidade de cada produto
});
\`\`\`

**Inclui:**
- ✅ Todos os pedidos entregues com produtos físicos
- ✅ Pagamentos com Vale Gás (entrega real)

**Exclui:**
- ❌ Pedidos cancelados
- ❌ Vendas antecipadas de Vale Gás

#### 2. Cálculo de Vendas para Estoque (calcVendasAuto)

\`\`\`javascript
// v2.52.64: Exclui vendas antecipadas do cálculo de estoque
"SELECT items_json FROM orders 
 WHERE status='entregue' 
 AND (venda_antecipada IS NULL OR venda_antecipada = 0) 
 AND delivered_at >= ? AND delivered_at <= ?"
\`\`\`

#### 3. Lançamento de Estoque no Bling

Mesmo que uma venda antecipada gere NFC-e, o sistema NÃO deve lançar estoque para ela, pois nenhum produto físico saiu.

**Regra:** Verificar \`venda_antecipada\` antes de chamar \`/lancar/estoque\`

### Campo venda_antecipada

\`\`\`sql
ALTER TABLE orders ADD COLUMN venda_antecipada INTEGER DEFAULT 0;

-- Marcar um pedido como venda antecipada
UPDATE orders SET venda_antecipada = 1 WHERE id = 1046;
\`\`\`

### Identificação Visual (gestao.html v2.9.32)

Pedidos com \`venda_antecipada = 1\` exibem badge:
- **🎫 VALE** (roxo, antes do nome do cliente)
- Tooltip: "Venda Antecipada — Vale Gás vendido, produto NÃO foi entregue"

---

## 📊 FLUXO COMPLETO — Do Pedido ao Estoque

\`\`\`
┌─────────────────────────────────────────────────────────────────┐
│                    PEDIDO CRIADO                                │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│               PEDIDO MARCADO COMO ENTREGUE                      │
└─────────────────────────────────────────────────────────────────┘
                              │
              ┌───────────────┴───────────────┐
              │                               │
              ▼                               ▼
┌──────────────────────┐        ┌──────────────────────┐
│   PAGAMENTO À VISTA  │        │   PAGAMENTO A PRAZO  │
│  (din, pix, deb, cre)│        │  (mensalista, boleto)│
└──────────────────────┘        └──────────────────────┘
              │                               │
              ▼                               ▼
┌──────────────────────┐        ┌──────────────────────┐
│    CRIA NFC-e        │        │  CRIA PEDIDO VENDA   │
│   (nfce_id)          │        │  (bling_pedido_id)   │
└──────────────────────┘        └──────────────────────┘
              │                               │
              ▼                               │
┌──────────────────────┐                      │
│  É VENDA ANTECIPADA? │                      │
└──────────────────────┘                      │
      │           │                           │
     SIM         NÃO                          │
      │           │                           │
      ▼           ▼                           │
┌──────────┐  ┌──────────────────┐            │
│ NÃO LANÇA│  │ LANÇA ESTOQUE    │            │
│ ESTOQUE  │  │ POST /lancar/    │            │
│          │  │      estoque     │            │
└──────────┘  └──────────────────┘            │
                     │                        │
                     ▼                        │
              ┌──────────────────┐            │
              │ estoque_lancado  │            │
              │      = 1         │            │
              └──────────────────┘            │
                                              │
                                              ▼
                              ┌──────────────────────────┐
                              │ CONVERSÃO EM LOTE        │
                              │ (pagamentos.html)        │
                              │ Pedido → NFC-e           │
                              └──────────────────────────┘
\`\`\`

---

## 🔧 TROUBLESHOOTING

### Problema: "Pedido entregue mas sem Bling"
**Verificar:** O pedido tem \`nfce_id\` OU \`bling_pedido_id\`?
- Se tem \`nfce_id\` → Está OK (pagamento à vista)
- Se não tem nenhum → Precisa reprocessar

### Problema: "Estoque não batendo"
**Verificar:**
1. Existem vendas antecipadas contando? → Marcar \`venda_antecipada = 1\`
2. \`estoque_lancado = 0\` mas já deveria ter lançado? → Executar lançamento manual

### Problema: "NFC-e autorizada mas estoque não lançou"
**Solução:** Botão "Lançar Estoque" no painel NFC-e Estoque (auditoria.html)

---

## 📝 VERSÕES RELACIONADAS

| Versão | Mudança |
|--------|---------|
| v2.51.0 | Pagamentos à vista criam NFC-e (não Pedido de Venda) |
| v2.52.51 | "já existe estoque" vira sucesso (skipped) |
| v2.52.61 | Lançamento automático de estoque via cron |
| v2.52.64 | Campo venda_antecipada — exclui do estoque |
