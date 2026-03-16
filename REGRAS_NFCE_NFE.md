# REGRAS DE EMISSÃO NFC-e / NF-e — MoskoGás

> **Atualizado em:** 16/03/2026 | **Worker:** v2.52.24

## 📋 RESUMO POR TIPO DE PAGAMENTO

| Tipo Pagamento | Gera NFC-e ao Entregar? | Onde gera? | Observação |
|----------------|-------------------------|------------|------------|
| 💵 Dinheiro | ✅ SIM | Automático | Gera NFC-e ao marcar ENTREGUE |
| ⚡ PIX à Vista | ✅ SIM | Automático | Gera NFC-e ao marcar ENTREGUE |
| ⏳ PIX a Receber | ❌ NÃO | Modal Pagamentos | Gera ao confirmar pagamento (escolhe NFC-e ou NF-e) |
| 💳 Débito | ✅ SIM | Automático | Gera NFC-e ao marcar ENTREGUE |
| 💳 Crédito | ✅ SIM | Automático | Gera NFC-e ao marcar ENTREGUE |
| 📅 Mensalista | ❌ NÃO | Lote (NF-e) | Venda Bling criada em lote no final do mês |
| 🧾 Boleto/Órgão | ❌ NÃO | Lote (NF-e) | Venda Bling criada em lote |
| 🎫 Vale Gás | ❌ NÃO | Lote | Faturado via empenho/nota de vales |

---

## 🔄 FLUXO DETALHADO

### Pagamentos À VISTA (Dinheiro, PIX Vista, Débito, Crédito)
```
Pedido criado → Encaminhado → Entregador marca ENTREGUE
                                    ↓
                              Sistema gera NFC-e automaticamente
                                    ↓
                              [OK] → nfce_status = 'emitida'
                              [ERRO] → Vai para NFC-e Pendentes (retry até 5x)
```

### PIX A RECEBER
```
Pedido criado → Encaminhado → Entregador marca ENTREGUE
                                    ↓
                              ⚠️ NÃO gera NFC-e
                              Vai para tela PAGAMENTOS
                                    ↓
                              Atendente clica "✅ Pago"
                                    ↓
                              Modal pergunta:
                              ┌──────────────────────────────────┐
                              │ 📄 Emitir NFC-e agora           │ → Gera NFC-e
                              │ 📑 Criar NF-e / Pedido de Venda │ → Gera NF-e grande
                              │ ⏭️ Sem documento fiscal         │ → Só marca pago
                              └──────────────────────────────────┘
```

### MENSALISTA / BOLETO
```
Pedido criado → Entregue → Vai para PAGAMENTOS (pendente)
                                    ↓
                              Atendente cria venda Bling em lote
                              (botão "Criar Vendas Bling")
                                    ↓
                              NF-e emitida manualmente no Bling
```

---

## 🛠️ IMPLEMENTAÇÃO NO CÓDIGO

### Query de NFC-e Pendentes (worker.js)
```sql
-- Tipos que geram NFC-e automática ao entregar:
tipo_pagamento IN ('dinheiro', 'pix_vista', 'debito', 'credito')

-- pix_receber NÃO está incluído!
```

### Função mark-delivered (worker.js)
```javascript
// Tipos que criam NFC-e ao marcar entregue:
const tiposComNfce = ['dinheiro', 'pix_vista', 'debito', 'credito'];
if (tiposComNfce.includes(tipo_pagamento)) {
  // Dispara emitirNFCeBling()
}
```

### Modal Pagamentos (pagamentos.html)
```javascript
// Ao confirmar pagamento de pix_receber:
// 1. "Emitir NFC-e agora" → chama /api/nfce/retry/{orderId}
// 2. "Criar NF-e" → chama /api/bling/criar-venda + marca para NF-e
// 3. "Só marcar pago" → só atualiza pago=1
```

---

## ⚠️ IMPORTANTE

1. **pix_receber NUNCA gera NFC-e automática** — decisão é do atendente no modal
2. **Mensalista/Boleto NUNCA geram NFC-e** — são NF-e em lote
3. **Erro de NFC-e vai para retry** — máximo 5 tentativas antes de bloquear
4. **NFC-e Pendentes mostra só pedidos com tipos à vista** — não mostra pix_receber

---

## 📝 HISTÓRICO DE MUDANÇAS

| Data | Versão | Mudança |
|------|--------|---------|
| 16/03/2026 | v2.52.24 | Documentado: pix_receber não gera NFC-e automática |
| 16/03/2026 | v2.52.23 | Query corrigida para usar nfce_status/nfce_numero |
| 16/03/2026 | v2.52.20 | Fix: usar api.bling.com.br para tokens JWT |
| 16/03/2026 | v2.52.19 | Fix: enable-jwt no refreshBlingToken |
