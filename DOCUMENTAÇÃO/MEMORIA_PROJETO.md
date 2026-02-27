# SUGESTÕES PARA USER MEMORIES

## Cole estas informações no campo "User Memories" ou "Custom Instructions"

---

## 🎯 Contexto do Projeto

MoskoGás é um sistema web para gestão de pedidos de gás/água desenvolvido por Luis Cesar Mosko. Stack: Cloudflare Workers + D1 + R2, integrando Bling ERP (fiscal) e IzChat (WhatsApp).

---

## 🔧 Stack Técnico

- **Backend:** Cloudflare Worker (ES Module) em https://api.moskogas.com.br
- **Banco:** D1 (moskogas_ops)
- **Storage:** R2 (moskogas-comprovantes)
- **ERP:** Bling v3 API (OAuth 2.0)
- **WhatsApp:** IzChat API
- **Frontend:** HTML estático em GitHub Pages

---

## 💡 Preferências de Desenvolvimento

- **Versionamento obrigatório:** Sempre incrementar versão em TODO arquivo editado (HTML: badge visível, JS: comentário no topo)
- **Deploy:** GitHub Pages para HTML, Wrangler para Worker
- **Prioridade:** Velocidade operacional > Complexidade técnica
- **UX:** Interface simples, botões grandes, poucos cliques
- **Sem CLI complicada:** Preferir dashboard web quando possível

---

## ⚠️ Decisões Arquiteturais Importantes

1. **NFCe NÃO tem API direta no Bling v3** → Operador emite em lote 1x/dia no painel
2. **Webhook NFCe descartado** → Complexidade desnecessária
3. **Sistema de pagamentos sem webhook** → Regra: `bling_pedido_id` existe = venda criada
4. **Cidade sempre Campo Grande/MS** → Hardcoded, não exibir na UI

---

## 🗂️ Estrutura de Arquivos

```
worker.js (v2.7.0) — Backend principal
pedido.html (v2.4.2) — Formulário de pedido
gestao.html — Admin de pedidos
pagamentos.html (v1.0.0) — Gestão de pagamentos
impressao.html — Recibo A4
```

---

## 🔑 Configurações Bling

- Consumidor Final ID: 726746364
- Formas de pagamento mapeadas (23368=Dinheiro, 23465=PIX, etc)
- Token auto-refresh via cron (5h)
- OAuth callback: https://api.moskogas.com.br/bling/oauth/callback

---

## 📊 Sistema de Pagamentos (v2.7.0)

- **À vista (dinheiro/PIX):** Cria Bling + marca pago
- **PIX a receber:** Cria Bling + aguarda confirmação (aparece em Pagamentos)
- **Mensalista/Boleto:** NÃO cria Bling agora (aparece em Pagamentos)

Campos D1: `tipo_pagamento TEXT`, `pago INTEGER DEFAULT 0`

---

## 🚫 Erros Comuns a Evitar

1. Tentar usar endpoint `/nfces` (não existe)
2. Esquecer versão em arquivos editados
3. Confundir `bling_pedido_num` (número visível) com `bling_pedido_id` (ID interno)
4. Form reset sem null check
5. Usar web search para acessar designs Bling (não funciona, precisa API)

---

## 📞 Contatos de Suporte

- Bling Developer: https://developer.bling.com.br
- IzChat: API própria (token em secrets)
- Luis: empresário local Campo Grande/MS, não é programador, prefere interfaces web

---

## ✅ Workflow Padrão

1. Sempre começar lendo transcript anterior se existir
2. Incrementar versão em arquivos editados
3. Consultar MANUAL_TECNICO_MOSKOGAS.pdf antes de implementar
4. Testar lógica antes de entregar
5. Apresentar files com present_files ao final
