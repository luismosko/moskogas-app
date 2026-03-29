# MoskoGás — Changelog 28/03/2026

## Resumo das Sessões (26-28/03/2026)
Implementações principais:
- Sistema de comprovante de pagamento separado do comprovante de entrega
- Versão mobile da tela de pagamentos
- Sistema de múltiplos contatos por cliente corporativo
- Extensão IZGLP com alertas sonoros e badge contador
- Ordenação inteligente na gestão de pedidos
- Diversos endpoints de diagnóstico e correção de dados

---

## 📊 Versões Atuais

| Arquivo | Versão | Função |
|---------|--------|--------|
| **worker.js** | **v2.52.81** | Backend Cloudflare Worker |
| gestao.html | v2.9.35 | Gestão de pedidos |
| pagamentos.html | v1.10.1 | Pagamentos pendentes |
| pedido.html | v2.11.72 | Inserção de pedido |
| entregador.html | v2.6.8 | Painel do entregador |
| config.html | v2.15.4 | Configurações |
| clientes.html | v1.3.2 | Gestão de clientes |
| shared.js | v1.25.8 | Utilitários compartilhados |

---

## 🆕 Novas Funcionalidades

### 1. Comprovante de Pagamento Separado (v2.52.79-81)

**Problema resolvido:** O `foto_comprovante` do entregador é apenas um recibo de entrega assinado. Para pagamentos a prazo (PIX a receber, mensalista, boleto), o atendente precisa anexar um segundo comprovante — o comprovante de pagamento real.

**Implementação:**
| Campo | Quem preenche | O que é |
|-------|---------------|---------|
| `foto_comprovante` | Entregador | Recibo de entrega assinado pelo cliente |
| `comprovante_pagamento` | Atendente/Financeiro | Comprovante de pagamento real (PIX, boleto pago) |

**Novo endpoint:**
```
POST /api/pagamentos/:id/confirmar
Content-Type: multipart/form-data

Campos:
- comprovante (File): Arquivo do comprovante (obrigatório para PIX/Cartão)
- tipo_fiscal (string): 'nfce', 'nfe', ou null
```

**Regras:**
- PIX/Cartão (pix_receber, pix_vista, debito, credito): comprovante **obrigatório**
- Dinheiro: sem comprovante, mas envia **e-mail de alerta** para admin
- Troca de tipo de pagamento após baixa: bloqueado para não-admin

---

### 2. Versão Mobile da Tela de Pagamentos (v1.10.0)

**Botão toggle:** `📱 Baixas` no toolbar

**Funcionalidades:**
- Cards otimizados para celular
- Filtro automático: apenas pendentes
- Botão grande "✅ Confirmar Pagamento"
- Badge de comprovante 💳✓
- Suporte a PIX QR Code

**CSS:**
```css
@media (max-width: 768px) {
  .desktop-only { display: none !important; }
  .mobile-list { display: block; }
}
```

---

### 3. Sistema de Múltiplos Contatos por Cliente (v2.52.78)

**Tabela nova:** `customer_contacts`
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

**Endpoints:**
| Endpoint | Método | Descrição |
|----------|--------|-----------|
| `/api/clientes/:phone/contatos` | GET | Lista contatos do cliente |
| `/api/clientes/:phone/contatos` | POST | Adiciona novo contato |
| `/api/clientes/:phone/contatos/:id` | PUT | Atualiza contato |
| `/api/clientes/:phone/contatos/:id` | DELETE | Remove contato |

**Uso:** Clientes corporativos (ex: "Karina - Sementes Boi Gordo LTDA") podem ter múltiplos contatos. A Bina retorna nome composto.

---

### 4. Ordenação Inteligente na Gestão (gestao.html v2.9.33-34)

**Ordenação padrão por status (prioridade):**
1. 🔴 NOVO (mais urgente)
2. 🟡 ENCAMINHADO
3. 🟢 WHATSAPP ENVIADO
4. 🔵 ENTREGUE
5. ⚪ CANCELADO

**Ordenação secundária:** Mais recente dentro de cada status

**Ordenação clicável:** Clicar no cabeçalho da coluna ordena ASC/DESC

---

### 5. Botão Ver Foto no Modal de Edição (gestao.html v2.9.35)

**Funcionalidade:** Botão verde "📷 Ver Foto" aparece no cabeçalho do modal de edição quando o pedido tem `foto_comprovante`.

**Modal de preview:**
- Imagem em tela cheia
- Link "Abrir em nova aba"
- Fecha ao clicar fora

---

### 6. Extensão IZGLP v2.2.0-2.2.5

**Novas funcionalidades:**
- 🔔 **Som automático** ao detectar novo pedido (MP3 via background worker)
- 🔢 **Badge contador** de alertas pendentes
- 📋 **Painel de alertas pendentes** com lista clicável
- ✓ **"Marcar como Visto"** para dispensar alertas individualmente
- ⏱️ **Scan a cada 3 minutos** (antes era 5)
- 🟠 **Barra laranja** para pedidos cancelados (não cria pedido, só alerta)

---

### 7. Edição de Itens pelo Entregador (v2.52.67 + entregador v2.6.8)

**Configuração:** `config.html > Entregador > Permitir edição de itens`

**Funcionalidade:** Entregador pode adicionar/remover itens antes de marcar entregue (ex: cliente pediu mais 1 botijão na hora).

---

## 🐛 Bugs Corrigidos

### 1. Status case-sensitive (v2.52.74)
- **Problema:** D1 usa lowercase (`entregue`), código usava uppercase (`ENTREGUE`)
- **Sintoma:** Queries retornavam vazio
- **Correção:** Normalizar para lowercase em todas as queries

### 2. Duplicados Consumidor Final (v2.52.70)
- **Problema:** Merge automático juntava clientes diferentes com mesmo nome "CONSUMIDOR FINAL"
- **Correção:** Só merge se MESMO endereço + auditoria completa

### 3. Mobile Nav Dropdown (shared.js v1.25.7)
- **Problema:** Dropdown do usuário não fechava ao tocar fora no mobile
- **Correção:** Listener `touchstart` + `closeMobileNav()` fecha dropdown
- **Extra:** Cores legíveis no dropdown mobile (fundo sólido)

### 4. Banner sem auto-close (shared.js v1.25.8)
- **Problema:** Banners de alerta sumiam muito rápido
- **Correção:** Banner fica até o usuário fechar manualmente

### 5. SQLITE_ERROR comprovante_pagamento (v2.52.81)
- **Problema:** Coluna não existia ao carregar pagamentos
- **Correção:** Migration automática no GET /api/pagamentos

---

## 🔧 Endpoints de Diagnóstico (Temporários)

| Endpoint | Descrição |
|----------|-----------|
| `/api/pub/ver-pedido/:id` | Diagnóstico completo de um pedido |
| `/api/pub/buscar-cliente?q=` | Busca cliente por nome/telefone |
| `/api/pub/corporativos-marco` | Lista clientes CNPJ em março |
| `/api/pub/diagnostico-cliente/:phone` | Diagnóstico completo de cliente |
| `/api/clientes/duplicados` | Detecta clientes com nomes similares |
| `/api/clientes/unificar-grupo` | Merge batch de duplicados |
| `/api/clientes/desfazer-merge/:phone` | Reverte merge problemático |
| `/api/clientes/corrigir-phone` | Unifica telefones inconsistentes |

---

## 📱 IZGLP Extension — Arquivos

| Arquivo | Função |
|---------|--------|
| `manifest.json` | Configuração da extensão (v2.2.5) |
| `background.js` | Service worker (scan, som, badge) |
| `popup.html` | Interface das 3 abas |
| `popup.js` | Lógica do popup |
| `content.js` | Injeção no Ultragaz Hub |
| `styles.css` | Estilos do popup |
| `alert.mp3` | Som de notificação |

---

## 🗄️ Schema D1 — Novas Colunas

### Tabela `orders`
```sql
ALTER TABLE orders ADD COLUMN comprovante_pagamento TEXT DEFAULT NULL;
ALTER TABLE orders ADD COLUMN baixa_por_id INTEGER DEFAULT NULL;
ALTER TABLE orders ADD COLUMN baixa_por_nome TEXT DEFAULT NULL;
ALTER TABLE orders ADD COLUMN baixa_at INTEGER DEFAULT NULL;
```

### Tabela `customer_contacts` (nova)
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
CREATE INDEX idx_customer_contacts_phone ON customer_contacts(phone_digits);
```

---

## 📧 E-mail de Alerta — Pagamento em Dinheiro

**Trigger:** Confirmar pagamento com `tipo_pagamento === 'dinheiro'`

**Destinatário:** Config `relatorio_email`

**Conteúdo:**
- Pedido #ID
- Cliente
- Itens
- Valor
- Quem fez a baixa
- Data/hora

---

## 🔐 Regras de Segurança

### Troca de Tipo de Pagamento Após Baixa
- **Atendente/Gerente:** Bloqueado (erro 403)
- **Admin:** Permitido, com log de auditoria

### Evento de Auditoria
```javascript
await logEvent(env, orderId, 'tipo_pagamento_alterado_pos_baixa', {
  de: tipoAnterior,
  para: tipoNovo,
  admin: user.nome
});
```

---

## 📁 Commits desta Sessão

```
b5214b2 v2.9.35: Fix URL do comprovante - usar endpoint /api/comprovante/:id
22198a0 v2.9.35: Botão Ver Foto no modal de edição de pedido
57502c3 v2.52.81: Fix SQLITE_ERROR - migration comprovante_pagamento
015d78e v2.52.80: Campo comprovante_pagamento separado de foto_comprovante
3286e11 v2.52.79/v1.10.0: Pagamentos com comprovante obrigatório + mobile
c346f46 v1.25.8: Banner sem auto-close + som melhorado
6cb3060 v1.25.7: Fix dropdown usuário mobile
74edb48 v2.9.34: Ordenação padrão por Status
c40fcff v2.52.78: Sistema de múltiplos contatos por cliente
b7c5e3c v2.52.77: Endpoint corrigir-phone
dc8d12e v2.52.76: Endpoint ver-pedido para diagnóstico
4baf690 v2.2.0: IZGLP som automático + badge contador
68ccffb v2.1.0: IZGLP manifest.json restaurado
6524eed v2.1.0: IZGLP Hub scan 3min + alertas pendentes
cbf0dd9 v2.52.75: Endpoints buscar-cliente e unificar-clientes
cbe0d1d v2.52.74: Fix status lowercase
917b325 v2.52.73: Diagnóstico pedidos março
c3c3adf v2.52.72: Endpoint corporativos marco
3595e3e v2.9.33: Ordenação clicável por coluna
31fb972 v2.52.71: Endpoints diagnóstico e desfazer merge
16d8dd2 v2.52.70: Duplicados CORRIGIDO - consumidor final só merge se MESMO endereço
aa2e9e7 v2.52.69: Duplicados inteligente + Unificar Grupo
91f0b05 v2.52.68: Agente de Duplicados
b3563a9 v2.52.67: Edição de itens pelo entregador configurável
44bd281 v2.11.72 + clientes v1.2.9: CEP auto-fill
```

---

## 🔜 Pendências Futuras

1. [ ] Completar logo IZGLP com texto legível (Ideogram recomendado)
2. [ ] SaaS white-label: instalações separadas por revendedor
3. [ ] Automação `novo-projeto.sh` para criar repos/páginas automaticamente
4. [ ] Análise 80/20 consumo Bling API com `bling-api-log.html`
5. [ ] MoskoLeads: captura de leads comerciais P20/P45
6. [ ] Atualizar telefone no Bling quando editado no sistema
7. [ ] Merge pendente do cliente ALTRI BRASIL

---

## 📋 Fluxo Completo — Pagamento com Comprovante

### PIX/Cartão (a prazo):
1. Entregador entrega → tira foto do **recibo assinado** → `foto_comprovante`
2. Cliente paga depois (PIX transferido)
3. Atendente abre Pagamentos → clica "✅ Pago"
4. Modal exige **comprovante de pagamento** (foto/PDF)
5. Escolhe NFC-e, NF-e ou só marcar pago
6. Sistema salva em `comprovante_pagamento` + marca `pago=1`

### Dinheiro:
1. Entregador entrega → tira foto do recibo
2. Atendente abre Pagamentos → clica "✅ Pago"
3. Sem exigência de comprovante
4. **E-mail de alerta** enviado para admin
5. Sistema marca `pago=1`

---

*Documentação gerada em 28/03/2026*
