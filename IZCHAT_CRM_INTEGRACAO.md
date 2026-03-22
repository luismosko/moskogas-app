# 📱 Integração MoskoGás ↔ IzChat CRM
> **Versão:** 1.0 | **Data:** 22/03/2026 | **Worker:** v2.52.44

---

## 📋 Índice

1. [Visão Geral](#visão-geral)
2. [Configuração Inicial](#configuração-inicial)
3. [Sincronização de Contatos](#sincronização-de-contatos)
4. [Campos Sincronizados](#campos-sincronizados)
5. [Variáveis para Automação no IzChat](#variáveis-para-automação-no-izchat)
6. [Exemplos de Mensagens Automatizadas](#exemplos-de-mensagens-automatizadas)
7. [Endpoints da API](#endpoints-da-api)
8. [Troubleshooting](#troubleshooting)

---

## 🎯 Visão Geral

A integração MoskoGás ↔ IzChat permite sincronizar os dados dos clientes do MoskoGás para o IzChat CRM. Isso possibilita:

- **Bina Virtual**: Quando um cliente entra em contato, você já vê o nome dele (não apenas o número)
- **Dados do Cliente**: Endereço, bairro, referência e última compra disponíveis no IzChat
- **Automação**: Usar os dados em fluxos de atendimento automatizado

### Direção da Sincronização

```
MoskoGás (15.112 clientes) ──────► IzChat CRM
     │                                  │
     │  - Nome do cliente               │
     │  - Endereço completo             │
     │  - Bairro                        │
     │  - Complemento                   │
     │  - Referência                    │
     │  - CPF/CNPJ                      │
     │  - Última compra                 │
     └──────────────────────────────────┘
```

---

## ⚙️ Configuração Inicial

### 1. Obter o Token da Empresa (Company Token)

1. Acesse o IzChat: https://chat.izchat.com.br
2. Vá em **ADMINISTRAÇÃO** → **API / Webhooks**
3. Copie o **Token da Empresa** (company_token)

> ⚠️ **Atenção**: Este token é diferente do token do WhatsApp! O company_token dá acesso à API de contatos.

### 2. Configurar no MoskoGás

1. Acesse: https://moskogas-app.pages.dev/config.html
2. Vá na aba **Integrações**
3. Na seção **💬 IzChat CRM — Sincronização**:
   - Cole o token no campo "TOKEN DA EMPRESA"
   - Clique em **💾 Salvar Token**
   - Clique em **📡 Testar Conexão** para verificar

### 3. Verificar Estatísticas

Clique em **📊 Estatísticas** para ver:
- Total de clientes no MoskoGás
- Status da conexão com IzChat
- Se o token está configurado

---

## 🔄 Sincronização de Contatos

### Sincronização em Lote

1. Na seção **Sincronização em Lote**, escolha o tamanho do lote:
   - **25 clientes**: Mais lento, mais estável
   - **50 clientes**: Equilíbrio (recomendado)
   - **100 clientes**: Mais rápido, pode dar timeout

2. Clique em **▶️ Iniciar Sincronização**

3. Acompanhe o progresso:
   - ✅ Criados: Novos contatos adicionados ao IzChat
   - 🔄 Atualizados: Contatos existentes com dados atualizados
   - ⏭️ Ignorados: Contatos sem dados válidos
   - ❌ Erros: Falhas na sincronização

4. Se der "Failed to fetch", clique novamente — continua de onde parou

### Lógica da Sincronização

Para cada cliente do MoskoGás:

1. **Busca no IzChat** por telefone
2. Se **não existe**: Cria novo contato
3. Se **existe**: Atualiza os dados

---

## 📝 Campos Sincronizados

### Mapeamento MoskoGás → IzChat

| Campo MoskoGás | Tipo no IzChat | Nome do Campo |
|----------------|----------------|---------------|
| `name` | Principal | `name` (nome do contato) |
| `phone_digits` | Principal | `number` (telefone) |
| `email` | Principal | `email` |
| `address_line` | Dados Adicionais | `Endereco` |
| `bairro` | Dados Adicionais | `Bairro` |
| `complemento` | Dados Adicionais | `Complemento` |
| `referencia` | Dados Adicionais | `Referencia` |
| `cpf_cnpj` | Dados Adicionais | `CPF_CNPJ` |
| `ultima_compra_glp` | Dados Adicionais | `Ultima_Compra` |

### Exemplo de Contato no IzChat

```
Nome: João Silva
Telefone: 5567999991234
Email: joao@email.com

Dados Adicionais:
├── Endereco: Rua das Flores, 123
├── Bairro: Centro
├── Complemento: Apto 2
├── Referencia: Próximo ao mercado
├── CPF_CNPJ: 123.456.789-00
└── Ultima_Compra: P13 - 15/03/2026
```

---

## 🤖 Variáveis para Automação no IzChat

### Variáveis Disponíveis

Use estas variáveis nos fluxos de automação do IzChat:

| Variável | Descrição | Exemplo |
|----------|-----------|---------|
| `{{contact.name}}` | Nome do cliente | João Silva |
| `{{contact.number}}` | Telefone | 5567999991234 |
| `{{contact.email}}` | E-mail | joao@email.com |
| `{{contact.extraInfo.Endereco}}` | Endereço | Rua das Flores, 123 |
| `{{contact.extraInfo.Bairro}}` | Bairro | Centro |
| `{{contact.extraInfo.Complemento}}` | Complemento | Apto 2 |
| `{{contact.extraInfo.Referencia}}` | Referência | Próximo ao mercado |
| `{{contact.extraInfo.CPF_CNPJ}}` | CPF ou CNPJ | 123.456.789-00 |
| `{{contact.extraInfo.Ultima_Compra}}` | Última compra | P13 - 15/03/2026 |

### Sintaxe Importante

- Os nomes dos campos em `extraInfo` são **case-sensitive**
- Use exatamente: `Endereco`, `Bairro`, `Complemento`, `Referencia`, `CPF_CNPJ`, `Ultima_Compra`
- Se o campo estiver vazio, a variável mostra em branco

---

## 💬 Exemplos de Mensagens Automatizadas

### 1. Saudação Personalizada

```
Olá {{contact.name}}! 👋

Bem-vindo à MoskoGás! Como posso ajudar você hoje?

1️⃣ Fazer um pedido
2️⃣ Consultar preços
3️⃣ Falar com atendente
```

### 2. Confirmação de Endereço

```
{{contact.name}}, confirma os dados da entrega?

📍 *Endereço:* {{contact.extraInfo.Endereco}}
🏘️ *Bairro:* {{contact.extraInfo.Bairro}}
🏠 *Complemento:* {{contact.extraInfo.Complemento}}
📌 *Referência:* {{contact.extraInfo.Referencia}}

Responda:
✅ *SIM* para confirmar
❌ *NÃO* para alterar o endereço
```

### 3. Lembrete de Recompra

```
Olá {{contact.name}}! 🔥

Já faz um tempinho desde sua última compra:
📦 {{contact.extraInfo.Ultima_Compra}}

Está precisando de gás? Temos entrega rápida para o {{contact.extraInfo.Bairro}}!

Responda *QUERO* para fazer um pedido agora.
```

### 4. Confirmação de Pedido

```
✅ *Pedido Confirmado!*

Cliente: {{contact.name}}
📍 {{contact.extraInfo.Endereco}}, {{contact.extraInfo.Bairro}}
{{contact.extraInfo.Complemento}}
Ref: {{contact.extraInfo.Referencia}}

🚚 Entrega em até 30 minutos!
```

### 5. Pesquisa de Satisfação

```
Olá {{contact.name}}! 

Como foi sua experiência com a MoskoGás?

Dê uma nota de 1 a 5:
⭐ 1 - Péssimo
⭐⭐ 2 - Ruim  
⭐⭐⭐ 3 - Regular
⭐⭐⭐⭐ 4 - Bom
⭐⭐⭐⭐⭐ 5 - Excelente
```

### 6. Campanha de Marketing

```
🔥 *PROMOÇÃO EXCLUSIVA* 🔥

{{contact.name}}, cliente especial do bairro {{contact.extraInfo.Bairro}}!

Só hoje: P13 com desconto especial!
Entrega grátis no seu endereço.

Responda *QUERO* para aproveitar!
```

### 7. Aviso de Manutenção

```
⚠️ *Aviso Importante*

{{contact.name}}, informamos que haverá manutenção 
programada na sua região ({{contact.extraInfo.Bairro}}) 
no dia XX/XX.

Garanta seu gás antes! 
Responda *PEDIDO* para fazer seu estoque.
```

---

## 🔌 Endpoints da API

### Configuração do Token

```
POST /api/izchat/config
Body: { "token": "seu_company_token" }
```

```
GET /api/izchat/config
Response: { "ok": true, "token": "c6c6...5857" }
```

### Estatísticas

```
GET /api/izchat/stats
Response: {
  "ok": true,
  "token_configured": true,
  "izchat_connected": true,
  "moskogas_total": 15112,
  "moskogas_with_name": 15112
}
```

### Buscar Contato no IzChat

```
GET /api/izchat/contacts/search?phone=5567999991234
Response: {
  "ok": true,
  "found": true,
  "contact": { "id": 123, "name": "João", ... }
}
```

### Sincronizar Um Contato

```
POST /api/izchat/contacts/sync
Body: { "phone": "5567999991234" }
Response: {
  "ok": true,
  "action": "updated",
  "contact_id": 123
}
```

### Sincronização em Lote

```
POST /api/izchat/contacts/sync-batch
Body: {
  "limit": 50,
  "offset": 0,
  "only_with_name": true
}
Response: {
  "ok": true,
  "total": 50,
  "created": 45,
  "updated": 3,
  "skipped": 0,
  "errors": [],
  "next_offset": 50
}
```

---

## 🔧 Troubleshooting

### Erro "Failed to fetch"

**Causa**: Timeout de rede ou limite do Worker (30s)

**Solução**: 
- Reduza o tamanho do lote para 25
- Clique novamente — continua de onde parou

### Token não reconhecido

**Causa**: Usando o token errado (WhatsApp vs Company)

**Solução**:
1. Vá em IzChat → ADMINISTRAÇÃO → API / Webhooks
2. Copie o **Token da Empresa**, não o do WhatsApp
3. Salve novamente no config.html

### Contato não atualiza

**Causa**: Conflito de dados ou contato bloqueado

**Solução**:
- Verifique se o telefone está no formato `5567XXXXXXXXX`
- O contato precisa existir no MoskoGás com dados válidos

### Variável mostra em branco

**Causa**: Campo não preenchido no MoskoGás

**Solução**:
- Verifique se o cliente tem o dado cadastrado
- Re-sincronize o contato específico

---

## 📊 Tokens e Configurações

### Tokens IzChat (2 tipos diferentes!)

| Token | Uso | Onde encontrar |
|-------|-----|----------------|
| **whatsapp_token** | Enviar mensagens WhatsApp | Conexões WhatsApp |
| **company_token** | API de contatos (sincronização) | ADMINISTRAÇÃO → API/Webhooks |

### Token do Luis (company_token)

```
c6c6383d2dcba4a4214026ffd628cc708c44eb40a68486d07dc7994d2c5e5857
```

---

## 📅 Histórico de Implementação

| Data | Versão | Mudança |
|------|--------|---------|
| 22/03/2026 | v2.52.42 | Implementação inicial da integração |
| 22/03/2026 | v2.52.43 | Delay aumentado para 500ms |
| 22/03/2026 | v2.52.44 | Stats mostra conexão (API não suporta count) |

---

## 🔗 Links Úteis

- **MoskoGás Config**: https://moskogas-app.pages.dev/config.html
- **IzChat CRM**: https://chat.izchat.com.br
- **API IzChat Docs**: Spec interna `izchat_api_spec_v1_0.yaml`

---

*Documentação gerada em 22/03/2026 por Claude (Anthropic)*
