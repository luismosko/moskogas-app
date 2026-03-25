# 🤖 GUIA DE CONFIGURAÇÃO — Agente IA MoskoGás no IzChat

## ✅ PRÉ-REQUISITOS (já feito)

| Item | Status |
|------|--------|
| Endpoints IA no Worker | ✅ v2.52.52 |
| Tabela delivery_zones | ✅ 51 bairros |
| Tela areas.html | ✅ Para gerenciar bairros |
| System Prompt | ✅ docs/IA_SYSTEM_PROMPT.md |
| Base de Conhecimento | ✅ docs/IA_BASE_CONHECIMENTO.md |

---

## 🔧 PASSO 1 — Criar o Agente de IA no IzChat

1. Acesse **IzChat → Configurações → Agentes de IA**
2. Clique em **"+ Novo Agente"**
3. Configure:

| Campo | Valor |
|-------|-------|
| **Nome** | MoskoGás IA |
| **Modelo** | GPT-4o Mini |
| **Chave OpenAI** | (sua chave) |

---

## 🔧 PASSO 2 — Colar o System Prompt

No campo **"Prompt do Sistema"**, cole o conteúdo abaixo:

```
Você é a Assistente Virtual da MoskoGás, revenda oficial Ultragaz em Campo Grande/MS.
Seu nome é "Gabi" (opcional).
Você atende pedidos de gás de cozinha (P13, P20, P45) e água mineral (galão 20L).

TOM DE VOZ:
- Simpática, objetiva e eficiente
- Use emojis com moderação (🔥 para gás, 💧 para água, ✅ para confirmações)
- Nunca seja robótica ou formal demais
- Trate o cliente pelo primeiro nome quando souber

HORÁRIO:
- Segunda a Sexta: 8h às 18h
- Sábado: 8h às 12h
- Domingo: Fechado

FLUXO:
1. Cumprimente e pergunte o que deseja (gás ou água)
2. Verifique se o cliente já está cadastrado (use a ferramenta de busca)
3. Confirme o endereço e bairro
4. Verifique se entregamos naquele bairro (use a ferramenta)
5. Confirme o pedido com todos os dados
6. Crie o pedido no sistema (use a ferramenta)
7. Informe que um atendente vai confirmar

QUANDO TRANSFERIR PARA HUMANO:
- Cliente quer P20 ou P45 (industrial)
- Cliente em bairro Zona 3 com pedido grande
- Cliente reclama ou está insatisfeito
- Dúvidas sobre NF-e, boleto, empenho

NUNCA:
- Invente preços (sempre consulte a ferramenta)
- Prometa prazos de entrega específicos
- Forneça dados de outros clientes
```

---

## 🔧 PASSO 3 — Fazer Upload da Base de Conhecimento

1. Na seção **"Base de Conhecimento"**, clique em **"+ Adicionar arquivo"**
2. Faça upload do arquivo `IA_BASE_CONHECIMENTO.md` (ou copie o conteúdo para um .txt)
3. Aguarde o processamento

---

## 🔧 PASSO 4 — Configurar Tool "Acesso à Web"

Esta é a parte mais importante! O agente precisa acessar suas APIs.

1. Na seção **"Ferramentas"**, habilite **"Acesso à Web"**
2. Configure as URLs permitidas:

### URLs para cadastrar:

```
https://api.moskogas.com.br/api/pub/ia/cliente
https://api.moskogas.com.br/api/pub/ia/precos
https://api.moskogas.com.br/api/pub/ia/bairros
https://api.moskogas.com.br/api/pub/ia/verificar-entrega
https://api.moskogas.com.br/api/pub/ia/horario
https://api.moskogas.com.br/api/pub/ia/criar-pedido
```

3. Na descrição de cada ferramenta, explique o que ela faz:

| URL | Descrição para a IA |
|-----|---------------------|
| `/ia/cliente?phone=NUMERO` | Busca dados do cliente pelo telefone. Retorna nome, endereço, bairro se encontrado. |
| `/ia/precos` | Lista todos os produtos e preços atuais. Use sempre antes de falar preços. |
| `/ia/bairros` | Lista todos os bairros e suas zonas de entrega (1, 2 ou 3). |
| `/ia/verificar-entrega?bairro=X&produto=Y&quantidade=Z` | Verifica se entregamos determinado produto naquele bairro. Retorna se atende e mensagem. |
| `/ia/horario` | Verifica se estamos abertos agora e mostra horários de funcionamento. |
| `/ia/criar-pedido` | Cria um novo pedido no sistema. Enviar POST com JSON: {telefone, nome, endereco, bairro, produto, quantidade} |

---

## 🔧 PASSO 5 — Configurar Detecção de Intenções

Configure ações automáticas para transferir quando necessário:

| Intenção | Ação |
|----------|------|
| "falar com atendente" | Transferir para Fila "Atendimento" |
| "p20" ou "p45" | Transferir para Fila "Comercial" |
| "reclamação" ou "problema" | Transferir para Fila "Atendimento" |
| "nota fiscal" ou "boleto" | Transferir para Fila "Financeiro" |

---

## 🔧 PASSO 6 — Integrar no Fluxo Existente

Seu fluxo atual tem o menu:
```
1 - Gás
2 - Água
3 - Outros assuntos
4 - Gás do Povo
5 - Currículo e Vagas
```

**Altere as opções 1 e 2:**

1. **Edite a opção "1 - Gás"**
   - Em vez de ir para uma mensagem fixa, direcione para o **Bloco "Agente de IA"**
   - Selecione o agente "MoskoGás IA"

2. **Edite a opção "2 - Água"**
   - Mesmo processo: direcione para o **Bloco "Agente de IA"**

3. **Opção "3 - Outros assuntos"**
   - Mantém indo para Fila de Atendimento (humano)

---

## 🧪 PASSO 7 — Testar

1. Envie uma mensagem para o WhatsApp da MoskoGás
2. Escolha opção 1 (Gás)
3. O agente IA deve responder
4. Teste os cenários:
   - Pedir gás em bairro Zona 1 (deve funcionar)
   - Pedir água em bairro Zona 2 (deve avisar que não entrega 1 galão)
   - Pedir P45 (deve transferir para humano)

---

## 🔗 TESTE AS URLs DIRETAMENTE

Antes de configurar, teste no navegador:

### 1. Preços
```
https://api.moskogas.com.br/api/pub/ia/precos
```
Deve retornar JSON com lista de produtos e preços.

### 2. Bairros
```
https://api.moskogas.com.br/api/pub/ia/bairros
```
Deve retornar JSON com 51 bairros e suas zonas.

### 3. Verificar entrega
```
https://api.moskogas.com.br/api/pub/ia/verificar-entrega?bairro=Estrela%20Dalva&produto=p13&quantidade=1
```
Deve retornar `{"atende": true, ...}`

### 4. Horário
```
https://api.moskogas.com.br/api/pub/ia/horario
```
Deve retornar se está aberto ou fechado agora.

---

## ⚠️ TROUBLESHOOTING

### IA não responde
- Verifique se a chave OpenAI está válida
- Verifique se o agente está ativo

### IA não consegue acessar as URLs
- Verifique se as URLs estão corretas (sem espaços)
- Teste as URLs no navegador primeiro
- Verifique se o Worker está no ar: https://api.moskogas.com.br/health

### IA inventa preços
- Certifique-se que o Tool "Acesso à Web" está habilitado
- Adicione no System Prompt: "NUNCA invente preços. SEMPRE use a ferramenta /ia/precos"

### Cliente não é encontrado
- O endpoint busca pelo número de telefone
- O número deve estar no formato: 67999999999 (com DDD, sem 55)

---

## 📊 MONITORAMENTO

### Ver pedidos criados pela IA
Acesse **gestao.html** e filtre por vendedor "IA WhatsApp"

### Gerenciar bairros
Acesse **areas.html** (ADM > Áreas de Entrega)

### Adicionar novos bairros
1. Acesse areas.html
2. Clique em "+ Novo Bairro"
3. Preencha nome, zona e produtos que entrega
4. Salvar

---

## 📝 RESUMO

| Etapa | Ação |
|-------|------|
| 1 | Criar Agente IA no IzChat |
| 2 | Colar System Prompt |
| 3 | Upload Base de Conhecimento |
| 4 | Configurar Tool Acesso à Web com as 6 URLs |
| 5 | Configurar intenções de transferência |
| 6 | Editar Fluxo: opções 1 e 2 vão para Agente IA |
| 7 | Testar! |

Pronto! 🎉
