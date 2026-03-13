# BLING RATE LIMIT — Guia Crítico MoskoGás
> **Criado em:** 13/03/2026 após incidente de bloqueio de IP  
> **Versão do worker na época:** v2.52.5 → corrigido em v2.52.6 e v2.52.7

---

## ⚠️ LIMITES OFICIAIS DA API BLING

| Regra | Limite | Duração do bloqueio |
|---|---|---|
| Requisições normais | 3 por segundo | Temporário (429) |
| Requisições normais | 120.000 por dia | Temporário (429) |
| **`/oauth/token`** | **20 chamadas em 60 segundos** | **60 minutos** |
| Erros em massa | 300 erros em 10 segundos | 10 minutos |
| Requests em massa | 600 requests em 10 segundos | 10 minutos |
| Abuso contínuo | Ultrapassar limites repetidamente | **Indeterminado** |

**Fonte:** https://developer.bling.com.br/limites

---

## 🚨 INCIDENTE DE 13/03/2026 — O que aconteceu

### Causa raiz (3 problemas combinados)

**1. `obtained_at = 1` colocado propositalmente na sessão anterior**  
Para forçar reconexão, o D1 foi editado com `obtained_at = 1` (equivale a 01/01/1970). Isso fez o sistema achar que o token estava expirado há 55 anos. Resultado: **todo request tentava fazer refresh do token**.

**2. Sem distributed lock no `refreshBlingToken`**  
O Cloudflare Workers roda em múltiplas instâncias paralelas. Quando o token parecia expirado, **todas as instâncias chamavam `/oauth/token` ao mesmo tempo**. Com 2-3 abas abertas no sistema → dezenas de chamadas em segundos → 1015/429.

**3. TTL de cache simétrico no `/bling/ping`**  
O ping é chamado a cada 60s pelo frontend. O backend verificava a API real a cada 5 minutos — **mesmo quando `bling_real_ok=false`**. Durante o bloqueio de 60 minutos, isso gerava 12 novas tentativas batendo no IP bloqueado, podendo **estender o bloqueio indefinidamente**.

### Linha do tempo
```
Ontem (sessão anterior):
  → obtained_at definido como 1 para forçar reconexão
  
Esta manhã (13/03):
  → Luis abre o sistema (gestão + config = 2 abas)
  → Cada aba chama /bling/ping → backend vê minutesLeft = -28 milhões
  → Todas as instâncias tentam refresh simultaneamente
  → Bling conta > 20 chamadas /oauth/token em 60s
  → IP do Worker bloqueado por 60 minutos
  → Erro retornado: "error code: 1015" (Cloudflare bloqueou o IP)
```

---

## ✅ CORREÇÕES IMPLEMENTADAS

### v2.52.5 — Proteção duplo callback OAuth
Código de autorização OAuth usado 2 vezes → Bling invalida o token → tentativa de refresh → 429.  
**Fix:** one-time-use no callback: armazena o código em `app_config`, segunda tentativa retorna página de aviso.

### v2.52.6 — Distributed lock + threshold cron corrigido
```javascript
// REGRA: refreshBlingToken tem lock distribuído via D1
// Apenas 1 instância faz a chamada; as demais aguardam 2.5s e reutilizam o token dela
// Chave no D1: bling_refresh_lock (timestamp da instância que adquiriu)
// Lock expira automaticamente após 25 segundos (stale lock protection)

// REGRA: cron renova só quando faltam < 60 minutos (era 240 = renovava por 4h seguidas)
// Com cron a cada 30 min, token de 6h só é renovado na janela final
```

### v2.52.7 — TTL assimétrico no /bling/ping
```javascript
// TTL quando ok=true:  5 minutos (verifica com frequência — token pode expirar)
// TTL quando ok=false: 30 minutos (NÃO bater em API bloqueada durante cooldown)
// Isso garante que durante bloqueio de 60min, no máximo 2 verificações reais ocorrem
```

---

## 🔴 REGRAS ABSOLUTAS — NUNCA FAZER

### ❌ NUNCA editar `obtained_at` para forçar reconexão
```sql
-- PROIBIDO — causa flood de refresh ao abrir o sistema
UPDATE bling_tokens SET obtained_at = 1 WHERE id = 1;

-- CORRETO — limpar cache de validação apenas
UPDATE app_config SET value='false' WHERE key='bling_real_ok';
UPDATE app_config SET value='0' WHERE key='bling_real_checked_at';
-- E pedir ao Luis para reconectar via Config → Bling
```

### ❌ NUNCA fazer múltiplas chamadas a /oauth/token em loop
O limite é 20 chamadas em 60 segundos. Qualquer retry automático deve ter:
- Mínimo 5 segundos entre tentativas
- Máximo 3 tentativas por ciclo
- Lock distribuído para instâncias paralelas

### ❌ NUNCA ignorar o `bling_refresh_lock`
Se o lock está ativo (valor != '0' e age < 25s), aguardar e reutilizar o token da instância que está renovando.

---

## 🟡 SE O BLOQUEIO ACONTECER — Protocolo de recuperação

### 1. Identificar o tipo de bloqueio
```
Erro 1015 → Cloudflare bloqueou o IP do Worker (excesso de requests)
Erro 429  → Bling recusou diretamente (rate limit da API)
Duração:  → 60 minutos para /oauth/token; 10 min para outros
```

### 2. PARAR imediatamente de tentar reconectar
- Fechar todas as abas do sistema
- NÃO clicar em reconectar várias vezes
- O sistema ficará com banner "Bling desconectado" — isso é normal

### 3. Aguardar o cooldown completo
- Mínimo 60 minutos após o último erro 429
- Com v2.52.7+, o ping para de bater no Bling por 30 minutos automaticamente

### 4. Reconectar UMA ÚNICA VEZ
- Config → Bling → Reconectar
- Abrir em UMA aba apenas
- Autorizar e fechar o popup imediatamente

---

## 🟢 MODO OFFLINE BLING — O sistema SEM o Bling conectado

### O que FUNCIONA normalmente sem Bling

| Função | Status | Observação |
|---|---|---|
| Criar pedido | ✅ 100% | Salvo no D1, nada usa Bling |
| Gestão (encaminhar, cancelar) | ✅ 100% | Independente |
| WhatsApp ao entregador/cliente | ✅ 100% | Via IzChat, independente |
| Marcar ENTREGUE | ✅ 100%* | *Pedido salvo; NFC-e fica pendente |
| Pagamentos (marcar pago) | ✅ 100%* | *Registro interno; Bling fica pendente |
| Relatório diário por email | ✅ 100% | Dados do D1 |
| Vale Gás (criar/baixar) | ✅ 100% | Sem NF-e |
| Estoque | ✅ 100% | Sem importação de compras Bling |
| Dashboard | ✅ 100% | Dados locais |

### O que fica PENDENTE (resolve depois)

| Função | Impacto | Como resolver depois |
|---|---|---|
| NFC-e automática | Não emitida | Emitir manualmente via Bling direto |
| Venda no Bling | Não criada | Usar "Criar Vendas Bling" em Pagamentos |
| Contatos novos | Não sincronizados | Sync manual em Clientes |

### Como identificar pedidos sem NFC-e
```sql
-- Pedidos ENTREGUES sem NFC-e (dinheiro/pix/débito/crédito)
SELECT id, customer_name, total_value, tipo_pagamento, delivered_at
FROM orders
WHERE status = 'ENTREGUE'
  AND tipo_pagamento IN ('dinheiro','pix_vista','debito','credito')
  AND (nfce_id IS NULL OR nfce_id = '')
  AND delivered_at > (unixepoch() - 86400)
ORDER BY delivered_at DESC;
```

---

## 📋 CHECKLIST PARA O CLAUDE — Antes de mexer no token Bling

- [ ] Nunca editar `obtained_at` diretamente no banco
- [ ] Para "forçar reconexão": limpar `bling_real_ok` e `bling_real_checked_at` apenas
- [ ] Confirmar que `bling_refresh_lock = '0'` antes de qualquer refresh manual
- [ ] Se houver erro 429: aguardar 60min, depois orientar Luis a reconectar via UI
- [ ] Jamais abrir múltiplas abas do painel OAuth ao mesmo tempo

---

## 📊 Arquitetura do controle de token (v2.52.7+)

```
Frontend (cada aba)
  └─ /bling/ping a cada 60s
       └─ Backend verifica cache D1:
            ├─ ok=true  + age < 5min  → retorna cached (sem chamar Bling)
            ├─ ok=false + age < 30min → retorna cached (SEM BATER NA API BLOQUEADA)
            └─ cache expirado → chama GET /situacoes/modulos (1 req, não /oauth/token)
                 ├─ 401 → refreshBlingToken() com LOCK distribuído
                 └─ ok  → atualiza cache

Cron (a cada 30 min)
  └─ keepBlingTokenFresh()
       └─ minutesLeft < 60? → refreshBlingToken() com LOCK distribuído
            └─ LOCK: só 1 instância chama /oauth/token
                     outras aguardam 2.5s e reutilizam token novo
```

---

## 🔗 Links de referência
- Limites API Bling: https://developer.bling.com.br/limites
- Worker em produção: https://api.moskogas.com.br
- Ping manual: https://api.moskogas.com.br/bling/ping
- Keep-alive (UptimeRobot): https://api.moskogas.com.br/api/bling/keep-alive
