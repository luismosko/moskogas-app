// v2.46.1
// v2.46.1: Marketing suggest-post — OpenAI GPT-4o-mini (substituiu Anthropic)
// v2.46.0: Módulo Marketing — Google OAuth, GMB reviews/posts, sugestão IA, Meta placeholder
// v2.45.4: Avaliação nota baixa — agente IA conversa com cliente (worker só alerta admin)
// v2.45.3: mensagens reais MoskoGás + link Google Review configurado
// v2.43.4: Vales — DELETE /api/vales/notas/:id (admin only)
// v2.42.1
// v2.42.0: Módulo Estoque — contagem manhã, divergência auto, Bling NFe import, cascos, WhatsApp admin
// v2.40.5: Fix requireAuth param order nos endpoints PIX (diagnostico, teste-cobranca, teste-consultar) + endpoint webhook-logs
// MOSKOGAS BACKEND v2 — Cloudflare Worker (ES Module)
// v2.40.3: GET /api/pagamentos suporta ?incluir_pagos=1 (ver pagos no financeiro) + ultima_compra_glp
// v2.40.4: (Cloudflare Quick Edit) PushInPay PIX + webhook + auto-check cron
// v2.38.3: Novos campos customers_cache: ultima_compra_glp + origem (importação GLP Master)
// v2.38.1: PushInPay PIX (substituiu Cora) + webhook + force lembrete
// v2.31.0: Cora PIX — cobrança automática, QR code, webhook pagamento, WhatsApp
// v2.30.0: WhatsApp troca entregador + Venda externa + QR avaliação Google
// v2.28.5: Fix Assinafy — reusa signer existente se email já cadastrado
// v2.28.3: Fix WhatsApp — formatPhoneWA auto em sendWhatsApp + erro detalhado
// v2.28.2: Fix erro Bling detalhado no cadastro + validação CPF/CNPJ frontend
// v2.28.1: Lembretes PIX — saudação variada, {ontem}/{chave_pix}, delay 60s anti-ban
// v2.28.0: Produtos — icon_key (upload ícone R2) + reorder endpoint + serve icon público
// v2.27.1: Remove assinatura/fechamento e opt-out das msgs WhatsApp
// v2.26.0: Lembretes PIX — payment_reminders, envio manual/bulk/cron, config admin
// v2.25.2: Fix auth contratos — bypass requireApiKey para /api/contratos e /api/webhooks
// v2.25.1: Fix IzChat contratos — usar sendWhatsApp (chatapi.izchat.com.br + {number,body})
// v2.25.0: Módulo Contratos Comodato — schema, endpoints, integração Assinafy + IzChat WhatsApp
// v2.24.0: Último pedido cliente + app_products (preços sugeridos MoskoGás)
// v2.23.1: Fix favorites — ensureAuditTable antes de acessar product_favorites
// v2.23.0: Produtos favoritos — tabela product_favorites + GET/POST/DELETE endpoints
// v2.22.1: Fix dashboard date filter (epoch, not text) + porHora BRT conversion
// v2.22.0: GET /api/dashboard (KPIs, status, produtos, pagamentos, vendedores, entregadores, hora)
// v2.21.0: Rate limiting login (5 falhas/15min IP), PATCH /api/auth/me/senha,
//          Permissões atendente expandidas (CRUD atendente+entregador, não admin)
// v2.20.0: Endpoint GET /api/consulta/pedidos (filtros, paginação, resumo, dropdowns)
// v2.19.2: Foto config defaults → WebP 1200px 85% + sharpen
// v2.19.1: Fix /api/config auth check (requireAuth retorna user, não Response)
// v2.19.0: Permissões dinâmicas atendente + fix auth revert/cancel (sessão null)
//          Config 'permissoes' controla: reabrir entregue/cancelado, cancelar, editar entregue
//          WhatsApp admin: notifica em qualquer cancel/revert de não-admin
// v2.18.0: Config dinâmica (app_config) + foto-config público + admin GET/POST config
// v2.17.1: Consumidor Final padrão no Bling (só vincula contato se CPF/CNPJ)
// v2.17.0: Bling só ao ENTREGAR — pedido novo nunca cria venda no Bling
// v2.16.2: Fix comprovante foto 401 — endpoint movido antes do auth gate
// v2.16.1: Fix ReferenceError: user não declarado em cancel/revert/deliver/select-driver
// v2.16.0: Reabrir/cancelar pedido com motivo + auditoria status + alerta WhatsApp admin
// v2.15.0: Entrega com foto obrigatória (R2) + trocar pgto + observação
// v2.14.0: Troca tipo pagamento → auto-cria/deleta venda Bling + confirmação
// v2.13.1: Audit logs com JOIN orders (nome cliente, valor, tipo, bling_num)
// v2.13.0: Sistema de Auditoria Bling — integration_audit table,
//          logBlingAudit em toda operação Bling, observação enriquecida,
//          GET /api/auditoria/diaria, /conciliacao-bling, /log-detalhado
//          Cron snapshot diário audit_snapshots
// v2.12.3: Flags pode_entregar + recebe_whatsapp em app_users
//          /api/drivers filtra por pode_entregar=1 (atendentes podem entregar)
//          WhatsApp skipped se recebe_whatsapp=0
// v2.12.2: Entregadores unificados: /api/drivers agora puxa de app_users
//          Removido POST/PATCH /api/drivers (gerenciar via Usuários)
// v2.12.1: Novas formas pgto: débito, crédito, NFe
//          Editar pedido aceita driver_id (troca entregador)
// v2.12.0: Segurança: endpoints users protegidos por requireAuth admin
//          Rename: gerar-nfe → criar-vendas-bling
//          Limpeza: removido código morto NFCe (não existe na API Bling v3)
//          Fix vendedores: busca contato.nome individual via API
//          Login por usuário/senha, roles (admin/atendente/entregador)
//          Vinculação vendedor Bling em pedidos
// v2.15.0: Entrega com foto obrigatória (R2) + trocar pgto + observação
// v2.14.0: Troca tipo pagamento → auto-cria/deleta venda Bling + confirmação
// v2.13.1: Audit logs com JOIN orders (nome cliente, valor, tipo, bling_num)
// v2.13.0: Sistema de Auditoria Bling — integration_audit table,
//          logBlingAudit em toda operação Bling, observação enriquecida,
//          GET /api/auditoria/diaria, /conciliacao-bling, /log-detalhado
//          Cron snapshot diário audit_snapshots
// v2.12.3: Flags pode_entregar + recebe_whatsapp em app_users
//          /api/drivers filtra por pode_entregar=1 (atendentes podem entregar)
//          WhatsApp skipped se recebe_whatsapp=0
// v2.12.2: Entregadores unificados: /api/drivers agora puxa de app_users
//          Removido POST/PATCH /api/drivers (gerenciar via Usuários)
// v2.12.1: Novas formas pgto: débito, crédito, NFe
//          Editar pedido aceita driver_id (troca entregador)
// v2.12.0: Segurança: endpoints users protegidos por requireAuth admin
//          Rename: gerar-nfe → criar-vendas-bling
//          Limpeza: removido código morto NFCe (não existe na API Bling v3)
//          Fix vendedores: busca contato.nome individual via API
//          Login por usuário/senha, roles (admin/atendente/entregador)
//          Vinculação vendedor Bling em pedidos
// =============================================================

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,PATCH,DELETE,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, X-API-KEY, Authorization',
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...CORS_HEADERS },
  });
}

function err(msg, status = 400) {
  return json({ ok: false, error: msg }, status);
}

// ── Auth: Password hashing (PBKDF2) ──────────────────────────

async function hashPassword(password, salt) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: enc.encode(salt), iterations: 100000, hash: 'SHA-256' }, keyMaterial, 256);
  return btoa(String.fromCharCode(...new Uint8Array(bits)));
}

async function verifyPassword(password, salt, storedHash) {
  const hash = await hashPassword(password, salt);
  return hash === storedHash;
}

function generateToken() {
  const arr = new Uint8Array(32);
  crypto.getRandomValues(arr);
  return Array.from(arr, b => b.toString(16).padStart(2, '0')).join('');
}

async function ensureAuthTables(env) {
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS app_users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nome TEXT NOT NULL,
    login TEXT NOT NULL UNIQUE,
    senha_hash TEXT NOT NULL,
    senha_salt TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'entregador',
    bling_vendedor_id INTEGER,
    bling_vendedor_nome TEXT,
    telefone TEXT,
    pode_entregar INTEGER DEFAULT 0,
    recebe_whatsapp INTEGER DEFAULT 0,
    ativo INTEGER DEFAULT 1,
    created_at INTEGER DEFAULT (unixepoch()),
    updated_at INTEGER DEFAULT (unixepoch())
  )`).run();
  // Migrate: add columns if missing
  await env.DB.prepare("ALTER TABLE app_users ADD COLUMN pode_entregar INTEGER DEFAULT 0").run().catch(() => { });
  await env.DB.prepare("ALTER TABLE app_users ADD COLUMN recebe_whatsapp INTEGER DEFAULT 0").run().catch(() => { });
  // Set defaults: entregadores existentes ganham pode_entregar=1, recebe_whatsapp=1
  await env.DB.prepare("UPDATE app_users SET pode_entregar=1, recebe_whatsapp=1 WHERE role='entregador' AND pode_entregar=0 AND recebe_whatsapp=0 AND ativo=1").run().catch(() => { });
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS auth_sessions (
    token TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    created_at INTEGER DEFAULT (unixepoch()),
    expires_at INTEGER NOT NULL
  )`).run();
  // v2.21.0: Rate limiting
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS login_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL,
    login_usado TEXT,
    sucesso INTEGER DEFAULT 0,
    created_at INTEGER DEFAULT (unixepoch())
  )`).run().catch(() => { });
  await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_login_ip ON login_attempts(ip, created_at)').run().catch(() => { });
}

// ── Rate Limiting (v2.21.0) ───────────────────────────────────

async function checkRateLimit(env, ip) {
  const quinzeMin = Math.floor(Date.now() / 1000) - 900;
  const row = await env.DB.prepare(
    'SELECT COUNT(*) as cnt FROM login_attempts WHERE ip = ? AND sucesso = 0 AND created_at > ?'
  ).bind(ip, quinzeMin).first();
  return (row?.cnt || 0) >= 5;
}

async function logLoginAttempt(env, ip, loginUsado, sucesso) {
  await env.DB.prepare(
    'INSERT INTO login_attempts (ip, login_usado, sucesso) VALUES (?, ?, ?)'
  ).bind(ip, loginUsado || '', sucesso ? 1 : 0).run().catch(() => { });
  // Limpar tentativas antigas (>24h)
  const ontem = Math.floor(Date.now() / 1000) - 86400;
  await env.DB.prepare('DELETE FROM login_attempts WHERE created_at < ?').bind(ontem).run().catch(() => { });
}

async function getSessionUser(request, env) {
  const authHeader = request.headers.get('Authorization') || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : '';
  if (!token) return null;
  const now = Math.floor(Date.now() / 1000);
  const session = await env.DB.prepare('SELECT s.*, u.* FROM auth_sessions s JOIN app_users u ON u.id = s.user_id WHERE s.token = ? AND s.expires_at > ? AND u.ativo = 1').bind(token, now).first();
  return session || null;
}

async function requireAuth(request, env, allowedRoles = null) {
  const url2 = new URL(request.url);
  const apiKey = request.headers.get('X-API-KEY') || url2.searchParams.get('api_key') || '';
  if (apiKey && apiKey === env.APP_API_KEY) {
    return { authType: 'api_key', role: 'admin', id: 0, nome: 'Sistema', bling_vendedor_id: null };
  }
  const user = await getSessionUser(request, env);
  if (!user) return err('Não autenticado', 401);
  if (allowedRoles && !allowedRoles.includes(user.role)) return err('Sem permissão', 403);
  return { authType: 'session', ...user };
}

// ── Token Bling ───────────────────────────────────────────────

async function getTokenRow(env) {
  const row = await env.DB.prepare('SELECT * FROM bling_tokens WHERE id=1').first();
  return row;
}

async function saveToken(env, data) {
  const now = Math.floor(Date.now() / 1000);
  await env.DB.prepare(`
    UPDATE bling_tokens SET
      access_token=?, refresh_token=?, expires_in=?, obtained_at=?
    WHERE id=1
  `).bind(data.access_token, data.refresh_token, data.expires_in || 3600, now).run();
}

async function refreshBlingToken(env, refreshToken) {
  const body = new URLSearchParams({
    grant_type: 'refresh_token',
    refresh_token: refreshToken,
  });
  const resp = await fetch('https://www.bling.com.br/Api/v3/oauth/token', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Authorization: 'Basic ' + btoa(`${env.BLING_CLIENT_ID}:${env.BLING_CLIENT_SECRET}`),
    },
    body,
  });
  if (!resp.ok) {
    const errBody = await resp.text().catch(() => '');
    throw new Error('bling_reauth_required:' + resp.status + ':' + errBody.substring(0, 100));
  }
  const data = await resp.json();
  await saveToken(env, data);
  return data.access_token;
}

async function getValidAccessToken(env) {
  const row = await getTokenRow(env);
  if (!row) throw new Error('no_token');
  const now = Math.floor(Date.now() / 1000);
  const expiresAt = (row.obtained_at || 0) + (row.expires_in || 3600) - 600;
  if (now < expiresAt) return row.access_token;
  console.log('[token] Margem 10min atingida, renovando proativamente...');
  return await refreshBlingToken(env, row.refresh_token);
}

async function blingFetch(path, options = {}, env) {
  const doRequest = async (token) => {
    return fetch(`https://www.bling.com.br/Api/v3${path}`, {
      ...options,
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
        'enable-jwt': '1',
        ...(options.headers || {}),
      },
    });
  };

  let token;
  try {
    token = await getValidAccessToken(env);
  } catch (e) {
    if (e.message === 'no_token' || e.message?.includes('reauth')) {
      return new Response(JSON.stringify({ error: 'bling_reauth_required', message: 'Token Bling expirado. Reautorize em Config → Conectar Bling.' }), { status: 401, headers: { 'Content-Type': 'application/json' } });
    }
    throw e;
  }

  let resp = await doRequest(token);

  if (resp.status === 401) {
    try {
      const row = await getTokenRow(env);
      token = await refreshBlingToken(env, row.refresh_token);
      resp = await doRequest(token);
    } catch (e) {
      return new Response(JSON.stringify({ error: 'bling_reauth_required', message: 'Sessão Bling expirada. Reautorize em Config → Conectar Bling.' }), { status: 401, headers: { 'Content-Type': 'application/json' } });
    }
  }

  return resp;
}

// ── Formas de pagamento mapeadas (IDs do Bling da Mosko Gás) ──────
const FORMAS_PAGAMENTO = {
  dinheiro: { id: 23368, descricao: 'Dinheiro', tipoPagamento: 1 },
  pix: { id: 3138153, descricao: 'PIX (Bradesco)', tipoPagamento: 16 },
  pix_itau: { id: 9052024, descricao: 'ITAU PIX, TED', tipoPagamento: 18 },
  debito: { id: 188552, descricao: 'Cartão Débito', tipoPagamento: 4 },
  credito: { id: 188555, descricao: 'Cartão Crédito', tipoPagamento: 3 },
  fiado: { id: 188534, descricao: 'Duplicata Mercantil', tipoPagamento: 14 },
  pix_aguardando: { id: 9315924, descricao: 'PIX Aguardando (Bradesco)', tipoPagamento: 18 },
};

const CONSUMIDOR_FINAL_ID = 726746364;

// ── Mapeia tipo_pagamento → forma de pagamento Bling ──────────
function getFormaPagamentoForTipo(tipoPg, formaKey, formaId) {
  if (formaId) return formaId;
  if (formaKey && FORMAS_PAGAMENTO[formaKey]) return FORMAS_PAGAMENTO[formaKey].id;
  switch (tipoPg) {
    case 'dinheiro': return FORMAS_PAGAMENTO.dinheiro.id;
    case 'pix_vista': return FORMAS_PAGAMENTO.pix.id;
    case 'pix_receber': return FORMAS_PAGAMENTO.pix_aguardando.id;
    case 'debito': return FORMAS_PAGAMENTO.debito.id;
    case 'credito': return FORMAS_PAGAMENTO.credito.id;
    case 'mensalista': return FORMAS_PAGAMENTO.fiado.id;
    case 'boleto': return FORMAS_PAGAMENTO.fiado.id;
    case 'nfe': return FORMAS_PAGAMENTO.fiado.id;
    default: return FORMAS_PAGAMENTO.dinheiro.id;
  }
}

function buildItemBling(item) {
  const blingId = item.bling_id || item.id || null;
  const code = item.code || item.sku || '';
  const desc = String(item.name || 'Produto').substring(0, 120);
  const qty = parseFloat(item.qty) || 1;
  const price = parseFloat(item.price) || 0;
  const result = {
    descricao: desc,
    quantidade: qty,
    valor: price,
  };
  if (blingId && !isNaN(Number(blingId)) && Number(blingId) > 0) {
    result.produto = { id: Number(blingId) };
  }
  if (code) {
    result.codigo = String(code);
  }
  return result;
}

// ── Cria pedido no Bling (sem NFCe) ──────────────────────────
async function criarPedidoBling(env, orderId, orderData) {
  const { name, items, total_value, forma_pagamento_key, forma_pagamento_id, bling_contact_id, tipo_pagamento, bling_vendedor_id, vendedor_nome, cpf_cnpj } = orderData;
  const today = new Date().toISOString().slice(0, 10);

  const itensBling = (items || []).map(it => buildItemBling(it));

  const fpId = getFormaPagamentoForTipo(tipo_pagamento, forma_pagamento_key, forma_pagamento_id);
  // v2.30.0: Calcular total dos itens (mesmo cálculo do Bling) para evitar divergência
  const totalItens = Math.round(itensBling.reduce((s, i) => s + i.valor * i.quantidade, 0) * 100) / 100;
  const total = totalItens || parseFloat(total_value) || 0;

  const obsVendedor = vendedor_nome ? ` | ${vendedor_nome}` : '';
  const obsTipo = tipo_pagamento ? ` | ${tipo_pagamento}` : '';

  // v2.17.0: Só vincula contato real no Bling se cliente tem CPF/CNPJ
  // Sem CPF → Consumidor Final (evita erro de pendência cadastral na NFCe)
  const usarContatoReal = bling_contact_id && cpf_cnpj && cpf_cnpj.replace(/\D/g, '').length >= 11;

  const pedidoBody = {
    contato: usarContatoReal ? { id: bling_contact_id } : { id: CONSUMIDOR_FINAL_ID, tipoPessoa: 'F' },
    data: today,
    dataSaida: today,
    itens: itensBling,
    parcelas: [{
      formaPagamento: { id: fpId },
      valor: total,
      dataVencimento: today,
    }],
    observacoes: `MoskoGás #${orderId}${obsVendedor}${obsTipo} - ${name}`,
  };

  if (bling_vendedor_id) {
    pedidoBody.vendedor = { id: bling_vendedor_id };
  }

  await logEvent(env, orderId, 'bling_payload', { itens: itensBling, contato: pedidoBody.contato }).catch(() => { });

  const pedidoResp = await blingFetch('/pedidos/vendas', {
    method: 'POST',
    body: JSON.stringify(pedidoBody),
  }, env);

  if (!pedidoResp.ok) {
    const errText = await pedidoResp.text();
    console.error('[Bling] Pedido venda erro:', pedidoResp.status, errText);
    await logEvent(env, orderId, 'bling_error_detail', { status: pedidoResp.status, body: errText.substring(0, 500) }).catch(() => { });
    await logBlingAudit(env, orderId, 'criar_venda', 'error', {
      request_payload: pedidoBody,
      error_message: `HTTP ${pedidoResp.status}: ${errText.substring(0, 300)}`
    });
    throw new Error(`Bling pedido ${pedidoResp.status}: ${errText.substring(0, 300)}`);
  }

  const pedidoData = await pedidoResp.json();
  const bling_pedido_id = pedidoData.data?.id ?? null;
  const bling_pedido_num = pedidoData.data?.numero ?? null;

  await logBlingAudit(env, orderId, 'criar_venda', 'success', {
    bling_pedido_id: String(bling_pedido_id || ''),
    request_payload: pedidoBody,
    response_data: pedidoData
  });

  return { bling_pedido_id, bling_pedido_num };
}

// ── [REMOVIDO v2.12.0] criarPedidoEGerarNFCe — NFCe não existe na API Bling v3 ──

// ── Deletar venda no Bling ──────────────────────────────────────
async function deletarVendaBling(env, orderId, blingPedidoId) {
  if (!blingPedidoId) return { ok: false, reason: 'no_bling_id' };

  const resp = await blingFetch(`/pedidos/vendas/${blingPedidoId}`, {
    method: 'DELETE',
  }, env);

  if (resp.ok || resp.status === 204) {
    await logBlingAudit(env, orderId, 'deletar_venda', 'success', {
      bling_pedido_id: String(blingPedidoId),
      response_data: { status: resp.status }
    });
    return { ok: true };
  }

  const errText = await resp.text().catch(() => '');
  console.error('[Bling] DELETE venda erro:', resp.status, errText);
  await logBlingAudit(env, orderId, 'deletar_venda', 'error', {
    bling_pedido_id: String(blingPedidoId),
    error_message: `HTTP ${resp.status}: ${errText.substring(0, 300)}`
  });
  return { ok: false, status: resp.status, error: errText.substring(0, 300) };
}

// ── PUSHINPAY PIX — Cobrança automática via QR Code ─────────────
// v2.34.0: Integração PushInPay (substituiu Cora)
// API simples: POST /api/pix/cashIn → retorna QR Code imediato
// Webhook: POST automático quando pagamento confirmado
// Secret: PUSHINPAY_TOKEN no Cloudflare

const PUSHINPAY_API = 'https://api.pushinpay.com.br';

function isPixConfigured(env) {
  return !!env.PUSHINPAY_TOKEN;
}

async function pushInPayCreateCharge(env, orderId, totalValue) {
  const amountCentavos = Math.round(parseFloat(totalValue) * 100);
  if (amountCentavos < 100) throw new Error('Valor mínimo PIX: R$1,00');

  const webhookUrl = 'https://api.moskogas.com.br/api/webhooks/pushinpay';

  console.log(`[PushInPay] Criando cobrança pedido #${orderId} - R$${(amountCentavos / 100).toFixed(2)}`);

  const resp = await fetch(`${PUSHINPAY_API}/api/pix/cashIn`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${env.PUSHINPAY_TOKEN}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      value: amountCentavos,
      webhook_url: webhookUrl,
    }),
  });

  const respText = await resp.text();
  let data;
  try { data = JSON.parse(respText); } catch { data = null; }

  if (!resp.ok) {
    console.error(`[PushInPay] Erro ${resp.status}:`, respText.substring(0, 500));
    throw new Error(`PushInPay ${resp.status}: ${(data?.message || respText).substring(0, 300)}`);
  }

  console.log(`[PushInPay] Cobrança criada: ${data?.id} - status: ${data?.status}`);

  await logEvent(env, orderId, 'pushinpay_charge_created', {
    pushinpay_tx_id: data?.id,
    value: amountCentavos,
    has_qrcode: !!data?.qr_code,
  });

  return {
    tx_id: data?.id || null,
    qr_code: data?.qr_code || null,
    qr_code_base64: data?.qr_code_base64 || null,
    status: data?.status || 'created',
  };
}

async function pushInPayCheckStatus(env, txId) {
  const resp = await fetch(`${PUSHINPAY_API}/api/transactions/${txId}`, {
    headers: { 'Authorization': `Bearer ${env.PUSHINPAY_TOKEN}` },
  });
  if (!resp.ok) throw new Error(`PushInPay status check failed: ${resp.status}`);
  return resp.json();
}

async function ensurePixColumns(env) {
  const cols = [
    { name: 'pix_tx_id', def: 'TEXT' },
    { name: 'pix_qrcode', def: 'TEXT' },
    { name: 'pix_qrcode_base64', def: 'TEXT' },
    { name: 'pix_paid_at', def: 'INTEGER' },
    // Legacy Cora columns
    { name: 'cora_invoice_id', def: 'TEXT' },
    { name: 'cora_qrcode', def: 'TEXT' },
    { name: 'cora_paid_at', def: 'INTEGER' },
  ];
  for (const col of cols) {
    await env.DB.prepare(`ALTER TABLE orders ADD COLUMN ${col.name} ${col.def}`).run().catch(() => { });
  }
}

// ── IzChat WhatsApp — Safety Layer v1.0 ──────────────────────
// Proteção contra banimento: rate limiting, circuit breaker,
// variação de mensagem, horário comercial, log de envios.
// TODA mensagem WhatsApp do sistema passa por aqui.

async function ensureWhatsAppTables(env) {
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS whatsapp_send_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    phone TEXT NOT NULL,
    category TEXT DEFAULT 'geral',
    status_code INTEGER,
    wa_ok INTEGER DEFAULT 0,
    blocked INTEGER DEFAULT 0,
    created_at INTEGER DEFAULT (unixepoch())
  )`).run().catch(() => { });
  await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_wsl_created ON whatsapp_send_log(created_at)').run().catch(() => { });
  await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_wsl_phone ON whatsapp_send_log(phone)').run().catch(() => { });
}

async function getWhatsAppSafetyConfig(env) {
  const defaults = {
    habilitado: true,
    max_por_minuto: 25,
    max_por_hora: 100,
    max_por_dia: 200,
    intervalo_min_segundos: 4,
    cooldown_mesmo_numero_horas: 12,
    horario_inicio_brt: 8,
    horario_fim_brt: 18,
    respeitar_horario: true,
    circuit_breaker_minutos: 30
  };
  try {
    const row = await env.DB.prepare("SELECT value FROM app_config WHERE key='whatsapp_safety'").first();
    if (row?.value) return { ...defaults, ...JSON.parse(row.value) };
  } catch (_) { }
  return defaults;
}

// Circuit breaker: verifica se houve 429/bloqueio recente
async function isCircuitBroken(env, config) {
  try {
    const cutoff = Math.floor(Date.now() / 1000) - (config.circuit_breaker_minutos * 60);
    const row = await env.DB.prepare(
      'SELECT COUNT(*) as c FROM whatsapp_send_log WHERE blocked=1 AND created_at > ?'
    ).bind(cutoff).first();
    return (row?.c || 0) > 0;
  } catch (_) { return false; }
}

// Rate limit checks
async function checkRateLimits(env, config, phone) {
  const now = Math.floor(Date.now() / 1000);

  // Por minuto
  const min1 = await env.DB.prepare(
    'SELECT COUNT(*) as c FROM whatsapp_send_log WHERE created_at > ? AND wa_ok=1'
  ).bind(now - 60).first();
  if ((min1?.c || 0) >= config.max_por_minuto) {
    return { ok: false, reason: `Rate limit: ${config.max_por_minuto} msgs/min atingido` };
  }

  // Por hora
  const hr1 = await env.DB.prepare(
    'SELECT COUNT(*) as c FROM whatsapp_send_log WHERE created_at > ? AND wa_ok=1'
  ).bind(now - 3600).first();
  if ((hr1?.c || 0) >= config.max_por_hora) {
    return { ok: false, reason: `Rate limit: ${config.max_por_hora} msgs/hora atingido` };
  }

  // Por dia (desde meia-noite BRT = 04:00 UTC)
  const nowDate = new Date();
  const brtOffset = -4;
  const brtMidnight = new Date(nowDate);
  brtMidnight.setUTCHours(Math.abs(brtOffset), 0, 0, 0);
  if (brtMidnight > nowDate) brtMidnight.setUTCDate(brtMidnight.getUTCDate() - 1);
  const midnightEpoch = Math.floor(brtMidnight.getTime() / 1000);

  const day1 = await env.DB.prepare(
    'SELECT COUNT(*) as c FROM whatsapp_send_log WHERE created_at > ? AND wa_ok=1'
  ).bind(midnightEpoch).first();
  if ((day1?.c || 0) >= config.max_por_dia) {
    return { ok: false, reason: `Rate limit: ${config.max_por_dia} msgs/dia atingido` };
  }

  // Intervalo mínimo desde último envio global
  const last = await env.DB.prepare(
    'SELECT MAX(created_at) as t FROM whatsapp_send_log WHERE wa_ok=1'
  ).first();
  if (last?.t && (now - last.t) < config.intervalo_min_segundos) {
    return { ok: false, reason: `Aguarde ${config.intervalo_min_segundos}s entre envios`, retry: true };
  }

  return { ok: true };
}

// Cooldown por destinatário (para lembretes/cobranças)
async function checkRecipientCooldown(env, config, phone, category) {
  if (!category || category === 'sistema' || category === 'entrega') return { ok: true };
  const cutoff = Math.floor(Date.now() / 1000) - (config.cooldown_mesmo_numero_horas * 3600);
  const row = await env.DB.prepare(
    'SELECT MAX(created_at) as t, COUNT(*) as c FROM whatsapp_send_log WHERE phone=? AND category=? AND wa_ok=1 AND created_at > ?'
  ).bind(phone, category, cutoff).first();
  if (row?.c > 0) {
    const horasAtras = Math.round((Math.floor(Date.now() / 1000) - (row.t || 0)) / 3600);
    return { ok: false, reason: `Último ${category} para este número há ${horasAtras}h (cooldown: ${config.cooldown_mesmo_numero_horas}h)` };
  }
  return { ok: true };
}

// Verificar horário comercial BRT
function isDentroHorarioComercial(config) {
  if (!config.respeitar_horario) return true;
  const now = new Date();
  const brtHour = (now.getUTCHours() - 4 + 24) % 24;
  return brtHour >= config.horario_inicio_brt && brtHour < config.horario_fim_brt;
}

// Variação de mensagem — embaralha para não ser idêntica
const MSG_SAUDACOES = ['Olá', 'Oi', 'Bom dia', 'Boa tarde', 'Prezado(a)'];

function variarMensagem(msg) {
  // Troca saudação se começa com emoji de sino/olá padrão
  if (msg.startsWith('🔔 Olá')) {
    const saud = MSG_SAUDACOES[Math.floor(Math.random() * MSG_SAUDACOES.length)];
    msg = msg.replace('🔔 Olá', `🔔 ${saud}`);
  }
  // Adiciona espaço invisível aleatório (variação técnica anti-duplicata)
  const pos = Math.floor(Math.random() * Math.min(msg.length, 100)) + 10;
  if (pos < msg.length) {
    msg = msg.slice(0, pos) + '\u200B' + msg.slice(pos); // zero-width space
  }
  return msg;
}

/**
 * sendWhatsApp — Função CENTRAL de envio. Todas as mensagens passam por aqui.
 * @param {object} env - Cloudflare env
 * @param {string} to - Número formato 5567999999999
 * @param {string} message - Texto da mensagem
 * @param {object} opts - Opções: { category, skipSafety, variar }
 *   category: 'entrega'|'lembrete_pix'|'admin_alerta'|'contrato'|'sistema'|'teste'
 *   skipSafety: true para bypasses (teste, admin direto)
 *   variar: true para aplicar variação automática (default true para lembretes)
 */
async function sendWhatsApp(env, to, message, opts = {}) {
  const { category = 'geral', skipSafety = false, variar } = opts;

  // Formatar número automaticamente (garante 55 + DDD + número)
  to = formatPhoneWA(to);
  if (!to) return { ok: false, status: 0, data: {}, safety: 'telefone_invalido' };

  // Garantir tabelas
  await ensureWhatsAppTables(env);

  if (!skipSafety) {
    const config = await getWhatsAppSafetyConfig(env);

    if (!config.habilitado) {
      return { ok: false, status: 0, data: {}, safety: 'whatsapp_desabilitado' };
    }

    // 1. Circuit breaker
    if (await isCircuitBroken(env, config)) {
      console.error('[WA-SAFETY] Circuit breaker ABERTO — 429/bloqueio recente');
      return { ok: false, status: 0, data: {}, safety: 'circuit_breaker_aberto' };
    }

    // 2. Horário comercial
    if (!isDentroHorarioComercial(config)) {
      console.log('[WA-SAFETY] Fora do horário comercial BRT');
      return { ok: false, status: 0, data: {}, safety: 'fora_horario_comercial' };
    }

    // 3. Rate limits globais
    const rateCheck = await checkRateLimits(env, config, to);
    if (!rateCheck.ok) {
      console.warn(`[WA-SAFETY] ${rateCheck.reason}`);
      return { ok: false, status: 0, data: {}, safety: 'rate_limit', detail: rateCheck.reason };
    }

    // 4. Cooldown por destinatário (lembretes/cobranças)
    if (category === 'lembrete_pix' || category === 'cobranca') {
      const coolCheck = await checkRecipientCooldown(env, config, to, category);
      if (!coolCheck.ok) {
        console.log(`[WA-SAFETY] Cooldown: ${coolCheck.reason}`);
        return { ok: false, status: 0, data: {}, safety: 'cooldown_destinatario', detail: coolCheck.reason };
      }
    }
  }

  // 6. Variação de mensagem (anti-duplicata)
  const deveVariar = variar !== undefined ? variar : ['lembrete_pix', 'cobranca'].includes(category);
  if (deveVariar) {
    message = variarMensagem(message);
  }

  // ── ENVIO REAL ──
  const resp = await fetch('https://chatapi.izchat.com.br/api/messages/send', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${env.IZCHAT_TOKEN}`,
    },
    body: JSON.stringify({ number: to, body: message }),
  });
  const data = await resp.json().catch(() => ({}));
  const isBlocked = resp.status === 429 || data.tokenBlocked === true;

  // ── LOG ──
  try {
    await env.DB.prepare(
      'INSERT INTO whatsapp_send_log (phone, category, status_code, wa_ok, blocked) VALUES (?, ?, ?, ?, ?)'
    ).bind(to, category, resp.status, resp.ok ? 1 : 0, isBlocked ? 1 : 0).run();
  } catch (_) { }

  // ── CIRCUIT BREAKER: se 429, logar e parar ──
  if (isBlocked) {
    console.error(`[WA-SAFETY] ⚠️ 429/BLOCKED detectado! Token pode ter sido rotacionado. Circuit breaker ATIVADO.`);
    // Notificação interna (não via WhatsApp, obviamente)
    try {
      await env.DB.prepare(
        "INSERT OR REPLACE INTO app_config (key, value, updated_at) VALUES ('whatsapp_last_block', ?, datetime('now'))"
      ).bind(JSON.stringify({ at: new Date().toISOString(), phone: to, status: resp.status, data })).run();
    } catch (_) { }
  }

  return { ok: resp.ok, status: resp.status, data, blocked: isBlocked };
}

// ── Envio de imagem via IzChat (multipart) ────────────────────
async function sendWhatsAppImage(env, to, imageUrl, caption = '') {
  to = formatPhoneWA(to);
  if (!to) return { ok: false, error: 'telefone_invalido' };
  try {
    // Baixar imagem do qrserver
    const imgResp = await fetch(imageUrl);
    if (!imgResp.ok) return { ok: false, error: 'qr_download_failed' };
    const imgBlob = await imgResp.blob();

    const fd = new FormData();
    fd.append('number', to);
    if (caption) fd.append('body', caption);
    fd.append('medias', imgBlob, 'qrcode.png');

    const resp = await fetch('https://chatapi.izchat.com.br/api/messages/send', {
      method: 'POST',
      headers: { Authorization: `Bearer ${env.IZCHAT_TOKEN}` },
      body: fd,
    });
    const data = await resp.json().catch(() => ({}));
    return { ok: resp.ok, status: resp.status, data };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}

// ── Lembretes PIX ─────────────────────────────────────────────

function formatPhoneWA(phone) {
  if (!phone) return null;
  const d = phone.replace(/\D/g, '');
  if (d.length >= 12 && d.startsWith('55')) return d;
  if (d.length >= 10) return '55' + d;
  return null;
}

async function getLembreteConfig(env) {
  const defaults = {
    ativo: true,
    intervalo_horas: 24,
    max_lembretes: 3,
    cron_ativo: true,
    cron_hora_utc: 12,
    delay_segundos: 60,
    chave_pix: '',
    mensagem: 'Olá {nome}! 👋\n\nEntregamos {ontem} o seguinte pedido:\n{itens}\nValor: R$ {valor}\n\nAinda não identificamos o pagamento via PIX.\n\nSegue abaixo o código Copia e Cola para efetuar o PIX. 👇\n\nCaso já tenha sido pago, por gentileza nos envie o comprovante para darmos baixa.'
  };
  try {
    const row = await env.DB.prepare("SELECT value FROM app_config WHERE key='lembrete_pix'").first();
    if (row?.value) return { ...defaults, ...JSON.parse(row.value) };
  } catch (_) { }
  return defaults;
}

// Saudações variadas para lembretes (anti-spam WhatsApp)
const SAUDACOES_LEMBRETE = [
  'Olá {nome}. 😃 Tudo bem?',
  'Oi {nome}! 😊 Tudo certo?',
  'Olá {nome}, bom dia! 😃',
  'Oi {nome}! Esperamos que esteja tudo bem. 😊',
  'Olá {nome}! 👋',
  'Oi {nome}, tudo bem com você? 😃',
  'Olá {nome}! Como vai? 😊',
];

function buildLembreteMessage(template, order, config) {
  const items = (() => { try { return JSON.parse(order.items_json || '[]'); } catch (_) { return []; } })();
  const itensStr = items.map(i => `${i.qty}x ${i.name}`).join(', ') || 'Gás';

  // Data de entrega formatada
  const entregaTs = order.delivered_at || order.created_at;
  const dataEntrega = new Date(entregaTs * 1000).toLocaleDateString('pt-BR', { timeZone: 'America/Campo_Grande' });

  // {ontem} = data relativa ("ontem", "há 3 dias", etc.)
  const now = new Date();
  const entregaDate = new Date(entregaTs * 1000);
  const diffDias = Math.floor((now - entregaDate) / 86400000);
  let ontem = dataEntrega;
  if (diffDias === 0) ontem = 'hoje';
  else if (diffDias === 1) ontem = 'ontem';
  else ontem = `no dia ${dataEntrega}`;

  // Variação de saudação — substitui primeira linha "Olá/Oi {nome}..." por aleatória
  const primeiroNome = (order.customer_name || 'Cliente').split(' ')[0];
  let msg = template;
  const saudacao = SAUDACOES_LEMBRETE[Math.floor(Math.random() * SAUDACOES_LEMBRETE.length)]
    .replace(/\{nome\}/g, primeiroNome);
  msg = msg.replace(/^(Olá|Oi|Ola|oi|olá)\s*\{nome\}[^\n]*/i, saudacao);

  const chavePix = config?.chave_pix || '(chave PIX não configurada)';

  // {pix_copia_cola} — código PIX copia e cola (PushInPay ou legacy Cora)
  const pixCopiaCola = order.pix_qrcode || order.cora_qrcode || '';
  const pixBlock = pixCopiaCola
    ? `\n\n📋 *PIX Copia e Cola:*\n${pixCopiaCola}`
    : '';

  return msg
    .replace(/\{nome\}/g, primeiroNome)
    .replace(/\{id\}/g, order.id)
    .replace(/\{itens\}/g, itensStr)
    .replace(/\{valor\}/g, parseFloat(order.total_value || 0).toFixed(2))
    .replace(/\{data_entrega\}/g, dataEntrega)
    .replace(/\{ontem\}/g, ontem)
    .replace(/\{chave_pix\}/g, chavePix)
    .replace(/\{pix_copia_cola\}/g, pixBlock.trim()); // opcional no template
}

async function enviarLembretePix(env, order, config, user, force = false) {
  await ensureAuditTable(env);
  const phone = formatPhoneWA(order.phone_digits);
  if (!phone) return { ok: false, order_id: order.id, error: 'Sem telefone válido' };

  // Verificar limite (skip se force=true)
  const countRow = await env.DB.prepare(
    'SELECT COUNT(*) as c FROM payment_reminders WHERE order_id=?'
  ).bind(order.id).first();
  const count = countRow?.c || 0;
  if (config.max_lembretes > 0 && count >= config.max_lembretes && !force) {
    return { ok: false, order_id: order.id, error: `Limite de ${config.max_lembretes} lembretes atingido`, limite_atingido: true, count };
  }

  // Verificar intervalo (skip se force=true)
  if (config.intervalo_horas > 0 && !force) {
    const lastRow = await env.DB.prepare(
      'SELECT sent_at FROM payment_reminders WHERE order_id=? ORDER BY sent_at DESC LIMIT 1'
    ).bind(order.id).first();
    if (lastRow?.sent_at) {
      const horasDesdeUltimo = (Math.floor(Date.now() / 1000) - lastRow.sent_at) / 3600;
      if (horasDesdeUltimo < config.intervalo_horas) {
        const falta = Math.ceil(config.intervalo_horas - horasDesdeUltimo);
        return { ok: false, order_id: order.id, error: `Aguarde ${falta}h para próximo lembrete` };
      }
    }
  }

  // Auto-gerar QR Code PushInPay se não tem ainda
  const pixCode = order.pix_qrcode || order.cora_qrcode || null;
  if (!pixCode && isPixConfigured(env)) {
    try {
      await ensurePixColumns(env);
      const pixData = await pushInPayCreateCharge(env, order.id, order.total_value);
      if (pixData.tx_id && pixData.qr_code) {
        await env.DB.prepare('UPDATE orders SET pix_tx_id=?, pix_qrcode=?, pix_qrcode_base64=? WHERE id=?')
          .bind(pixData.tx_id, pixData.qr_code, pixData.qr_code_base64 || '', order.id).run();
        order.pix_qrcode = pixData.qr_code;
      }
    } catch (pe) {
      console.error(`[lembrete] Erro ao gerar QR Code pedido #${order.id}:`, pe.message);
    }
  }

  const message = buildLembreteMessage(config.mensagem, order, config);
  const skipSafety = config.intervalo_horas === 0 && config.max_lembretes === 0;
  const waResult = await sendWhatsApp(env, phone, message, { category: 'lembrete_pix', variar: true, skipSafety });

  // Segunda msg = imagem QR, terceira = código puro
  const qrCode = order.pix_qrcode || order.cora_qrcode || null;
  if (waResult.ok && qrCode) {
    await new Promise(r => setTimeout(r, 2000));
    const qrUrl = `https://api.qrserver.com/v1/create-qr-code/?size=400x400&data=${encodeURIComponent(qrCode)}`;
    await sendWhatsAppImage(env, phone, qrUrl);
    await new Promise(r => setTimeout(r, 2000));
    await sendWhatsApp(env, phone, qrCode, { category: 'lembrete_pix', skipSafety: true });
  }

  const tipo = user ? 'manual' : 'cron';
  await env.DB.prepare(
    `INSERT INTO payment_reminders (order_id, tipo, phone_sent, sent_by, sent_by_nome, whatsapp_ok, whatsapp_detail)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  ).bind(
    order.id, tipo, phone,
    user?.id || null, user?.nome || 'sistema',
    waResult.ok ? 1 : 0,
    JSON.stringify(waResult.data || {}).substring(0, 500)
  ).run();

  await logEvent(env, order.id, 'pix_reminder_sent', {
    tipo, phone, wa_ok: waResult.ok, count: count + 1
  });

  return { ok: waResult.ok, order_id: order.id, phone, envio_num: count + 1, wa_status: waResult.status, blocked: waResult.blocked, safety: waResult.safety };
}

async function processarLembretesCron(env) {
  try {
    await ensureAuditTable(env);
    await ensurePixColumns(env);
    const config = await getLembreteConfig(env);
    if (!config.ativo || !config.cron_ativo) {
      console.log('[lembrete-cron] Desativado nas configs');
      return;
    }

    // Buscar pedidos PIX pendentes entregues com telefone
    const rows = await env.DB.prepare(`
      SELECT o.id, o.customer_name, o.phone_digits, o.total_value, o.items_json,
             o.created_at, o.delivered_at, o.pix_tx_id, o.pix_qrcode, o.cora_qrcode,
             (SELECT COUNT(*) FROM payment_reminders pr WHERE pr.order_id = o.id) as reminder_count,
             (SELECT MAX(sent_at) FROM payment_reminders pr WHERE pr.order_id = o.id) as last_reminder_at
      FROM orders o
      WHERE o.tipo_pagamento = 'pix_receber' AND o.pago = 0 AND o.status = 'entregue'
        AND o.phone_digits IS NOT NULL AND o.phone_digits != ''
      ORDER BY o.created_at ASC
      LIMIT 50
    `).all().then(r => r.results || []);

    let enviados = 0, pulados = 0, erros = 0;
    const now = Math.floor(Date.now() / 1000);

    for (const row of rows) {
      // Já atingiu limite? (0 = sem limite)
      if (config.max_lembretes > 0 && row.reminder_count >= config.max_lembretes) { pulados++; continue; }

      // Intervalo respeitado?
      if (row.last_reminder_at) {
        const horasDesde = (now - row.last_reminder_at) / 3600;
        if (horasDesde < config.intervalo_horas) { pulados++; continue; }
      } else {
        // Primeiro lembrete: esperar intervalo_horas desde a entrega
        const entregaAt = row.delivered_at || row.created_at;
        const horasDesdeEntrega = (now - entregaAt) / 3600;
        if (horasDesdeEntrega < config.intervalo_horas) { pulados++; continue; }
      }

      const result = await enviarLembretePix(env, row, config, null);
      if (result.ok) enviados++;
      else {
        erros++;
        // Circuit breaker: parar tudo se bloqueado
        if (result.wa_status === 429 || result.blocked) {
          console.error('[lembrete-cron] ⚠️ BLOQUEIO detectado — parando envios!');
          break;
        }
      }

      // Pausa entre envios — delay configurável (default 60s, anti-ban WhatsApp)
      const delayMs = (config.delay_segundos || 60) * 1000;
      await new Promise(r => setTimeout(r, delayMs));
    }

    console.log(`[lembrete-cron] Total: ${rows.length} pendentes, ${enviados} enviados, ${pulados} pulados, ${erros} erros`);
  } catch (e) {
    console.error('[lembrete-cron] Erro:', e.message);
  }
}

// ── Middleware Auth ───────────────────────────────────────────

function requireApiKey(request, env) {
  const url2 = new URL(request.url);
  const key = request.headers.get('X-API-KEY') || url2.searchParams.get('api_key') || '';
  if (key === env.APP_API_KEY) return null;
  const authHeader = request.headers.get('Authorization') || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : '';
  if (token) return null;
  return err('Unauthorized', 401);
}

// ── Log de evento ─────────────────────────────────────────────

async function logEvent(env, orderId, event, payload = null) {
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS order_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id INTEGER,
    event TEXT,
    payload_json TEXT,
    created_at TEXT DEFAULT (datetime('now'))
  )`).run().catch(() => { });
  await env.DB.prepare(
    'INSERT INTO order_events (order_id, event, payload_json) VALUES (?, ?, ?)'
  ).bind(orderId, event, payload ? JSON.stringify(payload) : null).run();
}

// ── Auditoria de Integração Bling ────────────────────────────

async function ensureAuditTable(env) {
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS integration_audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id INTEGER NOT NULL,
    action TEXT NOT NULL,
    status TEXT NOT NULL,
    bling_pedido_id TEXT,
    request_payload TEXT,
    response_data TEXT,
    error_message TEXT,
    created_at TEXT DEFAULT (datetime('now'))
  )`).run().catch(() => { });
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS audit_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    snapshot_date TEXT NOT NULL,
    data_json TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now'))
  )`).run().catch(() => { });
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS order_status_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id INTEGER NOT NULL,
    status_anterior TEXT NOT NULL,
    status_novo TEXT NOT NULL,
    motivo TEXT,
    usuario_id INTEGER,
    usuario_nome TEXT,
    created_at TEXT DEFAULT (datetime('now'))
  )`).run().catch(() => { });
  // Migração: coluna cancel_motivo em orders
  await env.DB.prepare(`ALTER TABLE orders ADD COLUMN cancel_motivo TEXT`).run().catch(() => { });
  // Tabela config (key-value)
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS app_config (
    key TEXT PRIMARY KEY, value TEXT, updated_at TEXT DEFAULT (datetime('now'))
  )`).run().catch(() => { });
  // Índices para consulta de pedidos (performance)
  await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_orders_created ON orders(created_at)').run().catch(() => { });
  await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_orders_status ON orders(status)').run().catch(() => { });
  await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_orders_customer ON orders(customer_name)').run().catch(() => { });
  await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_orders_phone ON orders(phone_digits)').run().catch(() => { });
  await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_orders_driver ON orders(driver_name_cache)').run().catch(() => { });
  await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_orders_pago ON orders(pago)').run().catch(() => { });
  await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_orders_bling ON orders(bling_pedido_id)').run().catch(() => { });
  // Produtos favoritos (v2.23.0)
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS product_favorites (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    bling_id TEXT NOT NULL,
    name TEXT NOT NULL,
    code TEXT DEFAULT '',
    price REAL DEFAULT 0,
    sort_order INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now'))
  )`).run().catch(() => { });
  await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_orders_bairro ON orders(bairro)').run().catch(() => { });
  // Lembretes PIX (v2.26.0)
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS payment_reminders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id INTEGER NOT NULL,
    tipo TEXT DEFAULT 'manual',
    phone_sent TEXT,
    sent_at INTEGER DEFAULT (unixepoch()),
    sent_by INTEGER,
    sent_by_nome TEXT,
    whatsapp_ok INTEGER DEFAULT 0,
    whatsapp_detail TEXT
  )`).run().catch(() => { });
  await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_pr_order ON payment_reminders(order_id)').run().catch(() => { });
}

// ── Contratos (Comodato) — Tabelas e Helpers ─────────────────

// ── Empenhos GOV ──────────────────────────────────────────────────────────────
async function ensureEmpenhoTables(env) {
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS gov_empenhos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    numero TEXT NOT NULL UNIQUE,
    cliente_nome TEXT NOT NULL,
    cliente_phone TEXT,
    bling_contact_id TEXT NOT NULL,
    status TEXT DEFAULT 'ativo',
    data_emissao TEXT,
    data_validade TEXT,
    valor_total REAL DEFAULT 0,
    observacoes TEXT,
    created_by INTEGER,
    created_by_nome TEXT,
    created_at INTEGER DEFAULT (unixepoch()),
    updated_at INTEGER DEFAULT (unixepoch())
  )`).run().catch(() => { });

  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS gov_empenho_arquivos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    empenho_id INTEGER NOT NULL,
    nome_arquivo TEXT,
    r2_key TEXT,
    bytes INTEGER,
    created_at INTEGER DEFAULT (unixepoch()),
    FOREIGN KEY (empenho_id) REFERENCES gov_empenhos(id)
  )`).run().catch(() => { });

  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS gov_empenho_itens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    empenho_id INTEGER NOT NULL,
    produto_nome TEXT NOT NULL,
    produto_bling_id TEXT,
    quantidade_total INTEGER NOT NULL DEFAULT 0,
    quantidade_usada INTEGER NOT NULL DEFAULT 0,
    preco_unitario REAL DEFAULT 0,
    FOREIGN KEY (empenho_id) REFERENCES gov_empenhos(id)
  )`).run().catch(() => { });

  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS gov_empenho_vendas (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    empenho_id INTEGER NOT NULL,
    order_id INTEGER NOT NULL,
    quantidade_json TEXT DEFAULT '{}',
    created_at INTEGER DEFAULT (unixepoch()),
    FOREIGN KEY (empenho_id) REFERENCES gov_empenhos(id)
  )`).run().catch(() => { });
}

async function alertarSaldoBaixo(env, empenho, item) {
  const saldo = item.quantidade_total - item.quantidade_usada;
  const pct = item.quantidade_total > 0 ? Math.round(saldo / item.quantidade_total * 100) : 0;
  if (pct > 10 && saldo > 10) return;
  const msg = `⚠️ ALERTA EMPENHO GOV\nEmpenho: ${empenho.numero}\nCliente: ${empenho.cliente_nome}\nProduto: ${item.produto_nome}\nSaldo restante: ${saldo} unidades (${pct}% do total)\n\nAcesse o sistema para verificar.`;
  const admins = await env.DB.prepare(`SELECT telefone FROM app_users WHERE role='admin' AND recebe_whatsapp=1 AND ativo=1`).all().then(r => r.results || []);
  for (const adm of admins) {
    if (adm.telefone) await sendWhatsApp(env, adm.telefone, msg, { category: 'admin_alerta' }).catch(() => { });
  }
  try {
    const emailCfg = await env.DB.prepare("SELECT value FROM app_config WHERE key='relatorio_email'").first();
    if (emailCfg?.value) {
      const cfg = JSON.parse(emailCfg.value);
      const destinos = (cfg.destinos || '').split('\n').map(s => s.trim()).filter(Boolean);
      if (destinos.length > 0) {
        const resendKey = env.RESEND_API_KEY || (await env.DB.prepare("SELECT value FROM app_config WHERE key='resend_api_key'").first())?.value;
        if (resendKey) {
          await fetch('https://api.resend.com/emails', {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${resendKey}`, 'Content-Type': 'application/json' },
            body: JSON.stringify({
              from: 'MoskoGás <noreply@moskogas.com.br>',
              to: destinos,
              subject: `⚠️ Alerta Empenho ${empenho.numero} — Saldo Baixo`,
              html: `<h2>⚠️ Saldo Baixo — Empenho ${empenho.numero}</h2><p><b>Cliente:</b> ${empenho.cliente_nome}</p><p><b>Produto:</b> ${item.produto_nome}</p><p><b>Saldo:</b> ${saldo} unidades (${pct}% do total)</p>`
            })
          }).catch(() => { });
        }
      }
    }
  } catch (_) { }
}


async function ensureContractTables(env) {
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS contracts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tipo_pessoa TEXT DEFAULT 'pj',
    razao_social TEXT,
    cnpj_cpf TEXT,
    endereco TEXT,
    cidade TEXT DEFAULT 'Campo Grande',
    uf TEXT DEFAULT 'MS',
    cep TEXT,
    responsavel_nome TEXT,
    responsavel_cpf TEXT,
    responsavel_email TEXT,
    responsavel_telefone TEXT,
    itens_json TEXT DEFAULT '[]',
    comodante_snapshot TEXT,
    testemunhas_snapshot TEXT,
    template_html TEXT,
    generated_pdf_key TEXT,
    signed_pdf_key TEXT,
    assinafy_doc_id TEXT,
    assinafy_assignment_id TEXT,
    assinafy_error TEXT,
    created_by INTEGER,
    created_by_nome TEXT,
    created_at INTEGER DEFAULT (unixepoch()),
    updated_at INTEGER DEFAULT (unixepoch()),
    signed_at INTEGER,
    canceled_at INTEGER,
    cancel_motivo TEXT
  )`).run().catch(() => { });

  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS contract_signers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    contract_id INTEGER NOT NULL,
    role TEXT NOT NULL,
    nome TEXT NOT NULL,
    cpf TEXT,
    telefone TEXT,
    email TEXT,
    assinafy_signer_id TEXT,
    signing_url TEXT,
    signed_at INTEGER,
    status TEXT DEFAULT 'pending',
    whatsapp_sent_at INTEGER,
    reject_reason TEXT,
    FOREIGN KEY (contract_id) REFERENCES contracts(id)
  )`).run().catch(() => { });

  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS contract_attachments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    contract_id INTEGER NOT NULL,
    tipo TEXT NOT NULL,
    nome_arquivo TEXT,
    r2_key TEXT NOT NULL,
    mime TEXT,
    bytes INTEGER,
    created_at INTEGER DEFAULT (unixepoch()),
    FOREIGN KEY (contract_id) REFERENCES contracts(id)
  )`).run().catch(() => { });

  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS contract_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    contract_id INTEGER NOT NULL,
    evento TEXT NOT NULL,
    detalhes TEXT,
    usuario_id INTEGER,
    usuario_nome TEXT,
    created_at INTEGER DEFAULT (unixepoch())
  )`).run().catch(() => { });

  await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_contracts_status ON contracts(status)').run().catch(() => { });
  await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_contracts_numero ON contracts(numero)').run().catch(() => { });
  await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_csigners_contract ON contract_signers(contract_id)').run().catch(() => { });
  await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_cattach_contract ON contract_attachments(contract_id)').run().catch(() => { });
  await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_cevents_contract ON contract_events(contract_id)').run().catch(() => { });
  // v2.32.0: índices para busca de clientes (performance com 10k+ registros)
  await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_customers_name ON customers_cache(name)').run().catch(() => { });
  await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_customers_phone ON customers_cache(phone_digits)').run().catch(() => { });
}

// ─── ESTOQUE: Schema (v2.42.0) ─────────────────────────────
async function ensureStockTables(env) {
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS stock_daily (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    data TEXT NOT NULL, tipo TEXT NOT NULL,
    cheios_manha INTEGER, vazios_manha INTEGER,
    compras INTEGER DEFAULT 0, vendas_auto INTEGER DEFAULT 0,
    cheios_tarde INTEGER, vazios_tarde INTEGER,
    cascos_devolucao INTEGER DEFAULT 0, cascos_emprestimo INTEGER DEFAULT 0,
    cascos_venda INTEGER DEFAULT 0, cascos_aquisicao INTEGER DEFAULT 0,
    observacao TEXT, contagem_manha_por TEXT, contagem_manha_at TEXT,
    contagem_tarde_por TEXT, contagem_tarde_at TEXT,
    divergencia_notificada INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now')), updated_at TEXT DEFAULT (datetime('now')),
    UNIQUE(data, tipo)
  )`).run().catch(() => { });
  await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_stock_data ON stock_daily(data)').run().catch(() => { });
  for (const sql of [
    "ALTER TABLE stock_daily ADD COLUMN cascos_devolucao INTEGER DEFAULT 0",
    "ALTER TABLE stock_daily ADD COLUMN cascos_emprestimo INTEGER DEFAULT 0",
    "ALTER TABLE stock_daily ADD COLUMN cascos_venda INTEGER DEFAULT 0",
    "ALTER TABLE stock_daily ADD COLUMN cascos_aquisicao INTEGER DEFAULT 0",
    "ALTER TABLE stock_daily ADD COLUMN observacao TEXT",
  ]) await env.DB.prepare(sql).run().catch(() => { });
}

// ─── ESTOQUE: Vendas automáticas dos pedidos entregues ─────
async function calcVendasAuto(env, data) {
  const startEpoch = Math.floor(new Date(data + 'T00:00:00-04:00').getTime() / 1000);
  const endEpoch = Math.floor(new Date(data + 'T23:59:59-04:00').getTime() / 1000);
  const orders = await env.DB.prepare(
    "SELECT items_json FROM orders WHERE status='entregue' AND delivered_at >= ? AND delivered_at <= ?"
  ).bind(startEpoch, endEpoch).all().then(r => r.results || []);
  const mapRow = await env.DB.prepare("SELECT value FROM app_config WHERE key='estoque_mapeamento'").first().catch(() => null);
  let mapeamento = {}; try { mapeamento = JSON.parse(mapRow?.value || '{}'); } catch { }
  const vendas = { P13: 0, P20: 0, P45: 0, P05: 0 };
  for (const order of orders) {
    let items = []; try { items = JSON.parse(order.items_json || '[]'); } catch { }
    for (const item of items) {
      const blingId = String(item.bling_id || item.id || '');
      const nome = (item.name || item.nome || '').toUpperCase();
      const code = (item.code || item.codigo || '').toUpperCase();
      const qty = parseFloat(item.qty || item.quantidade || 0);
      let tipo = mapeamento[blingId] || null;
      if (!tipo) {
        if (nome.includes('P13') || code.includes('P13')) tipo = 'P13';
        else if (nome.includes('P20') || code.includes('P20')) tipo = 'P20';
        else if (nome.includes('P45') || code.includes('P45')) tipo = 'P45';
        else if (nome.includes('P05') || nome.includes('P5') || code.includes('P05') || code.includes('P5')) tipo = 'P05';
      }
      if (tipo && vendas[tipo] !== undefined) vendas[tipo] += qty;
    }
  }
  return vendas;
}

async function logContractEvent(env, contractId, evento, detalhes, user) {
  try {
    await ensureContractTables(env);
    await env.DB.prepare(
      'INSERT INTO contract_events (contract_id, evento, detalhes, usuario_id, usuario_nome) VALUES (?, ?, ?, ?, ?)'
    ).bind(contractId, evento, detalhes || null, user?.id || null, user?.nome || 'sistema').run();
  } catch (e) { console.error('[logContractEvent]', e.message); }
}

async function generateContractNumber(env) {
  const year = new Date().getFullYear();
  const prefix = `COMOD-${year}-`;
  const last = await env.DB.prepare(
    "SELECT numero FROM contracts WHERE numero LIKE ? ORDER BY id DESC LIMIT 1"
  ).bind(`${prefix}%`).first();
  let seq = 1;
  if (last && last.numero) {
    const parts = last.numero.split('-');
    seq = parseInt(parts[2] || '0') + 1;
  }
  return `${prefix}${String(seq).padStart(3, '0')}`;
}

// ── Assinafy API Helpers ──────────────────────────────────────

async function assinaryFetch(path, options, env) {
  const baseUrl = 'https://api.assinafy.com.br/v1';
  const url = `${baseUrl}${path}`;
  const headers = {
    'X-Api-Key': env.ASSINAFY_API_KEY || '',
    ...options.headers,
  };
  const resp = await fetch(url, { ...options, headers });
  return resp;
}

async function assinaryUploadDocument(env, pdfBytes, filename) {
  const formData = new FormData();
  formData.append('file', new Blob([pdfBytes], { type: 'application/pdf' }), filename);
  const accountId = env.ASSINAFY_ACCOUNT_ID || '';
  const resp = await fetch(`https://api.assinafy.com.br/v1/accounts/${accountId}/documents`, {
    method: 'POST',
    headers: { 'X-Api-Key': env.ASSINAFY_API_KEY || '' },
    body: formData,
  });
  if (!resp.ok) {
    const errBody = await resp.text().catch(() => '');
    throw new Error(`Assinafy upload failed (${resp.status}): ${errBody}`);
  }
  return resp.json();
}

async function assinaryCreateSigner(env, signerData) {
  const accountId = env.ASSINAFY_ACCOUNT_ID || '';
  const resp = await assinaryFetch(`/accounts/${accountId}/signers`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      full_name: signerData.nome,
      email: signerData.email || undefined,
      whatsapp_phone_number: signerData.telefone ? `+55${signerData.telefone.replace(/\D/g, '')}` : undefined,
    }),
  }, env);

  if (resp.ok) {
    const result = await resp.json();
    return result.data || result;
  }

  // Se 400 "já existe", busca o signer existente pelo email
  const errBody = await resp.text().catch(() => '');
  if (resp.status === 400 && signerData.email) {
    console.log(`[assinafy] Signer already exists (${signerData.email}), searching...`);
    const searchResp = await assinaryFetch(
      `/accounts/${accountId}/signers?search=${encodeURIComponent(signerData.email)}`,
      { method: 'GET' }, env
    );
    if (searchResp.ok) {
      const searchResult = await searchResp.json();
      const signers = searchResult.data || searchResult || [];
      const found = signers.find(s => s.email === signerData.email);
      if (found) {
        console.log(`[assinafy] Found existing signer: ${found.id} (${found.full_name})`);
        return found;
      }
    }
  }

  throw new Error(`Assinafy create signer failed (${resp.status}): ${errBody}`);
}

async function assinaryCreateAssignment(env, documentId, signerIds) {
  const signers = signerIds.map(id => ({ id }));
  const resp = await assinaryFetch(`/documents/${documentId}/assignments`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      method: 'virtual',
      signers,
    }),
  }, env);
  if (!resp.ok) {
    const errBody = await resp.text().catch(() => '');
    throw new Error(`Assinafy assignment failed (${resp.status}): ${errBody}`);
  }
  const result = await resp.json();
  return result.data || result;
}

async function assinaryGetDocument(env, documentId) {
  const accountId = env.ASSINAFY_ACCOUNT_ID || '';
  const resp = await assinaryFetch(`/accounts/${accountId}/documents`, {
    method: 'GET',
  }, env);
  // Individual doc get
  const resp2 = await fetch(`https://api.assinafy.com.br/v1/accounts/${accountId}/documents?search=${documentId}`, {
    headers: { 'X-Api-Key': env.ASSINAFY_API_KEY || '' },
  });
  if (!resp2.ok) return null;
  const data = await resp2.json();
  const docs = data.data || [];
  return docs.find(d => d.id === documentId) || null;
}

async function assinaryDownloadSigned(env, documentId) {
  const resp = await fetch(`https://api.assinafy.com.br/v1/documents/${documentId}/download/certificated`, {
    headers: { 'X-Api-Key': env.ASSINAFY_API_KEY || '' },
  });
  if (!resp.ok) throw new Error(`Download signed PDF failed: ${resp.status}`);
  return resp.arrayBuffer();
}

async function assinaryResendToSigner(env, documentId, assignmentId, signerId) {
  const resp = await assinaryFetch(
    `/documents/${documentId}/assignments/${assignmentId}/signers/${signerId}/resend`,
    { method: 'PUT', headers: { 'Content-Type': 'application/json' } },
    env
  );
  return resp.ok;
}

async function logStatusChange(env, orderId, statusAnterior, statusNovo, motivo, user) {
  try {
    await ensureAuditTable(env);
    await env.DB.prepare(
      'INSERT INTO order_status_log (order_id, status_anterior, status_novo, motivo, usuario_id, usuario_nome) VALUES (?, ?, ?, ?, ?, ?)'
    ).bind(orderId, statusAnterior, statusNovo, motivo || null, user?.id || null, user?.nome || 'sistema').run();
  } catch (e) { console.error('[logStatusChange]', e.message); }
}

async function logBlingAudit(env, orderId, action, status, opts = {}) {
  await ensureAuditTable(env);
  await env.DB.prepare(
    'INSERT INTO integration_audit (order_id, action, status, bling_pedido_id, request_payload, response_data, error_message) VALUES (?, ?, ?, ?, ?, ?, ?)'
  ).bind(
    orderId, action, status,
    opts.bling_pedido_id || null,
    opts.request_payload ? JSON.stringify(opts.request_payload).substring(0, 4000) : null,
    opts.response_data ? JSON.stringify(opts.response_data).substring(0, 4000) : null,
    opts.error_message || null
  ).run().catch(e => console.error('[audit] log error:', e.message));
}

// ── Formatação mensagem entregador ────────────────────────────

function buildDeliveryMessage(order, observation) {
  const items = JSON.parse(order.items_json || '[]');
  const itemsList = items.map(i => `  • ${i.name} x${i.qty}`).join('\n') || '  (sem itens)';
  const addr = `${order.address_line}${order.bairro ? ', ' + order.bairro : ''}, Campo Grande/MS`;
  const mapsLink = `https://www.google.com/maps/search/?api=1&query=${encodeURIComponent(addr)}`;

  return `🚚 *NOVA ENTREGA* — Pedido #${order.id}

👤 Cliente: ${order.customer_name}
📞 Telefone: ${order.phone_digits || 'não informado'}

📍 Endereço:
${order.address_line}${order.bairro ? ' — ' + order.bairro : ''} — Campo Grande/MS${order.referencia ? '\nRef: ' + order.referencia : ''}

📦 Itens:
${itemsList}

📝 Obs do atendente:
${observation || '—'}

🗺️ Abrir no mapa:
${mapsLink}

📲 Painel do Entregador:
https://moskogas-app.pages.dev/entregador.html`;
}

// ── Import ruas ───────────────────────────────────────────────
async function importStreetsByLetter(env, letter) {
  const regex = `^[${letter.toUpperCase()}${letter.toLowerCase()}]`;
  const query = `[out:json][timeout:25];way["highway"]["name"~"${regex}"](-20.62,-54.91,-20.28,-54.44);out tags;`;

  const servers = [
    'https://overpass-api.de/api/interpreter',
    'https://overpass.kumi.systems/api/interpreter',
    'https://maps.mail.ru/osm/tools/overpass/api/interpreter',
  ];

  let elements = null;
  let lastError = '';
  for (const srv of servers) {
    try {
      const resp = await fetch(srv, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'data=' + encodeURIComponent(query),
        signal: AbortSignal.timeout(28000),
      });
      if (!resp.ok) { lastError = 'HTTP ' + resp.status; continue; }
      const data = await resp.json();
      elements = data?.elements || [];
      break;
    } catch (e) { lastError = e.message; }
  }

  if (elements === null) throw new Error(lastError || 'Todos os servidores falharam');

  const seen = new Set();
  const streets = [];
  for (const el of elements) {
    const name = (el.tags?.name || '').trim();
    if (!name || seen.has(name)) continue;
    seen.add(name);
    const norm = name.toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '');
    streets.push({ name, norm });
  }

  for (let i = 0; i < streets.length; i += 30) {
    const batch = streets.slice(i, i + 30);
    const ph = batch.map(() => '(?,?,?)').join(',');
    const vals = batch.flatMap(s => [s.name, s.norm, '']);
    await env.DB.prepare(`INSERT OR IGNORE INTO streets_cg (name, name_norm, bairro) VALUES ${ph}`).bind(...vals).run();
  }

  return streets.length;
}

// =============================================================
// ROTEADOR PRINCIPAL
// =============================================================

function mapContatos(lista) {
  return lista.map(c => {
    const end = (c.endereco && c.endereco.geral) ? c.endereco.geral : (c.endereco || {});
    const rua = (end.endereco || end.logradouro || '').trim();
    const num = (end.numero || '').trim();
    const address_line = num ? `${rua}, ${num}` : rua;
    const phone = (c.celular || c.telefone || c.fone || '').replace(/\D/g, '');
    return {
      name: c.nome,
      phone_digits: phone,
      address_line,
      bairro: end.bairro || '',
      complemento: end.complemento || '',
      referencia: '',
      bling_contact_id: c.id,
      cpf_cnpj: c.numeroDocumento || '',
      tipo_pessoa: c.tipo || '',
      email: c.email || '',
    };
  });
}

async function saveContactsCache(result, env) {
  // Ensure columns exist
  for (const col of ['cpf_cnpj TEXT', 'email TEXT', 'email_nfe TEXT', 'tipo_pessoa TEXT', 'ultima_compra_glp TEXT DEFAULT \'\'', 'origem TEXT DEFAULT \'manual\'']) {
    await env.DB.prepare(`ALTER TABLE customers_cache ADD COLUMN ${col}`).run().catch(() => { });
  }
  for (const r of result) {
    if (r.phone_digits || r.bling_contact_id) {
      try {
        await env.DB.prepare(`
          INSERT OR REPLACE INTO customers_cache (phone_digits, name, address_line, bairro, complemento, bling_contact_id, cpf_cnpj, tipo_pessoa, email, updated_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, unixepoch())
        `).bind(r.phone_digits || null, r.name, r.address_line, r.bairro, r.complemento, r.bling_contact_id || null, r.cpf_cnpj || null, r.tipo_pessoa || null, r.email || null).run();
      } catch (_) { }
    }
  }
}

async function ensureValesTables(env) {
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS notas_vales (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cliente_nome TEXT NOT NULL,
    cliente_doc TEXT,
    quantidade INTEGER NOT NULL,
    valor_unit REAL NOT NULL DEFAULT 0,
    total REAL NOT NULL DEFAULT 0,
    forma_pagamento TEXT,
    nota_fiscal TEXT,
    empenho TEXT,
    itens_json TEXT DEFAULT '[]',
    bling_pedido_id TEXT,
    bling_pedido_num TEXT,
    created_by INTEGER,
    created_by_nome TEXT,
    created_at INTEGER DEFAULT (unixepoch())
  )`).run().catch(() => { });

  try { await env.DB.prepare("ALTER TABLE notas_vales ADD COLUMN nota_fiscal TEXT;").run(); } catch (e) { }
  try { await env.DB.prepare("ALTER TABLE notas_vales ADD COLUMN empenho TEXT;").run(); } catch (e) { }
  try { await env.DB.prepare("ALTER TABLE notas_vales ADD COLUMN itens_json TEXT DEFAULT '[]';").run(); } catch (e) { }
  try { await env.DB.prepare("ALTER TABLE notas_vales ADD COLUMN validade TEXT DEFAULT '';").run(); } catch (e) { }

  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS vales (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nota_id INTEGER NOT NULL,
    numero TEXT NOT NULL,
    produto TEXT DEFAULT 'P13',
    status TEXT DEFAULT 'pendente',
    resgatado_em INTEGER,
    resgatado_por TEXT,
    FOREIGN KEY(nota_id) REFERENCES notas_vales(id)
  )`).run().catch(() => { });

  try { await env.DB.prepare("ALTER TABLE vales ADD COLUMN produto TEXT DEFAULT 'P13';").run(); } catch (e) { }
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    if (path.startsWith('/api/address') || path.startsWith('/api/streets')) {
      try {
        await env.DB.prepare(`
          CREATE TABLE IF NOT EXISTS customer_addresses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            phone_digits TEXT NOT NULL,
            obs TEXT NOT NULL,
            address_line TEXT NOT NULL,
            bairro TEXT DEFAULT '',
            complemento TEXT DEFAULT '',
            referencia TEXT DEFAULT '',
            created_at INTEGER DEFAULT (unixepoch())
          )
        `).run();
        await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_ca_phone ON customer_addresses(phone_digits)').run();
        await env.DB.prepare(`
          CREATE TABLE IF NOT EXISTS streets_cg (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            name_norm TEXT NOT NULL,
            bairro TEXT DEFAULT ''
          )
        `).run();
        await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_st_norm ON streets_cg(name_norm)').run();
      } catch (_) { }
    }

    if (method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }

    // ── Rotas públicas ──────────────────────────────────────

    if (method === 'GET' && path === '/health') {
      const db = await env.DB.prepare('SELECT 1').first().then(() => true).catch(() => false);
      return json({ ok: true, hasDB: db, hasBucket: !!env.BUCKET });
    }

    if (method === 'GET' && path === '/api/bling/status') {
      try {
        const row = await getTokenRow(env);
        if (!row || !row.access_token) return json({ ok: false, connected: false, error: 'no_token' });
        const now = Math.floor(Date.now() / 1000);
        const expiresAt = (row.obtained_at || 0) + (row.expires_in || 3600);
        const minutesLeft = Math.floor((expiresAt - now) / 60);
        const connected = minutesLeft > 0;
        return json({ ok: true, connected, minutesLeft, message: connected ? `Token válido (${minutesLeft}min)` : 'Token expirado' });
      } catch (e) {
        return json({ ok: false, connected: false, error: e.message });
      }
    }

    if (method === 'GET' && path === '/api/bling/keep-alive') {
      try {
        const row = await getTokenRow(env);
        if (!row || !row.access_token) return json({ ok: false, connected: false, error: 'no_token' });

        const testResp = await fetch('https://www.bling.com.br/Api/v3/contatos?pagina=1&limite=1', {
          headers: { Authorization: `Bearer ${row.access_token}`, 'Content-Type': 'application/json', 'enable-jwt': '1' },
        });

        if (testResp.ok) {
          const now = Math.floor(Date.now() / 1000);
          const minutesLeft = Math.floor(((row.obtained_at || 0) + (row.expires_in || 3600) - now) / 60);
          return json({ ok: true, connected: true, minutesLeft, message: `Token válido e testado (${minutesLeft}min)` });
        }

        console.log('[keep-alive] Token rejeitado pelo Bling (status ' + testResp.status + '), tentando refresh...');
        try {
          const newToken = await refreshBlingToken(env, row.refresh_token);
          console.log('[keep-alive] Token renovado com sucesso!');
          const newRow = await getTokenRow(env);
          const now2 = Math.floor(Date.now() / 1000);
          const ml2 = Math.floor(((newRow.obtained_at || 0) + (newRow.expires_in || 3600) - now2) / 60);
          return json({ ok: true, connected: true, minutesLeft: ml2, refreshed: true, message: `Token renovado! (${ml2}min)` });
        } catch (refreshErr) {
          console.error('[keep-alive] Refresh falhou:', refreshErr.message);
          return json({ ok: false, connected: false, error: 'refresh_failed: ' + refreshErr.message, message: 'Token expirado e refresh falhou. Reautorize em Config.' });
        }
      } catch (e) {
        return json({ ok: false, connected: false, error: e.message });
      }
    }

    if (method === 'GET' && path === '/api/bling/diagnostico') {
      try {
        const [depResp, fpResp] = await Promise.all([
          blingFetch('/depositos?pagina=1&limite=50', {}, env),
          blingFetch('/formas-pagamentos?pagina=1&limite=50', {}, env),
        ]);
        const depositos = depResp.ok ? (await depResp.json()).data : { error: depResp.status };
        const formasPgto = fpResp.ok ? (await fpResp.json()).data : { error: fpResp.status };
        return json({ depositos, formasPgto });
      } catch (e) {
        return json({ error: e.message });
      }
    }

    // ── STREETS ──────────────────────────────────────────────

    if (method === 'GET' && path === '/api/streets/search') {
      const q = (url.searchParams.get('q') || '').trim();
      if (q.length < 2) return json([]);
      const qNorm = q.toLowerCase().normalize('NFD').replace(/[\u0300-\u036f]/g, '');
      const rows = await env.DB.prepare(
        "SELECT name, bairro FROM streets_cg WHERE name_norm LIKE ? ORDER BY name ASC LIMIT 20"
      ).bind(`%${qNorm}%`).all().then(r => r.results || []);
      if (rows.length > 0) return json(rows);
      try {
        const nominatimUrl = `https://nominatim.openstreetmap.org/search?q=${encodeURIComponent(q)}+Campo+Grande+MS&format=json&addressdetails=1&limit=15&countrycodes=br&featuretype=street`;
        const nmResp = await fetch(nominatimUrl, { headers: { 'User-Agent': 'MoskoGas/2.0 (moskogas.com.br)' }, signal: AbortSignal.timeout(5000) });
        if (!nmResp.ok) return json([]);
        const nmData = await nmResp.json();
        const streets = []; const seen = new Set();
        for (const item of nmData) {
          const addr = item.address || {};
          const road = addr.road || addr.pedestrian || addr.path || item.display_name?.split(',')[0] || '';
          if (!road || seen.has(road)) continue; seen.add(road);
          streets.push({ name: road, bairro: addr.suburb || addr.neighbourhood || addr.quarter || '' });
        }
        return json(streets);
      } catch (_) { return json([]); }
    }

    if (method === 'POST' && path === '/api/streets/import-letter') {
      const body = await request.json().catch(() => ({}));
      const letter = (body.letter || '').toUpperCase();
      const isFirst = body.first === true;
      if (!letter) return json({ error: 'Parâmetro "letter" obrigatório' }, 400);
      if (isFirst) await env.DB.prepare('DELETE FROM streets_cg').run();
      try {
        const count = await importStreetsByLetter(env, letter);
        const total = await env.DB.prepare('SELECT COUNT(*) AS c FROM streets_cg').first().then(r => r?.c || 0);
        return json({ ok: true, letter, added: count, total });
      } catch (e) { return json({ ok: false, letter, error: e.message }, 500); }
    }

    if (method === 'POST' && path === '/api/streets/import') {
      return json({ ok: false, error: 'Use /api/streets/import-letter agora. Veja config.html.' }, 410);
    }

    if (method === 'GET' && path === '/api/streets/count') {
      const row = await env.DB.prepare('SELECT COUNT(*) AS c FROM streets_cg').first();
      return json({ count: row?.c || 0 });
    }

    if (method === 'GET' && path === '/api/streets/bairros') {
      const name = (url.searchParams.get('name') || '').trim();
      if (!name) return json({ bairros: [] });
      try {
        const nmUrl = `https://nominatim.openstreetmap.org/search?street=${encodeURIComponent(name)}&city=Campo+Grande&state=Mato+Grosso+do+Sul&country=Brazil&format=json&addressdetails=1&limit=15`;
        const nmResp = await fetch(nmUrl, { headers: { 'User-Agent': 'MoskoGas/2.0 (moskogas.com.br)' }, signal: AbortSignal.timeout(6000) });
        if (!nmResp.ok) return json({ bairros: [] });
        const nmData = await nmResp.json();
        const seen = new Set(); const bairros = [];
        for (const item of nmData) {
          const addr = item.address || {};
          const b = addr.suburb || addr.neighbourhood || addr.quarter || addr.city_district || '';
          if (b && !seen.has(b)) { seen.add(b); bairros.push(b); }
        }
        return json({ bairros });
      } catch (_) { return json({ bairros: [] }); }
    }

    // ── ENDEREÇOS MÚLTIPLOS ─────────────────────────────────

    if (method === 'GET' && path === '/api/address/list') {
      const phone = (url.searchParams.get('phone') || '').replace(/\D/g, '');
      if (!phone) return json([]);
      const rows = await env.DB.prepare('SELECT * FROM customer_addresses WHERE phone_digits=? ORDER BY obs ASC').bind(phone).all().then(r => r.results);
      return json(rows);
    }

    if (method === 'POST' && path === '/api/address/save') {
      const b = await request.json();
      const phone = (b.phone_digits || '').replace(/\D/g, '');
      if (!phone || !b.address_line) return json({ error: 'phone e address obrigatórios' }, 400);
      await env.DB.prepare(`INSERT INTO customer_addresses (phone_digits, obs, address_line, bairro, complemento, referencia) VALUES (?, ?, ?, ?, ?, ?)`).bind(phone, b.obs || '', b.address_line, b.bairro || '', b.complemento || '', b.referencia || '').run();
      return json({ ok: true });
    }

    if (method === 'DELETE' && path.startsWith('/api/address/')) {
      const addrId = path.split('/').pop();
      await env.DB.prepare('DELETE FROM customer_addresses WHERE id=?').bind(addrId).run();
      return json({ ok: true });
    }

    if (method === 'GET' && path === '/api/address/search') {
      const q = (url.searchParams.get('q') || '').trim();
      if (q.length < 2) return json([]);
      const rows = await env.DB.prepare(`
        SELECT ca.*, cc.name AS customer_name FROM customer_addresses ca
        LEFT JOIN customers_cache cc ON cc.phone_digits = ca.phone_digits
        WHERE ca.obs LIKE ? OR ca.address_line LIKE ? OR ca.bairro LIKE ?
        ORDER BY ca.obs ASC LIMIT 12
      `).bind(`%${q}%`, `%${q}%`, `%${q}%`).all().then(r => r.results);
      return json(rows);
    }

    // ── SYNC BLING ──────────────────────────────────────────

    if (method === 'POST' && path === '/api/customer/sync-bling') {
      let page = 1, total = 0, hasMore = true;
      while (hasMore && page <= 50) {
        const resp = await blingFetch(`/contatos?pagina=${page}&limite=100&situacao=A`, {}, env);
        if (!resp.ok) break;
        const data = await resp.json();
        const lista = data.data || [];
        if (lista.length === 0) { hasMore = false; break; }
        const mapped = mapContatos(lista);
        await saveContactsCache(mapped, env);
        total += mapped.length;
        page++;
        if (lista.length < 100) hasMore = false;
      }
      return json({ ok: true, synced: total, pages: page - 1 });
    }

    if (method === 'GET' && path.startsWith('/api/customer/bling-detail/')) {
      const blingId = path.split('/').pop();
      try {
        const resp = await blingFetch(`/contatos/${blingId}`, {}, env);
        if (!resp.ok) {
          const errText = await resp.text().catch(() => '');
          // Tenta buscar por pesquisa se ID não funcionar (ID pode ser de outro sistema)
          return json({ error: 'bling_id_invalido', status: resp.status, detail: errText.substring(0, 200) }, 404);
        }
        const data = await resp.json();
        const c = data.data || data;
        const end = (c.endereco && c.endereco.geral) ? c.endereco.geral : (c.endereco || {});
        const rua = (end.endereco || end.logradouro || '').trim();
        const num = (end.numero || '').trim();
        const address_line = num ? `${rua}, ${num}` : rua;
        const phone = (c.celular || c.telefone || c.fone || '').replace(/\D/g, '');
        const result = {
          name: c.nome, fantasia: c.fantasia || '', phone_digits: phone,
          address_line, bairro: end.bairro || '', complemento: end.complemento || '',
          cep: end.cep || '', cidade: end.municipio || '', uf: end.uf || '',
          bling_contact_id: c.id, tipo: c.tipo || '',
          numeroDocumento: c.numeroDocumento || c.cpfCnpj || '',
          rg_ie: c.ie || c.rg || '',
          email: c.email || '', emailNfe: c.emailNfe || '',
          telefone: c.telefone || c.fone || '', celular: c.celular || '',
          situacao: c.situacao || '', obs: c.obs || c.observacoes || '',
          bling_url: `https://www.bling.com.br/contatos.php#edit/${c.id}`,
        };
        if (phone || address_line) {
          await env.DB.prepare(`INSERT OR REPLACE INTO customers_cache (phone_digits, name, address_line, bairro, complemento, bling_contact_id, updated_at) VALUES (?, ?, ?, ?, ?, ?, unixepoch())`).bind(phone || null, result.name, address_line, result.bairro, result.complemento, c.id).run();
        }
        return json(result);
      } catch (e) { return json({ error: e.message }, 500); }
    }

    if (method === 'GET' && path.startsWith('/bling/debug-contato-id/')) {
      const id = path.split('/').pop();
      const resp = await blingFetch(`/contatos/${id}`, {}, env);
      const data = await resp.json();
      return json(data);
    }

    if (method === 'GET' && path === '/bling/debug-contato') {
      const q = url.searchParams.get('q') || 'solar';
      const resp = await blingFetch(`/contatos?pagina=1&limite=3&pesquisa=${encodeURIComponent(q)}`, {}, env);
      const data = await resp.json();
      return json(data);
    }

    if (method === 'GET' && path === '/bling/ping') {
      try {
        const resp = await blingFetch('/contatos?limite=1', {}, env);
        return json({ ok: resp.ok, status: resp.status });
      } catch (e) { return json({ ok: false, error: e.message }, 500); }
    }

    if (method === 'GET' && path === '/bling/oauth/start') {
      const redirect = `https://www.bling.com.br/Api/v3/oauth/authorize?response_type=code&client_id=${env.BLING_CLIENT_ID}&state=moskogas`;
      return Response.redirect(redirect, 302);
    }

    if (method === 'GET' && path === '/bling/oauth/callback') {
      const code = url.searchParams.get('code');
      if (!code) return err('missing code');
      const body = new URLSearchParams({ grant_type: 'authorization_code', code });
      const resp = await fetch('https://www.bling.com.br/Api/v3/oauth/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json', 'enable-jwt': '1', Authorization: 'Basic ' + btoa(`${env.BLING_CLIENT_ID}:${env.BLING_CLIENT_SECRET}`) },
        body,
      });
      if (!resp.ok) {
        const errHtml = `<!DOCTYPE html><html><body style="font-family:system-ui;display:flex;align-items:center;justify-content:center;min-height:100vh;background:#fee2e2"><div style="text-align:center"><h2>❌ Falha na autenticação Bling</h2><p>Status: ${resp.status}</p><button onclick="window.close()" style="margin-top:16px;padding:12px 24px;background:#dc2626;color:#fff;border:none;border-radius:8px;font-size:16px;cursor:pointer">Fechar</button></div></body></html>`;
        return new Response(errHtml, { status: 400, headers: { 'Content-Type': 'text/html; charset=utf-8' } });
      }
      const data = await resp.json();
      await saveToken(env, data);
      // Retorna HTML que notifica o opener (login/pedido) e fecha o popup
      const successHtml = `<!DOCTYPE html><html><body style="font-family:system-ui;display:flex;align-items:center;justify-content:center;min-height:100vh;background:#dcfce7"><div style="text-align:center"><h2>✅ Bling conectado!</h2><p>Token salvo com sucesso. Esta janela vai fechar automaticamente.</p></div><script>if(window.opener){window.opener.postMessage({type:'bling_connected'},'*')}setTimeout(()=>window.close(),2000)</script></body></html>`;
      return new Response(successHtml, { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
    }

    if (method === 'POST' && path === '/izchat/notificar-entrega') {
      const auth = requireApiKey(request, env);
      if (auth) return auth;
      const body = await request.json();
      const result = await sendWhatsApp(env, body.to, body.message, { category: 'entrega' });
      return json(result);
    }

    if (method === 'GET' && path === '/izchat/teste') {
      const to = url.searchParams.get('to');
      if (!to) return err('missing to');
      const result = await sendWhatsApp(env, to, '✅ Teste MoskoGás — Sistema funcionando!', { category: 'teste', skipSafety: true });
      return json(result);
    }

    // ── Rotas internas (requerem X-API-KEY) ─────────────────

    if (!path.startsWith('/api/')) return err('Not found', 404);

    if (method === 'GET' && path === '/api/pub/bling-status') {
      try {
        const row = await env.DB.prepare('SELECT id, obtained_at, expires_in FROM bling_tokens WHERE id=1').first();
        if (!row) return json({ ok: false, error: 'Sem token salvo no D1' });
        const now = Math.floor(Date.now() / 1000);
        const minutesLeft = Math.round(((row.obtained_at + row.expires_in) - now) / 60);
        const pingResp = await blingFetch('/situacoes/modulos', {}, env);
        const pingOk = pingResp.status < 400;
        return json({ ok: pingOk, bling_status: pingResp.status, token_minutes_left: minutesLeft });
      } catch (e) { return json({ ok: false, error: e.message }); }
    }

    if (method === 'GET' && path === '/api/pub/debug-items') {
      const orderId = parseInt(url.searchParams.get('order_id') || '0');
      if (!orderId) return err('order_id obrigatório', 400);
      const order = await env.DB.prepare('SELECT * FROM orders WHERE id=?').bind(orderId).first();
      if (!order) return err('Pedido não encontrado', 404);
      const items = JSON.parse(order.items_json || '[]');
      const itensBling = items.map(it => buildItemBling(it));
      const logs = await env.DB.prepare('SELECT * FROM order_events WHERE order_id=? ORDER BY id DESC LIMIT 10').bind(orderId).all().catch(() => ({ results: [] }));
      return json({
        order_id: orderId, raw_items_json: order.items_json, parsed_items: items, bling_payload_itens: itensBling,
        tipo_pagamento: order.tipo_pagamento, bling_pedido_id: order.bling_pedido_id, bling_pedido_num: order.bling_pedido_num,
        sync_status: order.sync_status,
        recent_logs: (logs.results || []).map(l => ({ event: l.event, data: l.payload_json, at: l.created_at })),
      });
    }

    if (method === 'GET' && path === '/api/pub/test-criar-pedido') {
      try {
        await ensureAuditTable(env);
        const orderId = parseInt(url.searchParams.get('order_id') || '0');
        if (!orderId) return json({ error: 'Informe ?order_id=X' });
        const order = await env.DB.prepare('SELECT * FROM orders WHERE id=?').bind(orderId).first();
        if (!order) return json({ error: 'Pedido não encontrado' });
        const items = JSON.parse(order.items_json || '[]');
        const today = new Date().toISOString().slice(0, 10);
        const fpKey = order.forma_pagamento_key || 'dinheiro';
        const fpId = FORMAS_PAGAMENTO[fpKey]?.id || 23368;
        const itensBling = items.map(it => buildItemBling(it));
        const payload = {
          contato: { id: CONSUMIDOR_FINAL_ID, tipoPessoa: 'F' },
          data: today, dataSaida: today, itens: itensBling,
          parcelas: [{ formaPagamento: { id: fpId }, valor: order.total_value || 0, dataVencimento: today }],
          observacoes: `MoskoGás #${orderId} | ${order.vendedor_nome || ''} | ${order.tipo_pagamento || ''} - ${order.customer_name} [TEST]`,
        };
        const resp = await blingFetch('/pedidos/vendas', { method: 'POST', body: JSON.stringify(payload) }, env);
        const txt = await resp.text();
        let parsed; try { parsed = JSON.parse(txt); } catch { parsed = txt; }
        const auditStatus = resp.ok ? 'success' : 'error';
        await logBlingAudit(env, orderId, 'test_criar_venda', auditStatus, {
          bling_pedido_id: resp.ok ? String(parsed?.data?.id || '') : '',
          request_payload: payload,
          response_data: parsed,
          error_message: resp.ok ? null : `HTTP ${resp.status}`
        });
        return json({ order_id: orderId, payload_sent: payload, bling_status: resp.status, bling_response: parsed });
      } catch (e) { return json({ ok: false, error: e.message }); }
    }

    // [REMOVIDO v2.12.0] test-nfce — NFCe não existe na API Bling v3

    // ── Config pública (foto-config para entregador) ──
    if (method === 'GET' && path === '/api/pub/foto-config') {
      await ensureAuditTable(env); // garante tabela app_config existe
      const row = await env.DB.prepare("SELECT value FROM app_config WHERE key='foto_config'").first();
      const defaults = { formato: 'webp', maxDim: 1200, quality: 85, contraste: true, desaturacao: 50, sharpen: true };
      if (!row?.value) return json(defaults);
      try { return json({ ...defaults, ...JSON.parse(row.value) }); } catch { return json(defaults); }
    }

    // v2.30.0: QR Code Avaliação Google
    if (method === 'GET' && path === '/api/pub/review-config') {
      const row = await env.DB.prepare("SELECT value FROM app_config WHERE key='google_review_url'").first();
      return json({ url: row?.value || null });
    }

    // Registrar que QR foi mostrado ao cliente
    const qrShownMatch = path.match(/^\/api\/order\/(\d+)\/qr-shown$/);
    if (method === 'POST' && qrShownMatch) {
      const orderId = qrShownMatch[1];
      const user = await getSessionUser(request, env);
      await logEvent(env, orderId, 'qr_review_shown', {
        driver_id: user?.user_id || user?.id,
        driver_name: user?.nome
      });
      return json({ ok: true });
    }

    // Stats QR por entregador (admin)
    if (method === 'GET' && path === '/api/qr-review/stats') {
      const authCheck = await requireAuth(request, env, ['admin']);
      if (authCheck instanceof Response) return authCheck;
      const rows = await env.DB.prepare(`
        SELECT json_extract(details, '$.driver_name') as driver, COUNT(*) as total
        FROM order_events WHERE evento = 'qr_review_shown'
        GROUP BY driver ORDER BY total DESC
      `).all().then(r => r.results || []);
      const total = rows.reduce((s, r) => s + r.total, 0);
      return json({ total, by_driver: rows });
    }

    // ── PIX Debug (público) ─────────────────────────────────────
    const pixDbgMatch = path.match(/^\/api\/pub\/pix-debug\/(\d+)$/);
    if (method === 'GET' && pixDbgMatch) {
      await ensurePixColumns(env);
      const oid = parseInt(pixDbgMatch[1]);
      const o = await env.DB.prepare(
        'SELECT id, pix_tx_id, pix_qrcode, pix_paid_at, pago, status, tipo_pagamento, total_value, cora_invoice_id FROM orders WHERE id=?'
      ).bind(oid).first();
      return json({ ok: true, order: o || null, configured: isPixConfigured(env) });
    }

    // ── AUTH: Login / Sessão / Logout (SEM autenticação prévia) ──

    if (method === 'POST' && path === '/api/auth/login') {
      await ensureAuthTables(env);
      const body = await request.json();
      const { login, senha } = body;
      if (!login || !senha) return err('Login e senha obrigatórios');

      // v2.21.0: Rate limiting — 5 falhas em 15min por IP
      const clientIp = request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For') || 'unknown';
      const blocked = await checkRateLimit(env, clientIp);
      if (blocked) return err('Muitas tentativas. Aguarde 15 minutos.', 429);

      const user = await env.DB.prepare('SELECT * FROM app_users WHERE login = ? AND ativo = 1').bind(login.toLowerCase().trim()).first();
      if (!user) {
        await logLoginAttempt(env, clientIp, login, false);
        return err('Usuário ou senha inválidos', 401);
      }
      const valid = await verifyPassword(senha, user.senha_salt, user.senha_hash);
      if (!valid) {
        await logLoginAttempt(env, clientIp, login, false);
        return err('Usuário ou senha inválidos', 401);
      }

      await logLoginAttempt(env, clientIp, login, true);
      const now = Math.floor(Date.now() / 1000);
      await env.DB.prepare('DELETE FROM auth_sessions WHERE expires_at < ?').bind(now).run().catch(() => { });
      const token = generateToken();
      const expiresAt = now + 86400;
      await env.DB.prepare('INSERT INTO auth_sessions (token, user_id, expires_at) VALUES (?, ?, ?)').bind(token, user.id, expiresAt).run();
      return json({ ok: true, token, expires_at: expiresAt, user: { id: user.id, nome: user.nome, login: user.login, role: user.role, bling_vendedor_id: user.bling_vendedor_id, bling_vendedor_nome: user.bling_vendedor_nome, telefone: user.telefone } });
    }

    if (method === 'GET' && path === '/api/auth/session') {
      await ensureAuthTables(env);
      const user = await getSessionUser(request, env);
      if (!user) return err('Sessão inválida ou expirada', 401);
      return json({ ok: true, user: { id: user.user_id, nome: user.nome, login: user.login, role: user.role, bling_vendedor_id: user.bling_vendedor_id, bling_vendedor_nome: user.bling_vendedor_nome, telefone: user.telefone } });
    }

    if (method === 'POST' && path === '/api/auth/logout') {
      const authHeader = request.headers.get('Authorization') || '';
      const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : '';
      if (token) await env.DB.prepare('DELETE FROM auth_sessions WHERE token = ?').bind(token).run().catch(() => { });
      return json({ ok: true });
    }

    // v2.21.0: Trocar própria senha (todos os roles)
    if (method === 'PATCH' && path === '/api/auth/me/senha') {
      const authCheck = await requireAuth(request, env);
      if (authCheck instanceof Response) return authCheck;
      const userId = authCheck.user_id || authCheck.id;
      if (!userId || userId === 0) return err('API key não pode trocar senha', 400);

      const body = await request.json();
      const { senha_atual, nova_senha } = body;
      if (!senha_atual || !nova_senha) return err('Senha atual e nova senha obrigatórias');
      if (nova_senha.length < 4) return err('Nova senha deve ter pelo menos 4 caracteres');

      const user = await env.DB.prepare('SELECT * FROM app_users WHERE id = ?').bind(userId).first();
      if (!user) return err('Usuário não encontrado', 404);

      const valid = await verifyPassword(senha_atual, user.senha_salt, user.senha_hash);
      if (!valid) return err('Senha atual incorreta', 401);

      const newSalt = crypto.randomUUID();
      const newHash = await hashPassword(nova_senha, newSalt);
      await env.DB.prepare('UPDATE app_users SET senha_hash=?, senha_salt=?, updated_at=unixepoch() WHERE id=?')
        .bind(newHash, newSalt, userId).run();

      return json({ ok: true, message: 'Senha alterada com sucesso' });
    }

    // ── Buscar comprovante foto do R2 (público — abre em nova aba) ──
    const comprovanteMatch = path.match(/^\/api\/comprovante\/(\d+)$/);
    if (method === 'GET' && comprovanteMatch) {
      const orderId = parseInt(comprovanteMatch[1]);
      const order = await env.DB.prepare('SELECT foto_comprovante FROM orders WHERE id=?').bind(orderId).first();
      if (!order || !order.foto_comprovante) return err('Comprovante não encontrado', 404);

      const obj = await env.BUCKET.get(order.foto_comprovante);
      if (!obj) return err('Arquivo não encontrado no R2', 404);

      return new Response(obj.body, {
        headers: {
          'Content-Type': obj.httpMetadata?.contentType || 'image/jpeg',
          'Cache-Control': 'public, max-age=86400',
          'Access-Control-Allow-Origin': '*',
        },
      });
    }

    // Contratos, webhooks, rotas públicas e relatório (auth próprio) têm auth próprio
    if (!path.startsWith('/api/contratos') && !path.startsWith('/api/webhooks') && !path.startsWith('/api/pub/') && !path.startsWith('/api/pix/') && !path.startsWith('/api/relatorio/')) {
      const authErr = requireApiKey(request, env);
      if (authErr) return authErr;
    }

    // ── AUTH: Gestão de Usuários (requer admin) ─────────────────

    if (method === 'GET' && path === '/api/auth/users') {
      const authCheck = await requireAuth(request, env, ['admin', 'atendente']);
      if (authCheck instanceof Response) return authCheck;
      await ensureAuthTables(env);
      const isAdmin = authCheck.role === 'admin';
      const sql = isAdmin
        ? 'SELECT id, nome, login, role, bling_vendedor_id, bling_vendedor_nome, telefone, pode_entregar, recebe_whatsapp, ativo, created_at FROM app_users ORDER BY nome'
        : "SELECT id, nome, login, role, bling_vendedor_id, bling_vendedor_nome, telefone, pode_entregar, recebe_whatsapp, ativo, created_at FROM app_users WHERE role IN ('atendente','entregador') ORDER BY nome";
      const rows = await env.DB.prepare(sql).all();
      return json(rows.results || []);
    }

    if (method === 'POST' && path === '/api/auth/users') {
      const authCheck = await requireAuth(request, env, ['admin', 'atendente']);
      if (authCheck instanceof Response) return authCheck;
      await ensureAuthTables(env);
      const isAdmin = authCheck.role === 'admin';
      const body = await request.json();
      const { id, nome, login, senha, role, bling_vendedor_id, bling_vendedor_nome, telefone, pode_entregar, recebe_whatsapp, ativo } = body;
      if (!nome || !login) return err('Nome e login obrigatórios');
      if (!['admin', 'atendente', 'entregador'].includes(role || 'entregador')) return err('Role inválido');

      // v2.21.0: Atendente NÃO pode criar/editar admin
      if (!isAdmin && role === 'admin') return err('Sem permissão para criar/editar administradores', 403);
      if (!isAdmin && id) {
        const target = await env.DB.prepare('SELECT role FROM app_users WHERE id=?').bind(id).first();
        if (target && target.role === 'admin') return err('Sem permissão para editar administradores', 403);
      }

      if (id) {
        const existing = await env.DB.prepare('SELECT * FROM app_users WHERE id = ?').bind(id).first();
        if (!existing) return err('Usuário não encontrado');
        const dup = await env.DB.prepare('SELECT id FROM app_users WHERE login = ? AND id != ?').bind(login.toLowerCase().trim(), id).first();
        if (dup) return err('Login já em uso por outro usuário');

        if (senha) {
          const salt = crypto.randomUUID();
          const hash = await hashPassword(senha, salt);
          await env.DB.prepare('UPDATE app_users SET nome=?, login=?, senha_hash=?, senha_salt=?, role=?, bling_vendedor_id=?, bling_vendedor_nome=?, telefone=?, pode_entregar=?, recebe_whatsapp=?, ativo=?, updated_at=unixepoch() WHERE id=?')
            .bind(nome, login.toLowerCase().trim(), hash, salt, role || 'entregador', bling_vendedor_id || null, bling_vendedor_nome || null, telefone || null, pode_entregar ? 1 : 0, recebe_whatsapp ? 1 : 0, ativo !== undefined ? (ativo ? 1 : 0) : 1, id).run();
        } else {
          await env.DB.prepare('UPDATE app_users SET nome=?, login=?, role=?, bling_vendedor_id=?, bling_vendedor_nome=?, telefone=?, pode_entregar=?, recebe_whatsapp=?, ativo=?, updated_at=unixepoch() WHERE id=?')
            .bind(nome, login.toLowerCase().trim(), role || 'entregador', bling_vendedor_id || null, bling_vendedor_nome || null, telefone || null, pode_entregar ? 1 : 0, recebe_whatsapp ? 1 : 0, ativo !== undefined ? (ativo ? 1 : 0) : 1, id).run();
        }
        if (ativo !== undefined && !ativo) {
          await env.DB.prepare('DELETE FROM auth_sessions WHERE user_id = ?').bind(id).run().catch(() => { });
        }
        return json({ ok: true, id });
      } else {
        if (!senha) return err('Senha obrigatória para novo usuário');
        const dup = await env.DB.prepare('SELECT id FROM app_users WHERE login = ?').bind(login.toLowerCase().trim()).first();
        if (dup) return err('Login já existe');
        const salt = crypto.randomUUID();
        const hash = await hashPassword(senha, salt);
        const result = await env.DB.prepare('INSERT INTO app_users (nome, login, senha_hash, senha_salt, role, bling_vendedor_id, bling_vendedor_nome, telefone, pode_entregar, recebe_whatsapp, ativo) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)')
          .bind(nome, login.toLowerCase().trim(), hash, salt, role || 'entregador', bling_vendedor_id || null, bling_vendedor_nome || null, telefone || null, pode_entregar ? 1 : 0, recebe_whatsapp ? 1 : 0, ativo !== undefined ? (ativo ? 1 : 0) : 1).run();
        return json({ ok: true, id: result.meta?.last_row_id });
      }
    }

    if (method === 'DELETE' && path.startsWith('/api/auth/users/')) {
      const authCheck = await requireAuth(request, env, ['admin']);
      if (authCheck instanceof Response) return authCheck;
      return err('Exclusão de usuários desabilitada. Use edição com ativo=0 para desativar.', 403);
    }

    // ── CLIENTES ────────────────────────────────────────────

    // ══════════════════════════════════════════════════════════
    // FIX v2.11.3: Vendedores — busca contato.nome individual
    // Bling v3 GET /vendedores retorna contato.id mas SEM nome
    // Solução: para cada vendedor sem nome, GET /contatos/{id}
    // ══════════════════════════════════════════════════════════
    if (method === 'GET' && path === '/api/vendedores') {
      try {
        const debug = url.searchParams.get('debug') === '1';
        const resp = await blingFetch('/vendedores?pagina=1&limite=50', {}, env);
        if (!resp.ok) return json(debug ? { error: resp.status } : []);
        const data = await resp.json();
        if (debug) return json(data);
        // Buscar nome de cada contato individualmente
        const vendedores = data.data || [];
        const result = await Promise.all(vendedores.map(async (v) => {
          let name = v.contato?.nome || v.descricao || v.nome || '';
          const contatoId = v.contato?.id || null;
          // Se não veio nome mas tem contato.id, busca no Bling
          if (!name && contatoId) {
            try {
              const cResp = await blingFetch(`/contatos/${contatoId}`, {}, env);
              if (cResp.ok) {
                const cData = await cResp.json();
                name = cData.data?.nome || cData.data?.fantasia || '';
              }
            } catch (_) { }
          }
          return {
            id: v.id,
            name: name || ('Vendedor #' + v.id),
            contato_id: contatoId,
            situacao: v.contato?.situacao || v.situacao || '',
          };
        }));
        return json(result);
      } catch (e) { return json([]); }
    }

    if (method === 'GET' && path === '/api/products/search') {
      const q = (url.searchParams.get('q') || '').trim().toLowerCase();
      try {
        const blingUrl = q.length >= 2 ? `/produtos?pagina=1&limite=50&criterio=1&pesquisa=${encodeURIComponent(q)}` : `/produtos?pagina=1&limite=50&criterio=1`;
        const resp = await blingFetch(blingUrl, {}, env);
        if (!resp.ok) { const errText = await resp.text().catch(() => ''); return json({ error: `Bling ${resp.status}: ${errText.substring(0, 200)}` }, 502); }
        const data = await resp.json();
        const all = (data.data || []);
        const filtered = q ? all.filter(p => { const nome = (p.descricao || p.nome || '').toLowerCase(); return nome.includes(q); }) : all;
        const produtos = (filtered.length ? filtered : all).map(p => ({ id: p.id, name: p.descricao || p.nome || '', code: p.codigo || '', price: parseFloat(p.preco) || 0, unit: p.unidade || 'un' }));
        return json(produtos.slice(0, 15));
      } catch (e) { return json({ error: e.message }, 500); }
    }

    // ── PRODUTOS FAVORITOS ────────────────────────────────────
    if (method === 'GET' && path === '/api/products/favorites') {
      const authCheck = await requireAuth(request, env, ['admin', 'atendente']);
      if (authCheck instanceof Response) return authCheck;
      await ensureAuditTable(env);
      const rows = await env.DB.prepare('SELECT * FROM product_favorites ORDER BY sort_order ASC, id ASC').all().then(r => r.results || []);
      return json(rows);
    }

    if (method === 'POST' && path === '/api/products/favorites') {
      const authCheck = await requireAuth(request, env, ['admin']);
      if (authCheck instanceof Response) return authCheck;
      await ensureAuditTable(env);
      const body = await request.json();
      const { bling_id, name, code, price } = body;
      if (!bling_id || !name) return json({ error: 'bling_id e name obrigatórios' }, 400);
      // Evitar duplicata
      const exists = await env.DB.prepare('SELECT id FROM product_favorites WHERE bling_id = ?').bind(String(bling_id)).first();
      if (exists) return json({ error: 'Produto já é favorito' }, 409);
      // Próximo sort_order
      const maxSort = await env.DB.prepare('SELECT MAX(sort_order) as mx FROM product_favorites').first();
      const nextSort = (maxSort?.mx || 0) + 1;
      await env.DB.prepare('INSERT INTO product_favorites (bling_id, name, code, price, sort_order) VALUES (?,?,?,?,?)')
        .bind(String(bling_id), name, code || '', parseFloat(price) || 0, nextSort).run();
      return json({ ok: true, message: 'Favorito adicionado' });
    }

    const favDeleteMatch = path.match(/^\/api\/products\/favorites\/(\d+)$/);
    if (method === 'DELETE' && favDeleteMatch) {
      const authCheck = await requireAuth(request, env, ['admin']);
      if (authCheck instanceof Response) return authCheck;
      const favId = favDeleteMatch[1];
      await env.DB.prepare('DELETE FROM product_favorites WHERE id = ?').bind(favId).run();
      return json({ ok: true, message: 'Favorito removido' });
    }

    if (method === 'PATCH' && path === '/api/products/favorites/reorder') {
      const authCheck = await requireAuth(request, env, ['admin']);
      if (authCheck instanceof Response) return authCheck;
      const body = await request.json();
      const { order } = body; // array de IDs na ordem desejada
      if (!Array.isArray(order)) return json({ error: 'order deve ser array de IDs' }, 400);
      for (let i = 0; i < order.length; i++) {
        await env.DB.prepare('UPDATE product_favorites SET sort_order = ? WHERE id = ?').bind(i + 1, order[i]).run();
      }
      return json({ ok: true, message: 'Ordem atualizada' });
    }

    // ── BUSCA COMBINADA ──────────────────────────────────────
    if (method === 'GET' && path === '/api/customer/search-multi') {
      const qPhone = (url.searchParams.get('phone') || '').replace(/\D/g, '');
      const qName = (url.searchParams.get('name') || '').trim();
      const qAddr = (url.searchParams.get('addr') || '').trim();
      const results = []; const seenPhone = new Set(); const seenBling = new Set();

      // v2.28.0: busca multi-palavra — cada palavra vira um AND LIKE separado
      const nameWords = qName ? qName.split(/\s+/).filter(Boolean) : [];
      {
        let sql = 'SELECT * FROM customers_cache WHERE 1=1'; const p = [];
        if (qPhone) { sql += ' AND phone_digits LIKE ?'; p.push(`%${qPhone}%`); }
        for (const w of nameWords) { sql += ' AND name LIKE ?'; p.push(`%${w}%`); }
        if (qAddr) { sql += ' AND (address_line LIKE ? OR bairro LIKE ?)'; p.push(`%${qAddr}%`, `%${qAddr}%`); }
        sql += ' ORDER BY name ASC LIMIT 15';
        const rows = await env.DB.prepare(sql).bind(...p).all().then(r => r.results || []);
        for (const r of rows) {
          if (seenPhone.has(r.phone_digits)) continue;
          if (r.bling_contact_id && seenBling.has(r.bling_contact_id)) continue;
          seenPhone.add(r.phone_digits);
          if (r.bling_contact_id) seenBling.add(r.bling_contact_id);
          results.push(r);
        }
      }

      if (qAddr || nameWords.length > 0) {
        const addrCond = qAddr ? '(ca.address_line LIKE ? OR ca.bairro LIKE ? OR ca.obs LIKE ?)' : null;
        // multi-palavra: cada palavra vira (cc.name LIKE ? OR ca.obs LIKE ?)
        const nameCondParts = nameWords.map(() => '(cc.name LIKE ? OR ca.obs LIKE ?)');
        const conditions = [addrCond, ...nameCondParts].filter(Boolean).join(' AND ');
        let sql2 = `SELECT cc.*, ca.address_line AS ca_addr, ca.bairro AS ca_bairro, ca.complemento AS ca_comp, ca.referencia AS ca_ref, ca.obs AS ca_obs FROM customer_addresses ca JOIN customers_cache cc ON cc.phone_digits = ca.phone_digits WHERE ${conditions}`;
        const p2 = [];
        if (qAddr) p2.push(`%${qAddr}%`, `%${qAddr}%`, `%${qAddr}%`);
        for (const w of nameWords) p2.push(`%${w}%`, `%${w}%`);
        if (qPhone) { sql2 += ' AND ca.phone_digits LIKE ?'; p2.push(`%${qPhone}%`); }
        sql2 += ' ORDER BY cc.name ASC LIMIT 15';
        const extraRows = await env.DB.prepare(sql2).bind(...p2).all().then(r => r.results || []);
        for (const r of extraRows) {
          const enriched = { ...r, address_line: r.ca_addr || r.address_line, bairro: r.ca_bairro || r.bairro, complemento: r.ca_comp || r.complemento, referencia: r.ca_ref || r.referencia, _extra_obs: r.ca_obs };
          if (!seenPhone.has(r.phone_digits)) {
            if (enriched.bling_contact_id && seenBling.has(enriched.bling_contact_id)) continue;
            seenPhone.add(r.phone_digits);
            if (enriched.bling_contact_id) seenBling.add(enriched.bling_contact_id);
            results.push(enriched);
          } else { const idx = results.findIndex(x => x.phone_digits === r.phone_digits); if (idx >= 0) results[idx] = enriched; }
        }
      }

      if (results.length < 5) {
        try {
          const blingQ = qName || qAddr;
          if (blingQ) {
            const resp = await blingFetch(`/contatos?pagina=1&limite=20&pesquisa=${encodeURIComponent(blingQ)}`, {}, env);
            if (resp.ok) {
              const data = await resp.json();
              const ql_addr = qAddr.toLowerCase();
              const filtrados = (data.data || []).filter(cont => {
                const nome = (cont.nome || '').toLowerCase();
                const end = cont.endereco || {};
                const rua = ((end.geral?.endereco || end.endereco || '') + ' ' + (end.geral?.bairro || end.bairro || '')).toLowerCase();
                const fone = (cont.celular || cont.telefone || '').replace(/\D/g, '');
                // multi-palavra: todas as palavras devem estar no nome
                const nameMatch = nameWords.length === 0 || nameWords.every(w => nome.includes(w.toLowerCase()));
                return nameMatch && (!qAddr || rua.includes(ql_addr)) && (!qPhone || fone.includes(qPhone));
              });
              const blingRows = mapContatos(filtrados);
              if (blingRows.length) await saveContactsCache(blingRows, env);
              for (const r of blingRows) { if (!seenPhone.has(r.phone_digits)) { seenPhone.add(r.phone_digits); results.push(r); } }
            }
          }
        } catch (_) { }
      }
      return json(results.slice(0, 12));
    }

    if (method === 'GET' && path === '/api/customer/search') {
      const q = (url.searchParams.get('q') || '').trim();
      const type = url.searchParams.get('type') || 'name';
      if (q.length < 2) return json([]);
      const digits = q.replace(/\D/g, '');

      if (type === 'phone') {
        let rows = [];
        if (digits.length >= 6) {
          const byEnd = await env.DB.prepare("SELECT * FROM customers_cache WHERE phone_digits LIKE ? LIMIT 10").bind(`%${digits}`).all().then(r => r.results);
          if (byEnd.length > 0) rows = byEnd;
          else rows = await env.DB.prepare("SELECT * FROM customers_cache WHERE phone_digits LIKE ? LIMIT 10").bind(`%${digits}%`).all().then(r => r.results);
        }
        if (rows.length > 0) return json(rows);
        try {
          const resp = await blingFetch(`/contatos?pagina=1&limite=10&telefone=${digits}`, {}, env);
          if (resp.ok) { const data = await resp.json(); const result = mapContatos(data.data || []); await saveContactsCache(result, env); return json(result); }
        } catch (_) { }
        return json([]);
      }

      if (type === 'address') {
        const cacheRows = await env.DB.prepare("SELECT * FROM customers_cache WHERE address_line LIKE ? OR bairro LIKE ? LIMIT 10").bind(`%${q}%`, `%${q}%`).all().then(r => r.results);
        let multiRows = [];
        try {
          const mr = await env.DB.prepare(`SELECT ca.phone_digits, ca.address_line, ca.bairro, ca.complemento, ca.referencia, ca.obs, cc.name FROM customer_addresses ca LEFT JOIN customers_cache cc ON cc.phone_digits = ca.phone_digits WHERE ca.obs LIKE ? OR ca.address_line LIKE ? OR ca.bairro LIKE ? LIMIT 10`).bind(`%${q}%`, `%${q}%`, `%${q}%`).all().then(r => r.results);
          multiRows = mr.map(r => ({ name: r.name || r.phone_digits, phone_digits: r.phone_digits, address_line: r.address_line, bairro: r.bairro, complemento: r.complemento, referencia: r.referencia, obs: r.obs }));
        } catch (_) { }
        const orderRows = await env.DB.prepare(`SELECT DISTINCT customer_name AS name, phone_digits, address_line, bairro, complemento, referencia FROM orders WHERE address_line LIKE ? OR bairro LIKE ? ORDER BY created_at DESC LIMIT 10`).bind(`%${q}%`, `%${q}%`).all().then(r => r.results);
        let blingRows = [];
        try {
          const resp = await blingFetch(`/contatos?pagina=1&limite=20&pesquisa=${encodeURIComponent(q)}`, {}, env);
          if (resp.ok) {
            const data = await resp.json(); const ql = q.toLowerCase();
            const filtrados = (data.data || []).filter(c => { const end = ((c.endereco?.geral?.endereco || c.endereco?.endereco || '') + ' ' + (c.endereco?.geral?.bairro || c.endereco?.bairro || '')).toLowerCase(); return end.includes(ql); });
            blingRows = mapContatos(filtrados); if (blingRows.length > 0) await saveContactsCache(blingRows, env);
          }
        } catch (_) { }
        const seen = new Set();
        const merged = [...multiRows, ...blingRows, ...cacheRows, ...orderRows].filter(r => { const key = r.phone_digits || r.name || Math.random(); if (seen.has(key)) return false; seen.add(key); return true; });
        return json(merged.slice(0, 12));
      }

      // Nome
      let blingByName = [];
      try {
        const resp = await blingFetch(`/contatos?pagina=1&limite=30&pesquisa=${encodeURIComponent(q)}`, {}, env);
        if (resp.ok) {
          const data = await resp.json(); const ql = q.toLowerCase();
          const filtrados = (data.data || []).filter(c => (c.nome || '').toLowerCase().includes(ql) || (c.fantasia || '').toLowerCase().includes(ql));
          blingByName = mapContatos(filtrados); if (blingByName.length > 0) await saveContactsCache(blingByName, env);
        }
      } catch (_) { }
      const cacheByName = await env.DB.prepare("SELECT * FROM customers_cache WHERE name LIKE ? ORDER BY name LIMIT 20").bind(`%${q}%`).all().then(r => r.results || []);
      const orderByName = await env.DB.prepare(`SELECT DISTINCT customer_name AS name, phone_digits, address_line, bairro, complemento, referencia FROM orders WHERE customer_name LIKE ? ORDER BY created_at DESC LIMIT 10`).bind(`%${q}%`).all().then(r => r.results || []);
      const seenId = new Set(); const seenName = new Set(); const merged = [];
      for (const r of [...blingByName, ...cacheByName, ...orderByName]) {
        const bid = r.bling_contact_id ? String(r.bling_contact_id) : null;
        const nome = (r.name || '').trim().toLowerCase();
        if (bid && seenId.has(bid)) continue; if (seenName.has(nome)) continue;
        if (bid) seenId.add(bid); seenName.add(nome); merged.push(r);
      }
      return json(merged.slice(0, 12));
    }

    // ── CADASTRO COMPLETO DE CLIENTE NO BLING (PF/PJ) ──────
    if (method === 'POST' && path === '/api/customer/create-bling') {
      const body = await request.json();
      const { tipoPessoa, nome, fantasia, numeroDocumento, ie, contribuinte, telefone, celular, email, emailNfe, endereco, numero, bairro, complemento, cep } = body;

      if (!nome) return json({ error: 'Nome obrigatório' }, 400);

      const extraCols = ['cpf_cnpj TEXT', 'email TEXT', 'email_nfe TEXT', 'tipo_pessoa TEXT'];
      for (const col of extraCols) { await env.DB.prepare(`ALTER TABLE customers_cache ADD COLUMN ${col}`).run().catch(() => { }); }

      const blingBody = {
        nome: nome,
        fantasia: fantasia || '',
        tipoPessoa: tipoPessoa || 'F',
        contribuinte: contribuinte || 9,
        situacao: 'A',
        numeroDocumento: (numeroDocumento || '').replace(/[^\d]/g, ''),
        ie: ie || '',
        telefone: telefone || '',
        celular: (celular || '').replace(/\D/g, ''),
        email: email || '',
        endereco: {
          endereco: endereco || '',
          numero: numero || 'S/N',
          bairro: bairro || '',
          complemento: complemento || '',
          cep: (cep || '').replace(/\D/g, ''),
          municipio: 'Campo Grande',
          uf: 'MS',
          pais: 'Brasil',
        },
        tiposContato: [{ descricao: 'Cliente' }],
      };

      if (emailNfe) blingBody.email = emailNfe;

      try {
        const bResp = await blingFetch('/contatos', { method: 'POST', body: JSON.stringify(blingBody) }, env);
        const bData = await bResp.json();

        if (!bResp.ok) {
          // Extrair detalhes de erro do Bling v3 (fields com mensagens específicas)
          let errMsg = bData?.error?.message || bData?.error?.description || '';
          const fields = bData?.error?.fields || bData?.error?.errors || [];
          if (Array.isArray(fields) && fields.length > 0) {
            const fieldMsgs = fields.map(f => f.message || f.msg || `${f.fieldName || f.field}: erro`).join('; ');
            errMsg = fieldMsgs || errMsg;
          }
          if (!errMsg) errMsg = JSON.stringify(bData).substring(0, 300);
          return json({ ok: false, error: errMsg, bling_status: bResp.status, bling_detail: bData });
        }

        const blingId = bData.data?.id;
        const digits = (celular || telefone || '').replace(/\D/g, '');

        if (digits) {
          await env.DB.prepare(`
            INSERT OR REPLACE INTO customers_cache (phone_digits, name, address_line, bairro, complemento, bling_contact_id, cpf_cnpj, email, email_nfe, tipo_pessoa, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, unixepoch())
          `).bind(digits, nome, endereco ? `${endereco}, ${numero || 'S/N'}` : '', bairro || '', complemento || '', blingId, numeroDocumento || '', email || '', emailNfe || '', tipoPessoa || 'F').run();
        }

        return json({ ok: true, bling_contact_id: blingId, nome, numeroDocumento });
      } catch (e) {
        return json({ ok: false, error: e.message });
      }
    }

    // ── ÚLTIMO PEDIDO DO CLIENTE ────────────────────────────────
    if (method === 'GET' && path === '/api/customer/last-order') {
      const phone = (url.searchParams.get('phone') || '').replace(/\D/g, '');
      if (!phone || phone.length < 6) return json({ found: false });
      const order = await env.DB.prepare(
        `SELECT id, customer_name, items_json, total_value, tipo_pagamento, created_at, status
         FROM orders WHERE phone_digits LIKE ? AND status != 'cancelado'
         ORDER BY created_at DESC LIMIT 1`
      ).bind(`%${phone.slice(-8)}%`).first();
      if (!order) return json({ found: false });
      return json({ found: true, order: { ...order, items: JSON.parse(order.items_json || '[]') } });
    }

    // ── PRODUTOS APP (preços sugeridos) ──────────────────────────
    if (path.startsWith('/api/app-products') || path.startsWith('/api/pub/product-icon/')) {
      await env.DB.prepare(`CREATE TABLE IF NOT EXISTS app_products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        bling_id TEXT,
        name TEXT NOT NULL,
        code TEXT DEFAULT '',
        price REAL DEFAULT 0,
        is_favorite INTEGER DEFAULT 0,
        sort_order INTEGER DEFAULT 0,
        ativo INTEGER DEFAULT 1,
        icon_key TEXT,
        created_at TEXT DEFAULT (datetime('now'))
      )`).run().catch(() => { });
      // Ensure icon_key column exists (migration)
      await env.DB.prepare("ALTER TABLE app_products ADD COLUMN icon_key TEXT").run().catch(() => { });
    }

    // Serve product icon from R2 (public)
    if (method === 'GET' && path.startsWith('/api/pub/product-icon/')) {
      const prodId = path.split('/').pop();
      const prod = await env.DB.prepare('SELECT icon_key FROM app_products WHERE id=?').bind(prodId).first();
      if (!prod?.icon_key) return err('Sem ícone', 404);
      const obj = await env.BUCKET.get(prod.icon_key);
      if (!obj) return err('Arquivo não encontrado no R2', 404);
      return new Response(obj.body, {
        headers: {
          'Content-Type': obj.httpMetadata?.contentType || 'image/webp',
          'Cache-Control': 'public, max-age=86400',
          'Access-Control-Allow-Origin': '*',
        }
      });
    }

    if (method === 'GET' && path === '/api/app-products') {
      const authCheck = await requireAuth(request, env, ['admin', 'atendente']);
      if (authCheck instanceof Response) return authCheck;
      const onlyFav = url.searchParams.get('favorites') === '1';
      const onlyActive = url.searchParams.get('active') !== '0';
      let sql = 'SELECT * FROM app_products WHERE 1=1';
      if (onlyFav) sql += ' AND is_favorite=1';
      if (onlyActive) sql += ' AND ativo=1';
      sql += ' ORDER BY sort_order ASC, name ASC';
      const rows = await env.DB.prepare(sql).all().then(r => r.results || []);
      // Add icon URLs
      rows.forEach(r => {
        r.icon_url = r.icon_key ? `/api/pub/product-icon/${r.id}` : null;
      });
      return json(rows);
    }

    // Reorder products (drag & drop)
    if (method === 'POST' && path === '/api/app-products/reorder') {
      const authCheck = await requireAuth(request, env, ['admin']);
      if (authCheck instanceof Response) return authCheck;
      const { order } = await request.json(); // [{id: 1}, {id: 3}, {id: 2}]
      if (!order?.length) return err('Array order obrigatório');
      for (let i = 0; i < order.length; i++) {
        await env.DB.prepare('UPDATE app_products SET sort_order=? WHERE id=?').bind(i + 1, order[i].id || order[i]).run();
      }
      return json({ ok: true, count: order.length });
    }

    // Upload product icon
    if (method === 'POST' && path.match(/^\/api\/app-products\/\d+\/icon$/)) {
      const authCheck = await requireAuth(request, env, ['admin']);
      if (authCheck instanceof Response) return authCheck;
      const prodId = path.split('/')[3];
      const prod = await env.DB.prepare('SELECT id, icon_key FROM app_products WHERE id=?').bind(prodId).first();
      if (!prod) return err('Produto não encontrado', 404);

      const formData = await request.formData();
      const file = formData.get('icon');
      if (!file) return err('Campo icon obrigatório');

      // Delete old icon if exists
      if (prod.icon_key) {
        await env.BUCKET.delete(prod.icon_key).catch(() => { });
      }

      const bytes = new Uint8Array(await file.arrayBuffer());
      const ext = (file.name || 'icon.webp').split('.').pop().toLowerCase();
      const key = `product-icons/${prodId}_${Date.now()}.${ext}`;
      await env.BUCKET.put(key, bytes, {
        httpMetadata: { contentType: file.type || 'image/webp' }
      });
      await env.DB.prepare('UPDATE app_products SET icon_key=? WHERE id=?').bind(key, prodId).run();
      return json({ ok: true, icon_key: key, icon_url: `/api/pub/product-icon/${prodId}` });
    }

    // Delete product icon
    if (method === 'DELETE' && path.match(/^\/api\/app-products\/\d+\/icon$/)) {
      const authCheck = await requireAuth(request, env, ['admin']);
      if (authCheck instanceof Response) return authCheck;
      const prodId = path.split('/')[3];
      const prod = await env.DB.prepare('SELECT icon_key FROM app_products WHERE id=?').bind(prodId).first();
      if (prod?.icon_key) {
        await env.BUCKET.delete(prod.icon_key).catch(() => { });
      }
      await env.DB.prepare('UPDATE app_products SET icon_key=NULL WHERE id=?').bind(prodId).run();
      return json({ ok: true });
    }

    if (method === 'POST' && path === '/api/app-products') {
      const authCheck = await requireAuth(request, env, ['admin']);
      if (authCheck instanceof Response) return authCheck;
      const body = await request.json();
      const { id, bling_id, name, code, price, is_favorite, sort_order, ativo } = body;
      if (!name) return err('Nome obrigatório');

      if (id) {
        // Update
        await env.DB.prepare(
          `UPDATE app_products SET bling_id=?, name=?, code=?, price=?, is_favorite=?, sort_order=?, ativo=? WHERE id=?`
        ).bind(bling_id || null, name, code || '', parseFloat(price) || 0, is_favorite ? 1 : 0, sort_order || 0, ativo !== undefined ? (ativo ? 1 : 0) : 1, id).run();
        return json({ ok: true, id });
      } else {
        // Insert
        const maxSort = await env.DB.prepare('SELECT MAX(sort_order) as mx FROM app_products').first();
        const result = await env.DB.prepare(
          `INSERT INTO app_products (bling_id, name, code, price, is_favorite, sort_order, ativo) VALUES (?,?,?,?,?,?,?)`
        ).bind(bling_id || null, name, code || '', parseFloat(price) || 0, is_favorite ? 1 : 0, (maxSort?.mx || 0) + 1, 1).run();
        return json({ ok: true, id: result.meta?.last_row_id });
      }
    }

    if (method === 'DELETE' && path.match(/^\/api\/app-products\/\d+$/)) {
      const authCheck = await requireAuth(request, env, ['admin']);
      if (authCheck instanceof Response) return authCheck;
      const prodId = path.split('/').pop();
      await env.DB.prepare('DELETE FROM app_products WHERE id=?').bind(prodId).run();
      return json({ ok: true });
    }

    if (method === 'POST' && path === '/api/app-products/import-bling') {
      const authCheck = await requireAuth(request, env, ['admin']);
      if (authCheck instanceof Response) return authCheck;
      // Importa produto do Bling para app_products
      const body = await request.json();
      const { bling_id, name, code, price, is_favorite } = body;
      if (!name) return err('Nome obrigatório');
      // Evitar duplicata por bling_id
      if (bling_id) {
        const exists = await env.DB.prepare('SELECT id FROM app_products WHERE bling_id=?').bind(String(bling_id)).first();
        if (exists) return json({ ok: true, id: exists.id, message: 'Produto já existe', existing: true });
      }
      const maxSort = await env.DB.prepare('SELECT MAX(sort_order) as mx FROM app_products').first();
      const result = await env.DB.prepare(
        `INSERT INTO app_products (bling_id, name, code, price, is_favorite, sort_order) VALUES (?,?,?,?,?,?)`
      ).bind(String(bling_id || ''), name, code || '', parseFloat(price) || 0, is_favorite ? 1 : 0, (maxSort?.mx || 0) + 1).run();
      return json({ ok: true, id: result.meta?.last_row_id });
    }

    // ── Busca contato Bling por nome (para vincular cliente) ──
    if (method === 'GET' && path === '/api/customer/search-bling-nome') {
      const q = (url.searchParams.get('q') || '').trim();
      if (!q || q.length < 2) return json([]);
      try {
        const resp = await blingFetch(`/contatos?pagina=1&limite=10&pesquisa=${encodeURIComponent(q)}&situacao=A`, {}, env);
        if (!resp.ok) return json([]);
        const data = await resp.json();
        const results = (data.data || []).map(c => ({
          id: c.id,
          nome: c.nome,
          fantasia: c.fantasia || '',
          numeroDocumento: c.numeroDocumento || '',
          telefone: c.telefone || c.celular || '',
          email: c.email || '',
        }));
        return json(results);
      } catch (e) { return json([]); }
    }

    // ── Vincular cliente local ao Bling contact ──
    if (method === 'POST' && path === '/api/customer/vincular-bling') {
      const { phone_digits, bling_contact_id, bling_nome } = await request.json();
      if (!phone_digits || !bling_contact_id) return err('phone_digits e bling_contact_id obrigatórios');
      await env.DB.prepare(
        `UPDATE customers_cache SET bling_contact_id=?, updated_at=unixepoch() WHERE phone_digits=?`
      ).bind(String(bling_contact_id), phone_digits).run();
      // Log
      console.log(`[vincular-bling] ${phone_digits} → Bling ${bling_contact_id} (${bling_nome})`);
      return json({ ok: true, phone_digits, bling_contact_id });
    }

    if (method === 'GET' && path === '/api/customer/search-bling-doc') {
      const doc = (url.searchParams.get('doc') || '').replace(/\D/g, '');
      if (!doc) return json({ error: 'Informe ?doc=CPF_ou_CNPJ' }, 400);
      try {
        const resp = await blingFetch(`/contatos?pagina=1&limite=5&pesquisa=${doc}`, {}, env);
        if (!resp.ok) return json({ results: [] });
        const data = await resp.json();
        const results = (data.data || []).map(c => ({
          id: c.id, nome: c.nome, fantasia: c.fantasia, tipo: c.tipo,
          numeroDocumento: c.numeroDocumento, telefone: c.telefone, celular: c.celular,
          email: c.email, ie: c.ie,
        }));
        return json({ results });
      } catch (e) { return json({ results: [], error: e.message }); }
    }

    if (method === 'POST' && path === '/api/customer/upsert') {
      const body = await request.json();
      const { phone, name, address_line, bairro, complemento, referencia, bling_contact_id, cpf_cnpj } = body;
      const digits = (phone || '').replace(/\D/g, '');

      // v2.28.8: Preservar bling_contact_id existente se não fornecido
      const existing = digits ? await env.DB.prepare('SELECT bling_contact_id, cpf_cnpj FROM customers_cache WHERE phone_digits=?').bind(digits).first().catch(() => null) : null;
      const finalBlingId = bling_contact_id || existing?.bling_contact_id || null;
      const finalCpf = cpf_cnpj || existing?.cpf_cnpj || null;

      await env.DB.prepare(`INSERT OR REPLACE INTO customers_cache (phone_digits, name, address_line, bairro, complemento, referencia, bling_contact_id, cpf_cnpj, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, unixepoch())`).bind(digits, name, address_line, bairro, complemento, referencia, finalBlingId, finalCpf).run();
      return json({ ok: true, bling_contact_id: finalBlingId });
    }

    // ── PEDIDOS ──────────────────────────────────────────────

    if (method === 'POST' && path === '/api/order/create') {
      const body = await request.json();
      const { phone, name, address_line, bairro, complemento, referencia, items, total_value, notes, emitir_nfce, forma_pagamento_key, forma_pagamento_id, bling_contact_id, tipo_pagamento, empenho_id } = body;
      const digits = (phone || '').replace(/\D/g, '');

      const cols = ['forma_pagamento_id INTEGER', 'forma_pagamento_key TEXT', 'emitir_nfce INTEGER', 'nfce_gerada INTEGER', 'nfce_numero TEXT', 'nfce_chave TEXT', 'bling_pedido_id INTEGER', 'bling_pedido_num INTEGER', 'pago INTEGER DEFAULT 0', 'tipo_pagamento TEXT', 'vendedor_id INTEGER', 'vendedor_nome TEXT', 'foto_comprovante TEXT', 'observacao_entregador TEXT', 'tipo_pagamento_original TEXT', 'delivered_at TEXT'];
      for (const col of cols) { await env.DB.prepare(`ALTER TABLE orders ADD COLUMN ${col}`).run().catch(() => { }); }

      let vendedorId = body.vendedor_id || null;
      let vendedorNome = body.vendedor_nome || null;
      let blingVendedorId = body.bling_vendedor_id || null;
      if (!vendedorId) {
        const sessionUser = await getSessionUser(request, env).catch(() => null);
        if (sessionUser) {
          vendedorId = sessionUser.user_id || sessionUser.id;
          vendedorNome = sessionUser.nome;
          blingVendedorId = sessionUser.bling_vendedor_id || null;
        }
      }

      const tipoPg = tipo_pagamento || 'dinheiro';
      // v2.17.0: Bling só é criado ao marcar ENTREGUE. Pedido novo = só D1.
      const pago = 0; // Nunca pago ao criar — só ao entregar

      const result = await env.DB.prepare(`
        INSERT INTO orders (phone_digits, customer_name, address_line, bairro, complemento, referencia, items_json, total_value, notes, status, sync_status, forma_pagamento_key, forma_pagamento_id, emitir_nfce, tipo_pagamento, pago, vendedor_id, vendedor_nome)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'novo', 'pending', ?, ?, ?, ?, ?, ?, ?)
      `).bind(digits || '', name || '', address_line || '', bairro || '', complemento || '', referencia || '', JSON.stringify(items || []), total_value != null ? total_value : null, notes || null, forma_pagamento_key || null, forma_pagamento_id != null ? Number(forma_pagamento_id) : null, emitir_nfce ? 1 : 0, tipoPg, pago, vendedorId, vendedorNome).run();

      const orderId = result.meta?.last_row_id;
      try { await env.DB.prepare('INSERT OR IGNORE INTO payments (order_id, status, method) VALUES (?, ?, ?)').bind(orderId, 'pendente', forma_pagamento_key || null).run(); } catch (_) { }
      await logEvent(env, orderId, 'created', { name, address_line, tipo_pagamento: tipoPg, pago, vendedor: vendedorNome });
      await logBlingAudit(env, orderId, 'criar_venda', 'skipped', { error_message: `Bling será criado ao marcar entregue` });

      // v2.41.0: Vincular empenho GOV se informado
      if (empenho_id) {
        await ensureEmpenhoTables(env);
        try {
          const empenho = await env.DB.prepare('SELECT * FROM gov_empenhos WHERE id=?').bind(parseInt(empenho_id)).first();
          if (empenho) {
            // Montar itens_vendidos a partir dos items do pedido
            const itensVendidos = (items || []).map(it => ({ produto_nome: it.name, qty: parseInt(it.qty) || 1 }));
            const qtdJson = {};
            for (const iv of itensVendidos) {
              const item = await env.DB.prepare(`SELECT * FROM gov_empenho_itens WHERE empenho_id=? AND produto_nome=?`).bind(parseInt(empenho_id), iv.produto_nome).first();
              if (item) {
                await env.DB.prepare(`UPDATE gov_empenho_itens SET quantidade_usada=quantidade_usada+? WHERE id=?`).bind(iv.qty, item.id).run();
                qtdJson[iv.produto_nome] = iv.qty;
                const itemAtualizado = { ...item, quantidade_usada: item.quantidade_usada + iv.qty };
                await alertarSaldoBaixo(env, empenho, itemAtualizado).catch(() => { });
              }
            }
            await env.DB.prepare(`INSERT INTO gov_empenho_vendas (empenho_id, order_id, quantidade_json) VALUES (?, ?, ?)`)
              .bind(parseInt(empenho_id), orderId, JSON.stringify(qtdJson)).run();
            // Verificar esgotamento
            const todosItens = await env.DB.prepare('SELECT * FROM gov_empenho_itens WHERE empenho_id=?').bind(parseInt(empenho_id)).all().then(r => r.results || []);
            if (todosItens.every(it => it.quantidade_usada >= it.quantidade_total)) {
              await env.DB.prepare(`UPDATE gov_empenhos SET status='esgotado', updated_at=unixepoch() WHERE id=?`).bind(parseInt(empenho_id)).run();
            }
            await logEvent(env, orderId, 'empenho_vinculado', { empenho_id, empenho_numero: empenho.numero });
          }
        } catch (e) { console.error('[empenho] vincular error:', e.message); }
      }

      return json({ ok: true, id: orderId, bling_pedido_id: null, pago, vendedor: vendedorNome });
    }

    // ══════════════════════════════════════════════════════════
    // v2.30.0: VENDA EXTERNA (entregador cria + entrega em 1 passo)
    // ══════════════════════════════════════════════════════════
    if (method === 'POST' && path === '/api/order/venda-externa') {
      const user = await getSessionUser(request, env);
      if (!user) return err('Sessão expirada', 401);

      const ct = request.headers.get('Content-Type') || '';
      if (!ct.includes('multipart/form-data')) return err('Content-Type deve ser multipart/form-data', 400);

      const formData = await request.formData();
      const customerName = formData.get('customer_name') || 'Cliente Avulso';
      const phone = (formData.get('phone') || '').replace(/\D/g, '');
      const addressLine = formData.get('address_line') || '';
      const bairro = formData.get('bairro') || '';
      const itemsJson = formData.get('items_json') || '[]';
      const totalValue = parseFloat(formData.get('total_value')) || 0;
      const tipoPagamento = formData.get('tipo_pagamento') || 'dinheiro';
      const obsEntregador = formData.get('observacao_entregador') || '';
      const photoFile = formData.get('photo');

      // Foto obrigatória
      if (!photoFile || !(photoFile instanceof File) || photoFile.size < 100) {
        return err('Foto do comprovante é obrigatória', 400);
      }
      const allowedTypes = ['image/jpeg', 'image/png', 'image/webp'];
      if (!allowedTypes.includes(photoFile.type)) return err('Use JPG, PNG ou WebP', 400);
      if (photoFile.size > 5 * 1024 * 1024) return err('Foto muito grande (máx 5MB)', 400);

      // 1) Criar pedido como ENTREGUE direto
      const items = JSON.parse(itemsJson);
      const TIPOS_PAGO_IMEDIATO = ['dinheiro', 'pix_vista', 'debito', 'credito'];
      const pago = TIPOS_PAGO_IMEDIATO.includes(tipoPagamento) ? 1 : 0;

      const result = await env.DB.prepare(`
        INSERT INTO orders (phone_digits, customer_name, address_line, bairro, items_json, total_value,
          tipo_pagamento, pago, status, sync_status, driver_id, driver_name_cache, driver_phone_cache,
          vendedor_id, vendedor_nome, observacao_entregador, delivered_at, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'entregue', 'pending', ?, ?, ?, ?, ?, ?, unixepoch(), unixepoch(), unixepoch())
      `).bind(
        phone, customerName, addressLine, bairro, JSON.stringify(items), totalValue,
        tipoPagamento, pago, user.user_id, user.nome, user.telefone || '',
        user.user_id, user.nome, obsEntregador
      ).run();

      const orderId = result.meta?.last_row_id;

      // 2) Upload foto para R2
      const dateStr = new Date().toISOString().slice(0, 10);
      const ext = photoFile.type === 'image/png' ? 'png' : photoFile.type === 'image/webp' ? 'webp' : 'jpg';
      const photoKey = `comprovantes/${dateStr}/pedido_${orderId}_${Date.now()}.${ext}`;
      const arrayBuffer = await photoFile.arrayBuffer();
      await env.BUCKET.put(photoKey, arrayBuffer, {
        httpMetadata: { contentType: photoFile.type },
        customMetadata: { order_id: String(orderId), uploaded_by: user.nome, type: 'venda_externa' },
      });

      await env.DB.prepare('UPDATE orders SET foto_comprovante=? WHERE id=?').bind(photoKey, orderId).run();

      // 3) Criar Bling se aplicável
      const TIPOS_BLING = ['dinheiro', 'pix_vista', 'pix_receber', 'debito', 'credito'];
      let blingResult = null;
      if (TIPOS_BLING.includes(tipoPagamento)) {
        try {
          const custData = phone
            ? await env.DB.prepare('SELECT bling_contact_id, cpf_cnpj FROM customers_cache WHERE phone_digits=?').bind(phone).first()
            : null;
          const blingData = await criarPedidoBling(env, orderId, {
            name: customerName, items, total_value: totalValue,
            tipo_pagamento: tipoPagamento,
            bling_contact_id: custData?.bling_contact_id || null,
            cpf_cnpj: custData?.cpf_cnpj || null,
            bling_vendedor_id: user.bling_vendedor_id || null,
            vendedor_nome: user.bling_vendedor_nome || user.nome
          });
          await env.DB.prepare('UPDATE orders SET bling_pedido_id=?, bling_pedido_num=?, sync_status=? WHERE id=?')
            .bind(blingData.bling_pedido_id, blingData.bling_pedido_num, 'synced', orderId).run();
          blingResult = { action: 'created', bling_pedido_id: blingData.bling_pedido_id, bling_num: blingData.bling_pedido_num };
        } catch (e) {
          blingResult = { action: 'create_error', error: e.message };
          await logEvent(env, orderId, 'bling_error_venda_externa', { error: e.message });
        }
      }

      await logEvent(env, orderId, 'venda_externa', {
        driver: user.nome, tipo_pagamento: tipoPagamento, total: totalValue,
        items_count: items.length, foto: photoKey
      });

      // 4) Upsert cache cliente
      if (phone && customerName) {
        await env.DB.prepare(`INSERT OR REPLACE INTO customers_cache (phone_digits, name, address_line, bairro, updated_at)
          VALUES (?, ?, ?, ?, datetime('now'))`).bind(phone, customerName, addressLine, bairro).run().catch(() => { });
      }

      // 5) PushInPay PIX para venda externa pix_receber
      let pixResult = null;
      if (tipoPagamento === 'pix_receber' && isPixConfigured(env)) {
        try {
          await ensurePixColumns(env);
          const pixData = await pushInPayCreateCharge(env, orderId, totalValue);
          if (pixData.tx_id) {
            await env.DB.prepare('UPDATE orders SET pix_tx_id=?, pix_qrcode=?, pix_qrcode_base64=? WHERE id=?')
              .bind(pixData.tx_id, pixData.qr_code || '', pixData.qr_code_base64 || '', orderId).run();
            pixResult = { created: true, tx_id: pixData.tx_id, qrcode: pixData.qr_code };
          }
        } catch (pe) {
          pixResult = { error: pe.message };
          await logEvent(env, orderId, 'pushinpay_error_venda_ext', { error: pe.message });
        }
      }

      return json({ ok: true, id: orderId, status: 'entregue', pago, bling_result: blingResult, pix_result: pixResult });
    }

    // [REMOVIDO v2.12.0] POST /api/order/:id/gerar-nfce — NFCe não existe na API Bling v3

    if (method === 'POST' && path === '/api/bling/debug-pedido') {
      try {
        const body = await request.json();
        const { items, total_value, forma_pagamento_key, forma_pagamento_id } = body;
        const today = new Date().toISOString().slice(0, 10);
        const fpId = forma_pagamento_id || FORMAS_PAGAMENTO[forma_pagamento_key]?.id || 23368;
        const total = total_value || (items || []).reduce((s, i) => s + (i.price || 0) * (i.qty || 1), 0);
        const itensBling = (items || []).map(it => buildItemBling(it));
        const payload = { contato: { id: CONSUMIDOR_FINAL_ID, tipoPessoa: 'F' }, data: today, dataSaida: today, itens: itensBling, parcelas: [{ formaPagamento: { id: fpId }, valor: total, dataVencimento: today }] };
        const resp = await blingFetch('/pedidos/vendas', { method: 'POST', body: JSON.stringify(payload) }, env);
        const result = await resp.json();
        return json({ payload_sent: payload, bling_status: resp.status, bling_response: result });
      } catch (e) { return json({ error: e.message }); }
    }

    // [REMOVIDO v2.12.0] GET /api/bling/debug-nfce — NFCe não existe na API Bling v3

    if (method === 'GET' && path === '/api/formas-pagamento') {
      return json(Object.entries(FORMAS_PAGAMENTO).map(([key, v]) => ({ key, ...v })));
    }

    // ── Config (admin) ──────────────────────────────────────
    if (method === 'GET' && path === '/api/config') {
      const authCheck = await requireAuth(request, env, ['admin']);
      if (authCheck instanceof Response) return authCheck;
      const key = url.searchParams.get('key');
      if (!key) return err('Informe ?key=nome_da_config');
      const row = await env.DB.prepare("SELECT value, updated_at FROM app_config WHERE key=?").bind(key).first();
      if (!row) return json({ key, value: null });
      try { return json({ key, value: JSON.parse(row.value), updated_at: row.updated_at }); }
      catch { return json({ key, value: row.value, updated_at: row.updated_at }); }
    }

    if (method === 'POST' && path === '/api/config') {
      const authCheck = await requireAuth(request, env, ['admin']);
      if (authCheck instanceof Response) return authCheck;
      const body = await request.json();
      const { key, value } = body;
      if (!key) return err('Informe key');
      const valueStr = typeof value === 'string' ? value : JSON.stringify(value);
      await env.DB.prepare("INSERT OR REPLACE INTO app_config (key, value, updated_at) VALUES (?, ?, datetime('now'))").bind(key, valueStr).run();
      return json({ ok: true, key, value });
    }

    if (method === 'POST' && /^\/api\/order\/\d+\/update$/.test(path)) {
      const orderId = parseInt(path.split('/')[3]);
      const body = await request.json();
      const { customer_name, phone_digits, address_line, bairro, complemento, referencia, items, total_value, notes, tipo_pagamento, forma_pagamento_key, driver_id, confirm_bling_change } = body;

      // Buscar pedido atual para detectar mudança de tipo_pagamento
      const currentOrder = await env.DB.prepare('SELECT * FROM orders WHERE id=?').bind(orderId).first();
      if (!currentOrder) return err('Pedido não encontrado', 404);

      // Verificar permissão para editar pedido entregue
      if (currentOrder.status === 'entregue') {
        const editUser = await getSessionUser(request, env);
        if (editUser && editUser.role !== 'admin') {
          const permRow = await env.DB.prepare("SELECT value FROM app_config WHERE key='permissoes'").first().catch(() => null);
          let perms = { atendente_editar_entregue: false };
          try { if (permRow?.value) perms = { ...perms, ...JSON.parse(permRow.value) }; } catch { }
          if (!perms.atendente_editar_entregue) return err('Sem permissão para editar pedido entregue. Peça ao admin.', 403);
        }
      }

      const TIPOS_COM_BLING = ['dinheiro', 'pix_vista', 'pix_receber', 'debito', 'credito'];
      const TIPOS_PAGO_IMEDIATO = ['dinheiro', 'pix_vista', 'debito', 'credito'];

      const oldTipo = currentOrder.tipo_pagamento || '';
      const newTipo = tipo_pagamento !== undefined ? tipo_pagamento : oldTipo;
      const tipoChanged = tipo_pagamento !== undefined && tipo_pagamento !== oldTipo;

      const hasBling = !!currentOrder.bling_pedido_id;
      const isDelivered = currentOrder.status === 'entregue';

      // v2.17.0: Bling só existe após entrega. Só mexe no Bling se pedido já entregue E tem Bling
      let blingAction = 'none';
      if (tipoChanged && isDelivered && hasBling) {
        const newCriaBling = TIPOS_COM_BLING.includes(newTipo);
        if (!newCriaBling) {
          blingAction = 'delete'; // Ex: PIX→Mensal em pedido entregue: deletar Bling
        }
        // Se tipo mudou mas ambos criam Bling: deletar antigo e recriar
        // (preço/forma pgto pode ter mudado)
      } else if (tipoChanged && isDelivered && !hasBling) {
        blingAction = 'create'; // Pedido entregue sem Bling (falha anterior) → criar agora
      }

      // Se vai impactar Bling, exigir confirmação explícita do frontend
      if (blingAction !== 'none' && !confirm_bling_change) {
        return json({
          ok: false,
          requires_confirmation: true,
          bling_action: blingAction,
          message: blingAction === 'create'
            ? `Trocar para "${newTipo}" vai CRIAR uma venda no Bling (pedido entregue). Confirma?`
            : `Trocar para "${newTipo}" vai EXCLUIR a venda nº ${currentOrder.bling_pedido_num || currentOrder.bling_pedido_id} do Bling. Confirma?`
        });
      }

      // ── Montar UPDATE SQL ──
      let sql = `UPDATE orders SET customer_name=?, phone_digits=?, address_line=?, bairro=?, complemento=?, referencia=?, items_json=?, total_value=?, notes=?, updated_at=datetime('now')`;
      const params = [customer_name, phone_digits || '', address_line || '', bairro || '', complemento || '', referencia || '', JSON.stringify(items || []), total_value || 0, notes || ''];
      if (tipo_pagamento !== undefined) { sql += `, tipo_pagamento=?`; params.push(tipo_pagamento); }
      if (forma_pagamento_key !== undefined) { sql += `, forma_pagamento_key=?`; params.push(forma_pagamento_key); }
      if (driver_id !== undefined && driver_id !== null && driver_id !== '') {
        const driver = await env.DB.prepare('SELECT id, nome, telefone FROM app_users WHERE id=?').bind(parseInt(driver_id)).first();
        if (driver) {
          sql += `, driver_id=?, driver_name_cache=?, driver_phone_cache=?`;
          params.push(parseInt(driver_id), driver.nome, driver.telefone || '');
        }
      }

      // ── Executar ação Bling ──
      let blingResult = null;

      if (blingAction === 'create') {
        // Buscar dados do cliente para Bling (incluindo cpf_cnpj para decidir contato)
        const custData = phone_digits
          ? await env.DB.prepare('SELECT bling_contact_id, cpf_cnpj FROM customers_cache WHERE phone_digits=?').bind(phone_digits).first()
          : null;

        // Buscar vendedor
        const vendedorRow = currentOrder.vendedor_id
          ? await env.DB.prepare('SELECT bling_vendedor_id, bling_vendedor_nome FROM app_users WHERE id=?').bind(currentOrder.vendedor_id).first()
          : null;

        try {
          const blingData = await criarPedidoBling(env, orderId, {
            name: customer_name || currentOrder.customer_name,
            items: items || JSON.parse(currentOrder.items_json || '[]'),
            total_value: total_value || currentOrder.total_value,
            forma_pagamento_key, tipo_pagamento: newTipo,
            bling_contact_id: custData?.bling_contact_id || null,
            cpf_cnpj: custData?.cpf_cnpj || null,
            bling_vendedor_id: vendedorRow?.bling_vendedor_id || null,
            vendedor_nome: vendedorRow?.bling_vendedor_nome || currentOrder.vendedor_nome || ''
          });
          sql += `, bling_pedido_id=?, bling_pedido_num=?`;
          params.push(blingData.bling_pedido_id, blingData.bling_pedido_num);
          // Se tipo é pago imediato, marcar como pago
          if (TIPOS_PAGO_IMEDIATO.includes(newTipo)) {
            sql += `, pago=1`;
          }
          blingResult = { action: 'created', bling_pedido_id: blingData.bling_pedido_id, bling_pedido_num: blingData.bling_pedido_num };
        } catch (e) {
          console.error('[Update] Erro ao criar venda Bling:', e.message);
          blingResult = { action: 'create_error', error: e.message };
        }
      } else if (blingAction === 'delete') {
        const delResult = await deletarVendaBling(env, orderId, currentOrder.bling_pedido_id);
        if (delResult.ok) {
          sql += `, bling_pedido_id=NULL, bling_pedido_num=NULL, pago=0`;
          blingResult = { action: 'deleted', old_bling_id: currentOrder.bling_pedido_id };
        } else {
          // Falhou ao deletar — atualiza local mesmo assim mas avisa
          sql += `, pago=0`;
          blingResult = { action: 'delete_error', error: delResult.error || `HTTP ${delResult.status}`, old_bling_id: currentOrder.bling_pedido_id };
        }
      }

      sql += ` WHERE id=?`; params.push(orderId);
      await env.DB.prepare(sql).bind(...params).run();
      await logEvent(env, orderId, 'edited', { customer_name, address_line, tipo_pagamento, driver_id, bling_action: blingAction });
      return json({ ok: true, bling_result: blingResult });
    }

    if (method === 'GET' && path === '/api/orders/list') {
      const status = url.searchParams.get('status'); const driverId = url.searchParams.get('driver_id'); const q = url.searchParams.get('q'); const date = url.searchParams.get('date');
      let sql = `SELECT o.*, d.nome AS driver_name_db FROM orders o LEFT JOIN app_users d ON o.driver_id = d.id WHERE 1=1`;
      const params = [];
      if (status) {
        const statusList = status.split(',').map(s => s.trim()).filter(Boolean);
        if (statusList.length === 1) { sql += ` AND o.status = ?`; params.push(statusList[0]); }
        else if (statusList.length > 1) { sql += ` AND o.status IN (${statusList.map(() => '?').join(',')})`; params.push(...statusList); }
      }
      if (driverId) { sql += ` AND o.driver_id = ?`; params.push(driverId); }
      if (date) {
        // date=YYYY-MM-DD → filter by created_at (unix epoch) within that day in BRT (UTC-4)
        const dayStart = Math.floor(new Date(date + 'T00:00:00-04:00').getTime() / 1000);
        const dayEnd = dayStart + 86400;
        sql += ` AND o.created_at >= ? AND o.created_at < ?`;
        params.push(dayStart, dayEnd);
      }
      if (q) {
        const words = q.trim().toLowerCase().split(/\s+/).filter(Boolean);
        for (const w of words) {
          sql += ` AND (o.customer_name LIKE ? OR o.phone_digits LIKE ? OR o.address_line LIKE ?)`;
          params.push(`%${w}%`, `%${w}%`, `%${w}%`);
        }
      }
      sql += ' ORDER BY o.created_at DESC LIMIT 200';
      const rows = await env.DB.prepare(sql).bind(...params).all();
      return json(rows.results || []);
    }

    const selectDriverMatch = path.match(/^\/api\/order\/(\d+)\/select-driver$/);
    if (method === 'POST' && selectDriverMatch) {
      const id = selectDriverMatch[1];
      const user = await getSessionUser(request, env);
      const { driver_id } = await request.json();
      const driver = await env.DB.prepare('SELECT id, nome, telefone, recebe_whatsapp FROM app_users WHERE id=?').bind(driver_id).first();
      if (!driver) return err('driver not found');

      // v2.30.0: Detectar troca de entregador
      const currentOrder = await env.DB.prepare('SELECT driver_id, driver_name_cache, driver_phone_cache, status FROM orders WHERE id=?').bind(id).first();
      const oldDriverId = currentOrder?.driver_id;
      const oldDriverName = currentOrder?.driver_name_cache;
      const oldDriverPhone = currentOrder?.driver_phone_cache;
      const isSwap = oldDriverId && oldDriverId !== driver_id;

      await env.DB.prepare(`UPDATE orders SET driver_id=?, driver_name_cache=?, driver_phone_cache=?, status='encaminhado', updated_at=unixepoch() WHERE id=?`).bind(driver_id, driver.nome, driver.telefone || '', id).run();
      await logEvent(env, id, isSwap ? 'driver_swapped' : 'driver_selected', {
        driver_id, driver_name: driver.nome,
        ...(isSwap ? { old_driver_id: oldDriverId, old_driver_name: oldDriverName } : {})
      });
      await logStatusChange(env, id, currentOrder?.status || 'novo', 'encaminhado', `Entregador: ${driver.nome}${isSwap ? ` (antes: ${oldDriverName})` : ''}`, user);

      // v2.30.0: WhatsApp na troca de entregador
      let whatsappResults = { old: null, new: null };
      if (isSwap) {
        // Notificar entregador ANTIGO (cancelamento)
        if (oldDriverPhone) {
          const oldDriverUser = await env.DB.prepare('SELECT recebe_whatsapp FROM app_users WHERE id=?').bind(oldDriverId).first();
          if (oldDriverUser?.recebe_whatsapp) {
            const cancelMsg = `⚠️ *ENTREGA REATRIBUÍDA* — Pedido #${id}\n\nEsta entrega foi transferida para outro entregador. Por favor, *desconsidere* este pedido.\n\nEm caso de dúvidas, ligue para o administrativo ou confira suas entregas:\n📲 https://moskogas-app.pages.dev/entregador.html`;
            const cancelResult = await sendWhatsApp(env, oldDriverPhone, cancelMsg, { category: 'entrega' });
            whatsappResults.old = { sent: cancelResult.ok, driver: oldDriverName };
            await logEvent(env, id, 'whatsapp_swap_cancel', { to: oldDriverPhone, driver: oldDriverName, ok: cancelResult.ok });
          }
        }

        // Notificar entregador NOVO (entrega)
        if (driver.recebe_whatsapp && driver.telefone) {
          const order = await env.DB.prepare('SELECT * FROM orders WHERE id=?').bind(id).first();
          const newMsg = buildDeliveryMessage(order, '⚠️ REATRIBUIÇÃO — Esta entrega estava com ' + oldDriverName);
          const newResult = await sendWhatsApp(env, driver.telefone, newMsg, { category: 'entrega' });
          whatsappResults.new = { sent: newResult.ok, driver: driver.nome };
          if (newResult.ok) {
            await env.DB.prepare(`UPDATE orders SET status='whatsapp_enviado', updated_at=unixepoch() WHERE id=?`).bind(id).run();
          }
          await logEvent(env, id, 'whatsapp_swap_new', { to: driver.telefone, driver: driver.nome, ok: newResult.ok });
        }
      }

      return json({ ok: true, status: isSwap && whatsappResults.new?.sent ? 'whatsapp_enviado' : 'encaminhado', swap: isSwap, whatsapp: whatsappResults });
    }

    const sendWaMatch = path.match(/^\/api\/order\/(\d+)\/send-whatsapp$/);
    if (method === 'POST' && sendWaMatch) {
      const id = sendWaMatch[1];
      const { observation, driver_id, skip_whatsapp } = await request.json();
      let order = await env.DB.prepare('SELECT * FROM orders WHERE id=?').bind(id).first();
      if (!order) return err('order not found', 404);
      if (driver_id) {
        const driver = await env.DB.prepare('SELECT id, nome, telefone FROM app_users WHERE id=?').bind(driver_id).first();
        if (driver) {
          await env.DB.prepare(`UPDATE orders SET driver_id=?, driver_name_cache=?, driver_phone_cache=?, updated_at=unixepoch() WHERE id=?`).bind(driver_id, driver.nome, driver.telefone || '', id).run();
          order = { ...order, driver_id, driver_name_cache: driver.nome, driver_phone_cache: driver.telefone || '' };
        }
      }
      if (!order.driver_id) return err('Nenhum entregador selecionado');

      // Marcar como enviado sem WhatsApp (botão "Marcar Enviado" na gestão)
      if (skip_whatsapp) {
        await env.DB.prepare(`UPDATE orders SET status='whatsapp_enviado', updated_at=unixepoch() WHERE id=?`).bind(id).run();
        await logEvent(env, id, 'whatsapp_skipped', { driver_id: order.driver_id, reason: 'manual_skip' });
        return json({ ok: true, status: 'whatsapp_enviado', whatsapp_skipped: true });
      }
      // Checar se entregador recebe WhatsApp
      const driverUser = await env.DB.prepare('SELECT recebe_whatsapp, telefone FROM app_users WHERE id=?').bind(order.driver_id).first();
      if (!driverUser || !driverUser.recebe_whatsapp) {
        // Não envia WhatsApp, mas marca como encaminhado
        await env.DB.prepare(`UPDATE orders SET status='encaminhado', updated_at=unixepoch() WHERE id=?`).bind(id).run();
        await logEvent(env, id, 'whatsapp_skipped', { driver_id: order.driver_id, reason: 'recebe_whatsapp=0' });
        return json({ ok: true, status: 'encaminhado', whatsapp_skipped: true, message: 'Entregador não recebe WhatsApp — pedido encaminhado sem envio' });
      }
      if (!order.driver_phone_cache) return err('Entregador sem telefone cadastrado');
      const message = buildDeliveryMessage(order, observation);
      const result = await sendWhatsApp(env, order.driver_phone_cache, message, { category: 'entrega' });
      if (result.ok) {
        await env.DB.prepare(`UPDATE orders SET status='whatsapp_enviado', whatsapp_sent_at=unixepoch(), updated_at=unixepoch() WHERE id=?`).bind(id).run();
        await logEvent(env, id, 'whatsapp_sent', { to: order.driver_phone_cache });
        return json({ ok: true, status: 'whatsapp_enviado' });
      } else {
        const errDetail = result.safety
          ? `Bloqueado: ${result.safety.replace(/_/g, ' ')}`
          : (result.data?.error || result.data?.message || `HTTP ${result.status}`);
        return json({ ok: false, error: `WhatsApp: ${errDetail}`, detail: result }, 500);
      }
    }

    const deliveredMatch = path.match(/^\/api\/order\/(\d+)\/mark-delivered$/);
    if (method === 'POST' && deliveredMatch) {
      const id = parseInt(deliveredMatch[1]);
      const user = await getSessionUser(request, env);
      const order = await env.DB.prepare('SELECT * FROM orders WHERE id=?').bind(id).first();
      if (!order) return err('Pedido não encontrado', 404);

      let photoKey = null;
      let tipoPagamento = null;
      let obsEntregador = null;

      const ct = request.headers.get('Content-Type') || '';

      if (ct.includes('multipart/form-data')) {
        // ── Multipart: foto + dados ──
        const formData = await request.formData();
        const photoFile = formData.get('photo');
        tipoPagamento = formData.get('tipo_pagamento') || null;
        obsEntregador = formData.get('observacao_entregador') || null;

        if (!photoFile || !(photoFile instanceof File) || photoFile.size < 100) {
          return err('Foto do comprovante é obrigatória', 400);
        }

        // Validar tipo
        const allowedTypes = ['image/jpeg', 'image/png', 'image/webp'];
        if (!allowedTypes.includes(photoFile.type)) {
          return err('Tipo de arquivo inválido. Use JPG, PNG ou WebP.', 400);
        }

        // Limite 5MB (após compressão no cliente deve ser ~200-400KB)
        if (photoFile.size > 5 * 1024 * 1024) {
          return err('Foto muito grande (máx 5MB)', 400);
        }

        // Gerar key para R2
        const dateStr = new Date().toISOString().slice(0, 10);
        const ts = Date.now();
        const ext = photoFile.type === 'image/png' ? 'png' : photoFile.type === 'image/webp' ? 'webp' : 'jpg';
        photoKey = `comprovantes/${dateStr}/pedido_${id}_${ts}.${ext}`;

        // Upload para R2
        const arrayBuffer = await photoFile.arrayBuffer();
        await env.BUCKET.put(photoKey, arrayBuffer, {
          httpMetadata: { contentType: photoFile.type },
          customMetadata: {
            order_id: String(id),
            uploaded_by: user?.nome || 'entregador',
            original_name: photoFile.name || 'comprovante',
          },
        });

        console.log(`[R2] Foto salva: ${photoKey} (${(photoFile.size / 1024).toFixed(1)}KB)`);
      } else if (ct.includes('application/json')) {
        // Fallback JSON (sem foto — só admin pode)
        const body = await request.json();
        tipoPagamento = body.tipo_pagamento || null;
        obsEntregador = body.observacao_entregador || null;
        // Admin e atendente podem marcar sem foto (gestao.html)
        if (!['admin', 'atendente'].includes(user?.role)) {
          return err('Foto do comprovante é obrigatória para entregadores', 400);
        }
      } else {
        return err('Content-Type inválido', 400);
      }

      // ── Montar UPDATE SQL ──
      let sql = `UPDATE orders SET status='entregue', delivered_at=unixepoch(), updated_at=unixepoch()`;
      const params = [];

      if (photoKey) {
        sql += `, foto_comprovante=?`;
        params.push(photoKey);
      }

      if (obsEntregador) {
        sql += `, observacao_entregador=?`;
        params.push(obsEntregador);
      }

      // Tipo pagamento (entregador pode alterar na hora)
      const tipoFinal = tipoPagamento || order.tipo_pagamento || 'dinheiro';
      if (tipoPagamento && tipoPagamento !== order.tipo_pagamento) {
        if (!order.tipo_pagamento_original) {
          sql += `, tipo_pagamento_original=?`;
          params.push(order.tipo_pagamento);
        }
        sql += `, tipo_pagamento=?`;
        params.push(tipoPagamento);
      }

      // Marcar pago se tipo imediato
      const TIPOS_PAGO_IMEDIATO = ['dinheiro', 'pix_vista', 'debito', 'credito'];
      if (TIPOS_PAGO_IMEDIATO.includes(tipoFinal)) {
        sql += `, pago=1`;
      }

      // ── v2.17.0: Criar venda no Bling AGORA (ao entregar) ──
      // v2.28.7: Boleto/Mensalista NÃO criam Bling aqui — só via criar-vendas-bling (agrupado)
      const TIPOS_BLING_ENTREGA = ['dinheiro', 'pix_vista', 'pix_receber', 'debito', 'credito'];
      let blingResult = null;
      if (!order.bling_pedido_id && TIPOS_BLING_ENTREGA.includes(tipoFinal)) {
        try {
          const custData = order.phone_digits
            ? await env.DB.prepare('SELECT bling_contact_id, cpf_cnpj FROM customers_cache WHERE phone_digits=?').bind(order.phone_digits).first()
            : null;
          const vendedorRow = order.vendedor_id
            ? await env.DB.prepare('SELECT bling_vendedor_id, bling_vendedor_nome FROM app_users WHERE id=?').bind(order.vendedor_id).first()
            : null;

          const blingData = await criarPedidoBling(env, id, {
            name: order.customer_name,
            items: JSON.parse(order.items_json || '[]'),
            total_value: order.total_value,
            tipo_pagamento: tipoFinal,
            bling_contact_id: custData?.bling_contact_id || null,
            cpf_cnpj: custData?.cpf_cnpj || null,
            bling_vendedor_id: vendedorRow?.bling_vendedor_id || null,
            vendedor_nome: vendedorRow?.bling_vendedor_nome || order.vendedor_nome || ''
          });
          sql += `, bling_pedido_id=?, bling_pedido_num=?, sync_status='synced'`;
          params.push(blingData.bling_pedido_id, blingData.bling_pedido_num);
          blingResult = { action: 'created', bling_pedido_id: blingData.bling_pedido_id, bling_num: blingData.bling_pedido_num };
          await logEvent(env, id, 'bling_created_on_deliver', { bling_pedido_id: blingData.bling_pedido_id });
        } catch (e) {
          console.error('[Deliver] Erro criar Bling:', e.message);
          blingResult = { action: 'create_error', error: e.message };
          await logEvent(env, id, 'bling_error_on_deliver', { error: e.message });
          // NÃO bloqueia entrega — salva sem Bling, depois resolve em pagamentos
        }
      }

      // ── PushInPay PIX — gerar cobrança QR para pix_receber ──
      let pixResult = null;
      if (tipoFinal === 'pix_receber' && isPixConfigured(env)) {
        try {
          await ensurePixColumns(env);
          // Verificar se já tem QR existente (NÃO sobrescrever!)
          const existingPix = await env.DB.prepare('SELECT pix_tx_id, pix_qrcode FROM orders WHERE id=?').bind(id).first();
          if (existingPix?.pix_tx_id && existingPix?.pix_qrcode) {
            console.log(`[Deliver] Reusando QR existente pedido #${id} tx=${existingPix.pix_tx_id}`);
            pixResult = { created: false, reused: true, tx_id: existingPix.pix_tx_id };
          } else {
            const pixData = await pushInPayCreateCharge(env, id, order.total_value);
            if (pixData.tx_id) {
              sql += `, pix_tx_id=?, pix_qrcode=?, pix_qrcode_base64=?`;
              params.push(pixData.tx_id, pixData.qr_code || '', pixData.qr_code_base64 || '');
              pixResult = { created: true, tx_id: pixData.tx_id, has_qr: !!pixData.qr_code };
            }
          }
        } catch (pe) {
          console.error('[Deliver] Erro criar PushInPay PIX:', pe.message);
          pixResult = { created: false, error: pe.message };
          await logEvent(env, id, 'pushinpay_error_on_deliver', { error: pe.message });
        }
      }

      sql += ` WHERE id=?`;
      params.push(id);

      await env.DB.prepare(sql).bind(...params).run();
      await logEvent(env, id, 'delivered', {
        foto: photoKey,
        tipo_pagamento_changed: tipoPagamento !== order.tipo_pagamento ? tipoPagamento : null,
        observacao: obsEntregador,
      });

      return json({ ok: true, status: 'entregue', foto_key: photoKey, bling_result: blingResult, pix_result: pixResult });
    }

    const cancelMatch = path.match(/^\/api\/order\/(\d+)\/cancel$/);
    if (method === 'POST' && cancelMatch) {
      const id = parseInt(cancelMatch[1]);
      const user = await getSessionUser(request, env);
      if (!user) return err('Sessão expirada. Faça login novamente.', 401);

      const order = await env.DB.prepare('SELECT * FROM orders WHERE id=?').bind(id).first();
      if (!order) return err('Pedido não encontrado', 404);

      // Verificar permissão atendente para cancelar
      const isAdmin = user.role === 'admin';
      if (!isAdmin) {
        const permRow = await env.DB.prepare("SELECT value FROM app_config WHERE key='permissoes'").first().catch(() => null);
        let perms = { atendente_cancelar: true };
        try { if (permRow?.value) perms = { ...perms, ...JSON.parse(permRow.value) }; } catch { }
        if (!perms.atendente_cancelar) return err('Sem permissão para cancelar pedido. Peça ao admin.', 403);
      }

      // Motivo obrigatório
      let motivo = '';
      try {
        const body = await request.json();
        motivo = (body.motivo || '').trim();
      } catch (e) { }
      if (!motivo) return err('Motivo é obrigatório para cancelar', 400);

      const statusAnterior = order.status;
      const foiEntregue = statusAnterior === 'entregue';

      // Cancelar
      await env.DB.prepare(
        `UPDATE orders SET status='cancelado', canceled_at=unixepoch(), updated_at=unixepoch(), cancel_motivo=? WHERE id=?`
      ).bind(motivo, id).run();

      // Log de auditoria
      await logStatusChange(env, id, statusAnterior, 'cancelado', motivo, user);
      await logEvent(env, id, 'canceled', { motivo, status_anterior: statusAnterior, usuario: user?.nome });

      // ── Alerta WhatsApp pro admin ──
      // Se cancelou pós-entrega OU se quem cancelou não é admin
      let whatsappResult = null;
      if (foiEntregue || !isAdmin) {
        try {
          await ensureAuthTables(env);
          const admins = await env.DB.prepare(
            "SELECT nome, telefone FROM app_users WHERE role='admin' AND ativo=1 AND recebe_whatsapp=1 AND telefone IS NOT NULL AND telefone != ''"
          ).all();
          const adminList = admins.results || [];

          if (adminList.length > 0) {
            const risco = foiEntregue ? '🔴 *ALTO RISCO — Pós-entrega*' : '🟡 Cancelamento';
            const msg = `⚠️ ${risco}\n\n` +
              `📦 Pedido #${id}\n` +
              `👤 Cliente: ${order.customer_name}\n` +
              `💰 Valor: R$ ${(order.total_value || 0).toFixed(2)}\n` +
              `📋 Motivo: ${motivo}\n` +
              `👷 Cancelado por: ${user?.nome || 'desconhecido'}\n` +
              `🕐 ${new Date().toLocaleString('pt-BR', { timeZone: 'America/Campo_Grande' })}`;

            for (const adm of adminList) {
              const waResult = await sendWhatsApp(env, adm.telefone, msg, { category: 'admin_alerta', skipSafety: true });
              if (!whatsappResult) whatsappResult = waResult;
            }
          }
        } catch (e) { console.error('[cancelamento WhatsApp admin]', e.message); }
      }

      return json({
        ok: true,
        status: 'cancelado',
        status_anterior: statusAnterior,
        cancelamento_pos_entrega: foiEntregue,
        admin_notificado: whatsappResult?.ok || false
      });
    }

    // ── REABRIR / REVERTER STATUS ─────────────────────────────
    const revertMatch = path.match(/^\/api\/order\/(\d+)\/revert-status$/);
    if (method === 'POST' && revertMatch) {
      const id = parseInt(revertMatch[1]);
      const user = await getSessionUser(request, env);
      if (!user) return err('Sessão expirada. Faça login novamente.', 401);

      const order = await env.DB.prepare('SELECT * FROM orders WHERE id=?').bind(id).first();
      if (!order) return err('Pedido não encontrado', 404);

      let body = {};
      try { body = await request.json(); } catch (e) { }
      const novoStatus = (body.novo_status || '').trim().toLowerCase();
      const motivo = (body.motivo || '').trim();

      if (!motivo) return err('Motivo é obrigatório para reverter status', 400);

      const VALID_STATUSES = ['novo', 'encaminhado', 'whatsapp_enviado', 'entregue'];
      if (!VALID_STATUSES.includes(novoStatus)) return err('Status inválido: ' + novoStatus, 400);

      const statusAnterior = order.status;
      if (statusAnterior === novoStatus) return err('Pedido já está com status: ' + novoStatus, 400);

      // Carregar permissões dinâmicas
      const permRow = await env.DB.prepare("SELECT value FROM app_config WHERE key='permissoes'").first().catch(() => null);
      let perms = { atendente_reabrir_entregue: true, atendente_reabrir_cancelado: false };
      try { if (permRow?.value) perms = { ...perms, ...JSON.parse(permRow.value) }; } catch { }

      const isAdmin = user.role === 'admin';

      // Verificar permissão para reverter cancelado
      if (statusAnterior === 'cancelado' && !isAdmin && !perms.atendente_reabrir_cancelado) {
        return err('Sem permissão para reabrir pedido cancelado. Peça ao admin.', 403);
      }

      // Verificar permissão para reverter entregue
      if (statusAnterior === 'entregue' && !isAdmin && !perms.atendente_reabrir_entregue) {
        return err('Sem permissão para reverter pedido entregue. Peça ao admin.', 403);
      }

      // Reverter status
      let sql = `UPDATE orders SET status=?, updated_at=unixepoch()`;
      const params = [novoStatus];

      // Se voltando de entregue, limpar delivered_at
      if (statusAnterior === 'entregue') {
        sql += ', delivered_at=NULL';
      }
      // Se voltando de cancelado, limpar canceled_at e cancel_motivo
      if (statusAnterior === 'cancelado') {
        sql += ', canceled_at=NULL, cancel_motivo=NULL';
      }

      sql += ' WHERE id=?';
      params.push(id);
      await env.DB.prepare(sql).bind(...params).run();

      // Log de auditoria
      await logStatusChange(env, id, statusAnterior, novoStatus, motivo, user);
      await logEvent(env, id, 'status_reverted', { de: statusAnterior, para: novoStatus, motivo, usuario: user?.nome, role: user?.role });

      // Se não é admin, notificar admin via WhatsApp
      if (!isAdmin) {
        try {
          const admins = await env.DB.prepare("SELECT telefone, nome FROM app_users WHERE role='admin' AND ativo=1 AND recebe_whatsapp=1 AND telefone IS NOT NULL").all().then(r => r.results || []);
          for (const adm of admins) {
            if (adm.telefone) {
              await sendWhatsApp(env, adm.telefone, `⚠️ ${user.nome} reverteu pedido #${id}: ${statusAnterior.toUpperCase()} → ${novoStatus.toUpperCase()}\nMotivo: ${motivo}`, { category: 'admin_alerta', skipSafety: true });
            }
          }
        } catch (_) { } // não bloqueia se WhatsApp falhar
      }

      return json({
        ok: true,
        status_anterior: statusAnterior,
        status_novo: novoStatus,
        motivo
      });
    }

    const orderGetMatch = path.match(/^\/api\/order\/(\d+)$/);
    if (method === 'GET' && orderGetMatch) {
      const id = orderGetMatch[1];
      const order = await env.DB.prepare('SELECT * FROM orders WHERE id=?').bind(id).first();
      if (!order) return err('not found', 404);
      return json(order);
    }

    // ── ENTREGADORES ────────────────────────────────────────

    if (method === 'GET' && path === '/api/drivers') {
      await ensureAuthTables(env);
      const rows = await env.DB.prepare("SELECT id, nome, telefone, recebe_whatsapp FROM app_users WHERE ativo=1 AND pode_entregar=1 ORDER BY nome").all();
      const result = (rows.results || []).map(u => ({ id: u.id, name: u.nome, phone_e164: u.telefone || '', recebe_whatsapp: u.recebe_whatsapp ? 1 : 0 }));
      return json(result);
    }

    // [REMOVIDO v2.12.2] POST/PATCH /api/drivers — entregadores agora gerenciados via /api/auth/users (app_users)

    // ── PAGAMENTOS (legado) ─────────────────────────────────

    if (method === 'GET' && path === '/api/payments/list') {
      const status = url.searchParams.get('status'); const dateFrom = url.searchParams.get('date_from'); const dateTo = url.searchParams.get('date_to');
      let sql = `SELECT p.*, o.customer_name, o.phone_digits, o.address_line, o.items_json, o.total_value, o.driver_name_cache, o.created_at AS order_created_at FROM payments p JOIN orders o ON o.id = p.order_id WHERE 1=1`;
      const params = [];
      if (status) { sql += ' AND p.status = ?'; params.push(status); }
      if (dateFrom) { sql += ' AND o.created_at >= ?'; params.push(Math.floor(new Date(dateFrom + 'T00:00:00-04:00').getTime() / 1000)); }
      if (dateTo) { sql += ' AND o.created_at <= ?'; params.push(Math.floor(new Date(dateTo + 'T23:59:59-04:00').getTime() / 1000)); }
      sql += ' ORDER BY o.created_at DESC LIMIT 500';
      const rows = await env.DB.prepare(sql).bind(...params).all();
      return json(rows.results || []);
    }

    if (method === 'POST' && path === '/api/payment/set') {
      const { order_id, status, method: payMethod, notes } = await request.json();
      const received_at = status === 'recebido' ? Math.floor(Date.now() / 1000) : null;
      await env.DB.prepare(`INSERT INTO payments (order_id, status, method, notes, received_at, updated_at) VALUES (?, ?, ?, ?, ?, unixepoch()) ON CONFLICT(order_id) DO UPDATE SET status=excluded.status, method=excluded.method, notes=excluded.notes, received_at=excluded.received_at, updated_at=excluded.updated_at`).bind(order_id, status, payMethod || null, notes || null, received_at).run();
      return json({ ok: true });
    }

    // ══════════════════════════════════════════════════════════
    // GESTÃO DE PAGAMENTOS — MoskoGás v2.8.0
    // ══════════════════════════════════════════════════════════

    if (method === 'GET' && path === '/api/pagamentos') {
      await ensureAuditTable(env);
      await ensurePixColumns(env);
      const rows = await env.DB.prepare(`
        SELECT 
          o.id, o.customer_name, o.phone_digits, o.address_line, o.total_value, 
          o.tipo_pagamento, o.pago, o.bling_pedido_id, o.bling_pedido_num,
          o.created_at, o.delivered_at, o.status, o.items_json, o.bairro,
          o.forma_pagamento_key, o.forma_pagamento_id,
          o.pix_tx_id, o.pix_qrcode, o.pix_qrcode_base64, o.pix_paid_at,
          o.cora_invoice_id, o.cora_qrcode, o.cora_paid_at,
          cc.bling_contact_id,
          (SELECT COUNT(*) FROM payment_reminders pr WHERE pr.order_id = o.id) as reminder_count,
          (SELECT MAX(sent_at) FROM payment_reminders pr WHERE pr.order_id = o.id) as last_reminder_at
        FROM orders o
        LEFT JOIN customers_cache cc ON cc.phone_digits = o.phone_digits
        WHERE (o.pago = 0 OR (? = 1 AND o.pago = 1)) AND o.status = 'entregue'
        ORDER BY o.created_at DESC
        LIMIT 500
      `).bind(url.searchParams.get('incluir_pagos') === '1' ? 1 : 0).all();
      return json(rows.results || []);
    }

    if (method === 'PATCH' && /^\/api\/pagamentos\/\d+$/.test(path)) {
      const orderId = parseInt(path.split('/')[3]);
      const order = await env.DB.prepare('SELECT * FROM orders WHERE id=?').bind(orderId).first();
      if (!order) return err('Pedido não encontrado', 404);
      if (order.pago === 1) return json({ ok: true, message: 'Já estava pago' });

      // Tipos que criam Bling individualmente (ao entregar)
      // Boleto e Mensalista → Bling só em lote (criar-vendas-bling), não criar aqui
      const tiposCriarBling = ['dinheiro', 'pix_vista', 'pix_receber', 'debito', 'credito'];
      const deveCriarBling = !order.bling_pedido_id && tiposCriarBling.includes(order.tipo_pagamento);

      if (deveCriarBling) {
        try {
          const cached = await env.DB.prepare(
            'SELECT bling_contact_id, cpf_cnpj FROM customers_cache WHERE phone_digits=?'
          ).bind(order.phone_digits).first();

          const items = JSON.parse(order.items_json || '[]');
          let orderVendedorBlingId = null;
          let orderVendedorNome = order.vendedor_nome || null;
          if (order.vendedor_id) {
            const vendUser = await env.DB.prepare('SELECT bling_vendedor_id, nome FROM app_users WHERE id=?').bind(order.vendedor_id).first().catch(() => null);
            if (vendUser?.bling_vendedor_id) orderVendedorBlingId = vendUser.bling_vendedor_id;
            if (vendUser?.nome) orderVendedorNome = vendUser.nome;
          }
          const blingResult = await criarPedidoBling(env, orderId, {
            name: order.customer_name,
            items,
            total_value: order.total_value,
            forma_pagamento_key: order.forma_pagamento_key,
            forma_pagamento_id: order.forma_pagamento_id,
            bling_contact_id: cached?.bling_contact_id || null,
            cpf_cnpj: cached?.cpf_cnpj || null,
            tipo_pagamento: order.tipo_pagamento,
            bling_vendedor_id: orderVendedorBlingId,
            vendedor_nome: orderVendedorNome,
          });

          await env.DB.prepare(
            'UPDATE orders SET bling_pedido_id=?, bling_pedido_num=?, sync_status=? WHERE id=?'
          ).bind(blingResult.bling_pedido_id, blingResult.bling_pedido_num, 'synced', orderId).run();

          await logEvent(env, orderId, 'bling_created_on_pay', {
            bling_pedido_id: blingResult.bling_pedido_id,
            bling_pedido_num: blingResult.bling_pedido_num,
          });
        } catch (e) {
          await logEvent(env, orderId, 'bling_error_on_pay', { error: e.message });
          return json({ ok: false, error: 'Falha ao criar venda no Bling: ' + e.message }, 500);
        }
      }

      await env.DB.prepare('UPDATE orders SET pago=1 WHERE id=?').bind(orderId).run();
      await logBlingAudit(env, orderId, 'marcar_pago', 'success', { bling_pedido_id: order.bling_pedido_id || '', tipo: order.tipo_pagamento });
      await logEvent(env, orderId, 'payment_confirmed', {});
      return json({ ok: true });
    }

    // ── PushInPay PIX — QR Code do pedido ──────────────────
    const qrMatch = path.match(/^\/api\/pagamentos\/(\d+)\/qrcode$/);
    if (method === 'GET' && qrMatch) {
      const orderId = parseInt(qrMatch[1]);
      await ensurePixColumns(env);
      const order = await env.DB.prepare('SELECT pix_tx_id, pix_qrcode, pix_qrcode_base64, pix_paid_at, cora_invoice_id, cora_qrcode, cora_paid_at, total_value, customer_name FROM orders WHERE id=?').bind(orderId).first();
      if (!order) return err('Pedido não encontrado', 404);
      return json({
        ok: true,
        qrcode: order.pix_qrcode || order.cora_qrcode || null,
        qrcode_base64: order.pix_qrcode_base64 || null,
        paid: !!(order.pix_paid_at || order.cora_paid_at),
        total_value: order.total_value,
        customer_name: order.customer_name,
        provider: order.pix_tx_id ? 'pushinpay' : (order.cora_invoice_id ? 'cora_legacy' : null),
      });
    }

    // ── PushInPay PIX — (Re)gerar cobrança PIX ─────────────
    const gerarPixMatch = path.match(/^\/api\/pagamentos\/(\d+)\/gerar-pix$/);
    if (method === 'POST' && gerarPixMatch) {
      const orderId = parseInt(gerarPixMatch[1]);
      if (!isPixConfigured(env)) return err('PushInPay PIX não configurada (PUSHINPAY_TOKEN ausente)', 400);

      await ensurePixColumns(env);
      const order = await env.DB.prepare('SELECT * FROM orders WHERE id=?').bind(orderId).first();
      if (!order) return err('Pedido não encontrado', 404);
      if (order.pago === 1) return json({ ok: true, message: 'Pedido já está pago' });
      if (order.pix_paid_at) return json({ ok: true, message: 'PIX já confirmado' });

      // Se já tem pix_tx_id + qrcode, retornar o existente (NÃO gerar novo!)
      const forceNew = (await request.json().catch(() => ({}))).force_new === true;
      if (order.pix_tx_id && order.pix_qrcode && !forceNew) {
        console.log(`[PushInPay] Reusando QR existente pedido #${orderId} tx=${order.pix_tx_id}`);
        return json({ ok: true, tx_id: order.pix_tx_id, qrcode: order.pix_qrcode, qrcode_base64: order.pix_qrcode_base64 || null, pix_disponivel: true, reused: true });
      }

      try {
        const pixData = await pushInPayCreateCharge(env, orderId, order.total_value);
        if (pixData.tx_id) {
          await env.DB.prepare('UPDATE orders SET pix_tx_id=?, pix_qrcode=?, pix_qrcode_base64=? WHERE id=?')
            .bind(pixData.tx_id, pixData.qr_code || '', pixData.qr_code_base64 || '', orderId).run();
        }
        return json({ ok: true, tx_id: pixData.tx_id, qrcode: pixData.qr_code || null, qrcode_base64: pixData.qr_code_base64 || null, pix_disponivel: !!pixData.qr_code });
      } catch (e) {
        return json({ ok: false, error: e.message }, 500);
      }
    }

    if (method === 'POST' && path === '/api/pagamentos/criar-vendas-bling') {
      const body = await request.json();
      const orderIds = body.order_ids || [];
      if (orderIds.length === 0) return err('Nenhum pedido selecionado');

      const placeholders = orderIds.map(() => '?').join(',');
      const orders = await env.DB.prepare(
        `SELECT o.*, cc.bling_contact_id, cc.cpf_cnpj 
         FROM orders o
         LEFT JOIN customers_cache cc ON cc.phone_digits = o.phone_digits
         WHERE o.id IN (${placeholders})`
      ).bind(...orderIds).all().then(r => r.results || []);

      if (orders.length === 0) return err('Nenhum pedido encontrado');

      const invalidos = orders.filter(o => !['mensalista', 'boleto'].includes(o.tipo_pagamento));
      if (invalidos.length > 0) {
        return err(`Pedidos ${invalidos.map(o => '#' + o.id).join(', ')} não são mensalista/boleto`);
      }

      const grupos = {};
      for (const o of orders) {
        const key = o.phone_digits || o.customer_name || 'sem_id_' + o.id;
        if (!grupos[key]) {
          // Se não achou bling_contact_id via phone (phone nulo), buscar por nome
          let blingContactId = o.bling_contact_id || null;
          if (!blingContactId && !o.phone_digits && o.customer_name) {
            const byName = await env.DB.prepare(
              `SELECT bling_contact_id FROM customers_cache WHERE LOWER(name) = LOWER(?) AND bling_contact_id IS NOT NULL LIMIT 1`
            ).bind(o.customer_name).first().catch(() => null);
            blingContactId = byName?.bling_contact_id || null;
          }
          grupos[key] = { cliente: o.customer_name, phone: o.phone_digits, bling_contact_id: blingContactId, cpf_cnpj: o.cpf_cnpj || null, pedidos: [], produtos: {}, total: 0 };
        }
        grupos[key].pedidos.push(o);
        grupos[key].total += parseFloat(o.total_value) || 0;
        try {
          const items = JSON.parse(o.items_json || '[]');
          for (const item of items) {
            const prodKey = item.bling_id || item.code || item.name;
            if (!grupos[key].produtos[prodKey]) {
              grupos[key].produtos[prodKey] = { name: item.name, bling_id: item.bling_id || null, code: item.code || item.sku || '', sku: item.code || item.sku || '', qty: 0, price: parseFloat(item.price) || 0 };
            }
            grupos[key].produtos[prodKey].qty += parseInt(item.qty) || 1;
          }
        } catch (_) { }
      }

      const resultados = [];
      const today = new Date().toISOString().slice(0, 10);

      for (const [key, grupo] of Object.entries(grupos)) {
        const produtos = Object.values(grupo.produtos);
        const pedidoIds = grupo.pedidos.map(p => p.id);

        const itensBling = produtos.map(p => buildItemBling(p));

        // v2.30.0: Total DEVE ser calculado dos itens (mesmo cálculo que o Bling faz)
        // Se usar grupo.total (soma dos pedidos), pode divergir por arredondamento
        const totalItens = Math.round(itensBling.reduce((s, i) => s + i.quantidade * i.valor, 0) * 100) / 100;

        // v2.28.7: Para boleto/mensalista, usar contato real se bling_contact_id existe
        // (não exigir cpf_cnpj como na NFCe — esses clientes já estão cadastrados no Bling)
        const usarContatoReal = !!grupo.bling_contact_id;

        const pedidoBody = {
          contato: usarContatoReal ? { id: grupo.bling_contact_id } : { id: CONSUMIDOR_FINAL_ID, tipoPessoa: 'F' },
          data: today,
          dataSaida: today,
          itens: itensBling,
          parcelas: [{ formaPagamento: { id: FORMAS_PAGAMENTO.fiado.id }, valor: totalItens, dataVencimento: today }],
          observacoes: `MoskoGás Venda Agrupada — ${grupo.cliente} — Pedidos: ${pedidoIds.map(i => '#' + i).join(', ')}`,
        };

        try {
          const resp = await blingFetch('/pedidos/vendas', { method: 'POST', body: JSON.stringify(pedidoBody) }, env);

          if (!resp.ok) {
            const errText = await resp.text();
            for (const oid of pedidoIds) {
              await logBlingAudit(env, oid, 'criar_venda_lote', 'error', { request_payload: pedidoBody, error_message: `HTTP ${resp.status}: ${errText.substring(0, 500)}` });
            }
            resultados.push({ cliente: grupo.cliente, ok: false, error: `Bling ${resp.status}: ${errText.substring(0, 500)}`, pedidos: pedidoIds });
            continue;
          }

          const pedidoData = await resp.json();
          const blingId = pedidoData.data?.id ?? null;
          const blingNum = pedidoData.data?.numero ?? null;

          for (const orderId of pedidoIds) {
            await env.DB.prepare('UPDATE orders SET bling_pedido_id=?, bling_pedido_num=?, pago=1, sync_status=? WHERE id=?').bind(blingId, blingNum, 'synced_nfe', orderId).run();
            await logEvent(env, orderId, 'venda_agrupada', { bling_pedido_id: blingId, bling_pedido_num: blingNum, grupo_pedidos: pedidoIds });
            await logBlingAudit(env, orderId, 'criar_venda_lote', 'success', { bling_pedido_id: String(blingId || ''), request_payload: pedidoBody, response_data: pedidoData });
          }

          resultados.push({ cliente: grupo.cliente, ok: true, bling_pedido_id: blingId, bling_pedido_num: blingNum, pedidos: pedidoIds, total: grupo.total, itens_count: itensBling.length });
        } catch (e) {
          for (const oid of pedidoIds) {
            await logBlingAudit(env, oid, 'criar_venda_lote', 'error', { request_payload: pedidoBody, error_message: e.message });
          }
          resultados.push({ cliente: grupo.cliente, ok: false, error: e.message, pedidos: pedidoIds });
        }
      }

      const sucessos = resultados.filter(r => r.ok).length;
      const falhas = resultados.filter(r => !r.ok).length;
      return json({
        ok: falhas === 0,
        message: `${sucessos} venda(s) criada(s) no Bling${falhas > 0 ? `, ${falhas} falha(s)` : ''}`,
        resultados,
      });
    }

    // ══════════════════════════════════════════════════════════
    // WHATSAPP SAFETY — Config + Stats (admin)
    // ══════════════════════════════════════════════════════════

    if (method === 'GET' && path === '/api/whatsapp/safety-config') {
      const authCheck = await requireAuth(request, env, ['admin']);
      if (authCheck instanceof Response) return authCheck;
      const config = await getWhatsAppSafetyConfig(env);
      return json(config);
    }

    if (method === 'POST' && path === '/api/whatsapp/safety-config') {
      const authCheck = await requireAuth(request, env, ['admin']);
      if (authCheck instanceof Response) return authCheck;
      await ensureWhatsAppTables(env);
      const body = await request.json();
      // v2.32.9: reset do circuit breaker — limpa o bloqueio imediatamente
      if (body.circuit_breaker_reset) {
        await env.DB.prepare("DELETE FROM app_config WHERE key='whatsapp_last_block'").run().catch(() => { });
        return json({ ok: true, message: 'Circuit breaker resetado' });
      }
      const current = await getWhatsAppSafetyConfig(env);
      const updated = { ...current, ...body };
      await env.DB.prepare(
        "INSERT OR REPLACE INTO app_config (key, value, updated_at) VALUES ('whatsapp_safety', ?, datetime('now'))"
      ).bind(JSON.stringify(updated)).run();
      return json({ ok: true, config: updated });
    }

    if (method === 'GET' && path === '/api/whatsapp/stats') {
      const authCheck = await requireAuth(request, env, ['admin']);
      if (authCheck instanceof Response) return authCheck;
      await ensureWhatsAppTables(env);
      const now = Math.floor(Date.now() / 1000);
      const stats = {};
      // Hoje
      const brtMidnight = new Date();
      brtMidnight.setUTCHours(4, 0, 0, 0);
      if (brtMidnight > new Date()) brtMidnight.setUTCDate(brtMidnight.getUTCDate() - 1);
      const midnightEpoch = Math.floor(brtMidnight.getTime() / 1000);

      stats.hoje = await env.DB.prepare('SELECT COUNT(*) as total, SUM(wa_ok) as ok, SUM(blocked) as bloqueios FROM whatsapp_send_log WHERE created_at > ?').bind(midnightEpoch).first();
      stats.ultima_hora = await env.DB.prepare('SELECT COUNT(*) as total, SUM(wa_ok) as ok FROM whatsapp_send_log WHERE created_at > ?').bind(now - 3600).first();
      stats.por_categoria = await env.DB.prepare('SELECT category, COUNT(*) as total, SUM(wa_ok) as ok FROM whatsapp_send_log WHERE created_at > ? GROUP BY category').bind(midnightEpoch).all().then(r => r.results || []);
      stats.ultimo_bloqueio = await env.DB.prepare("SELECT value FROM app_config WHERE key='whatsapp_last_block'").first().then(r => r?.value ? JSON.parse(r.value) : null).catch(() => null);
      stats.circuit_breaker = await isCircuitBroken(env, await getWhatsAppSafetyConfig(env));
      return json(stats);
    }

    // ══════════════════════════════════════════════════════════
    // LEMBRETES PIX — MoskoGás v2.26.0
    // ══════════════════════════════════════════════════════════

    // GET /api/lembretes/config — retorna config atual
    if (method === 'GET' && path === '/api/lembretes/config') {
      const authCheck = await requireAuth(request, env, ['admin']);
      if (authCheck instanceof Response) return authCheck;
      const config = await getLembreteConfig(env);
      return json(config);
    }

    // POST /api/lembretes/config — salvar config (admin)
    if (method === 'POST' && path === '/api/lembretes/config') {
      const authCheck = await requireAuth(request, env, ['admin']);
      if (authCheck instanceof Response) return authCheck;
      await ensureAuditTable(env);
      const body = await request.json();
      const current = await getLembreteConfig(env);
      const updated = { ...current, ...body };
      await env.DB.prepare(
        "INSERT OR REPLACE INTO app_config (key, value, updated_at) VALUES ('lembrete_pix', ?, datetime('now'))"
      ).bind(JSON.stringify(updated)).run();
      return json({ ok: true, config: updated });
    }

    // POST /api/lembretes/enviar/:orderId — enviar lembrete individual
    const lembreteMatch = path.match(/^\/api\/lembretes\/enviar\/(\d+)$/);
    if (method === 'POST' && lembreteMatch) {
      const authCheck = await requireAuth(request, env, ['admin', 'atendente']);
      if (authCheck instanceof Response) return authCheck;
      const user = await getSessionUser(request, env);
      const orderId = parseInt(lembreteMatch[1]);
      let body = {}; try { body = await request.json(); } catch (_) { }
      const force = body.force === true;
      const order = await env.DB.prepare(
        "SELECT * FROM orders WHERE id=? AND tipo_pagamento='pix_receber' AND pago=0 AND status='entregue'"
      ).bind(orderId).first();
      if (!order) return err('Pedido não encontrado ou não é PIX pendente', 404);
      const config = await getLembreteConfig(env);
      if (!config.ativo) return err('Lembretes PIX estão desativados', 400);
      const result = await enviarLembretePix(env, order, config, user, force);
      return json(result, 200);
    }

    // POST /api/lembretes/enviar-bulk — enviar lembretes em lote
    if (method === 'POST' && path === '/api/lembretes/enviar-bulk') {
      const authCheck = await requireAuth(request, env, ['admin', 'atendente']);
      if (authCheck instanceof Response) return authCheck;
      const user = await getSessionUser(request, env);
      const { order_ids } = await request.json();
      if (!order_ids?.length) return err('Nenhum pedido selecionado');
      const config = await getLembreteConfig(env);
      if (!config.ativo) return err('Lembretes PIX estão desativados', 400);

      const placeholders = order_ids.map(() => '?').join(',');
      const orders = await env.DB.prepare(
        `SELECT * FROM orders WHERE id IN (${placeholders}) AND tipo_pagamento='pix_receber' AND pago=0 AND status='entregue'`
      ).bind(...order_ids).all().then(r => r.results || []);

      const resultados = [];
      let bloqueado = false;
      const delayMs = (config.delay_segundos || 60) * 1000;
      for (const order of orders) {
        if (bloqueado) {
          resultados.push({ ok: false, order_id: order.id, error: 'Envio interrompido — bloqueio detectado' });
          continue;
        }
        const result = await enviarLembretePix(env, order, config, user);
        resultados.push(result);
        if (result.blocked || result.wa_status === 429) {
          bloqueado = true;
        } else if (result.ok && orders.indexOf(order) < orders.length - 1) {
          await new Promise(r => setTimeout(r, delayMs));
        }
      }

      const enviados = resultados.filter(r => r.ok).length;
      const falhas = resultados.filter(r => !r.ok).length;
      return json({
        ok: falhas === 0,
        message: `${enviados} lembrete(s) enviado(s)${falhas ? `, ${falhas} falha(s)` : ''}`,
        resultados,
      });
    }

    // GET /api/lembretes/pedido/:orderId — histórico de lembretes
    const lembreteHistMatch = path.match(/^\/api\/lembretes\/pedido\/(\d+)$/);
    if (method === 'GET' && lembreteHistMatch) {
      const authCheck = await requireAuth(request, env, ['admin', 'atendente']);
      if (authCheck instanceof Response) return authCheck;
      await ensureAuditTable(env);
      const orderId = parseInt(lembreteHistMatch[1]);
      const rows = await env.DB.prepare(
        'SELECT * FROM payment_reminders WHERE order_id=? ORDER BY sent_at DESC'
      ).bind(orderId).all().then(r => r.results || []);
      return json(rows);
    }

    // GET /api/lembretes/pendentes — pedidos PIX pendentes c/ info lembretes
    if (method === 'GET' && path === '/api/lembretes/pendentes') {
      const authCheck = await requireAuth(request, env, ['admin', 'atendente']);
      if (authCheck instanceof Response) return authCheck;
      await ensureAuditTable(env);
      const rows = await env.DB.prepare(`
        SELECT o.id, o.customer_name, o.phone_digits, o.total_value, o.items_json,
               o.created_at, o.delivered_at, o.bairro, o.address_line,
               (SELECT COUNT(*) FROM payment_reminders pr WHERE pr.order_id = o.id) as reminder_count,
               (SELECT MAX(sent_at) FROM payment_reminders pr WHERE pr.order_id = o.id) as last_reminder_at
        FROM orders o
        WHERE o.tipo_pagamento = 'pix_receber' AND o.pago = 0 AND o.status = 'entregue'
        ORDER BY o.created_at DESC
        LIMIT 200
      `).all().then(r => r.results || []);
      return json(rows);
    }

    // ── CONSULTA DE PEDIDOS (admin/atendente) ─────────────────────
    if (method === 'GET' && path === '/api/consulta/pedidos') {
      const authCheck = await requireAuth(request, env, ['admin', 'atendente']);
      if (authCheck instanceof Response) return authCheck;

      // Índices (idempotente)
      await env.DB.exec(`
        CREATE INDEX IF NOT EXISTS idx_orders_created ON orders(created_at);
        CREATE INDEX IF NOT EXISTS idx_orders_status ON orders(status);
        CREATE INDEX IF NOT EXISTS idx_orders_customer ON orders(customer_name);
        CREATE INDEX IF NOT EXISTS idx_orders_phone ON orders(phone_digits);
        CREATE INDEX IF NOT EXISTS idx_orders_driver ON orders(driver_name_cache);
        CREATE INDEX IF NOT EXISTS idx_orders_pagamento ON orders(tipo_pagamento);
        CREATE INDEX IF NOT EXISTS idx_orders_pago ON orders(pago);
        CREATE INDEX IF NOT EXISTS idx_orders_bling ON orders(bling_pedido_id);
        CREATE INDEX IF NOT EXISTS idx_orders_vendedor ON orders(vendedor_nome);
        CREATE INDEX IF NOT EXISTS idx_orders_bairro ON orders(bairro);
      `);

      const page = Math.max(1, parseInt(url.searchParams.get('page')) || 1);
      const limit = Math.min(50, Math.max(1, parseInt(url.searchParams.get('limit')) || 30));

      // Datas
      const hoje = new Date().toISOString().slice(0, 10);
      const seteAtras = new Date(Date.now() - 7 * 86400000).toISOString().slice(0, 10);
      let data_de = url.searchParams.get('data_de') || seteAtras;
      let data_ate = url.searchParams.get('data_ate') || hoje;

      // Limite 90 dias
      const diffDias = (new Date(data_ate) - new Date(data_de)) / 86400000;
      if (diffDias > 90) return err('Período máximo: 90 dias. Reduza o intervalo de datas.');

      const conditions = ['1=1'];
      const params = [];

      // created_at é INTEGER (unixepoch) — converter datas para epoch com offset BRT (-04:00)
      const epochDe = Math.floor(new Date(data_de + 'T00:00:00-04:00').getTime() / 1000);
      const epochAte = Math.floor(new Date(data_ate + 'T23:59:59-04:00').getTime() / 1000);
      conditions.push('created_at >= ?'); params.push(epochDe);
      conditions.push('created_at <= ?'); params.push(epochAte);

      // Filtros
      const pedido_id = url.searchParams.get('pedido_id');
      const cliente = url.searchParams.get('cliente');
      const telefone = url.searchParams.get('telefone');
      const produto = url.searchParams.get('produto');
      const entregador = url.searchParams.get('entregador');
      const vendedor = url.searchParams.get('vendedor');
      const status_f = url.searchParams.get('status');
      const tipo_pagamento = url.searchParams.get('tipo_pagamento');
      const rua = url.searchParams.get('rua');
      const bairro = url.searchParams.get('bairro');
      const pago = url.searchParams.get('pago');
      const tem_foto = url.searchParams.get('tem_foto');
      const tem_bling = url.searchParams.get('tem_bling');
      const consumidor_final = url.searchParams.get('consumidor_final');

      if (pedido_id) { conditions.push('id = ?'); params.push(parseInt(pedido_id)); }
      if (cliente) {
        const clienteWords = cliente.trim().split(/\s+/).filter(Boolean);
        for (const w of clienteWords) { conditions.push("customer_name LIKE ?"); params.push(`%${w}%`); }
      }
      if (telefone) { conditions.push("phone_digits LIKE ?"); params.push(`%${telefone}%`); }
      if (produto) { conditions.push("items_json LIKE ?"); params.push(`%${produto}%`); }
      if (entregador) { conditions.push("driver_name_cache = ?"); params.push(entregador); }
      if (vendedor) { conditions.push("vendedor_nome = ?"); params.push(vendedor); }
      if (status_f) { conditions.push("status = ?"); params.push(status_f); }
      if (tipo_pagamento) { conditions.push("tipo_pagamento = ?"); params.push(tipo_pagamento); }
      if (rua) { conditions.push("address_line LIKE ?"); params.push(`%${rua}%`); }
      if (bairro) { conditions.push("bairro = ?"); params.push(bairro); }
      if (pago === 'sim') conditions.push("pago = 1");
      if (pago === 'nao') conditions.push("pago = 0");
      if (tem_foto === 'sim') conditions.push("foto_comprovante IS NOT NULL AND foto_comprovante != ''");
      if (tem_foto === 'nao') conditions.push("(foto_comprovante IS NULL OR foto_comprovante = '')");
      if (tem_bling === 'sim') conditions.push("bling_pedido_id IS NOT NULL AND bling_pedido_id != ''");
      if (tem_bling === 'nao') conditions.push("(bling_pedido_id IS NULL OR bling_pedido_id = '')");
      if (consumidor_final === 'sim') conditions.push("customer_name = 'CONSUMIDOR FINAL'");

      const where = conditions.join(' AND ');

      // Ordenação
      const allowedOrder = ['created_at', 'total_value', 'customer_name', 'id', 'status'];
      let orderBy = url.searchParams.get('order_by') || 'created_at';
      if (!allowedOrder.includes(orderBy)) orderBy = 'created_at';
      let orderDir = (url.searchParams.get('order_dir') || 'DESC').toUpperCase();
      if (orderDir !== 'ASC' && orderDir !== 'DESC') orderDir = 'DESC';

      // Resumo
      const resumoSQL = `SELECT COUNT(*) as total_pedidos, COALESCE(SUM(total_value),0) as total_valor,
        SUM(CASE WHEN foto_comprovante IS NOT NULL AND foto_comprovante != '' THEN 1 ELSE 0 END) as com_foto,
        SUM(CASE WHEN foto_comprovante IS NULL OR foto_comprovante = '' THEN 1 ELSE 0 END) as sem_foto,
        SUM(CASE WHEN bling_pedido_id IS NOT NULL AND bling_pedido_id != '' THEN 1 ELSE 0 END) as com_bling,
        SUM(CASE WHEN bling_pedido_id IS NULL OR bling_pedido_id = '' THEN 1 ELSE 0 END) as sem_bling,
        SUM(CASE WHEN pago = 1 THEN 1 ELSE 0 END) as pagos,
        SUM(CASE WHEN pago = 0 THEN 1 ELSE 0 END) as nao_pagos
        FROM orders WHERE ${where}`;

      const resumo = await env.DB.prepare(resumoSQL).bind(...params).first();

      const total = resumo?.total_pedidos || 0;
      const pages = Math.ceil(total / limit);
      const offset = (page - 1) * limit;

      // Dados paginados
      const dadosSQL = `SELECT * FROM orders WHERE ${where} ORDER BY ${orderBy} ${orderDir} LIMIT ? OFFSET ?`;
      const pedidos = await env.DB.prepare(dadosSQL).bind(...params, limit, offset).all();

      // Listas para dropdowns
      const entregadores = await env.DB.prepare("SELECT DISTINCT driver_name_cache as nome FROM orders WHERE driver_name_cache IS NOT NULL AND driver_name_cache != '' ORDER BY driver_name_cache").all();
      const vendedores = await env.DB.prepare("SELECT DISTINCT vendedor_nome as nome FROM orders WHERE vendedor_nome IS NOT NULL AND vendedor_nome != '' ORDER BY vendedor_nome").all();
      const bairros = await env.DB.prepare("SELECT DISTINCT bairro as nome FROM orders WHERE bairro IS NOT NULL AND bairro != '' ORDER BY bairro").all();

      return json({
        ok: true,
        pedidos: pedidos.results || [],
        resumo: {
          total_pedidos: total,
          total_valor: resumo?.total_valor || 0,
          com_foto: resumo?.com_foto || 0,
          sem_foto: resumo?.sem_foto || 0,
          com_bling: resumo?.com_bling || 0,
          sem_bling: resumo?.sem_bling || 0,
          pagos: resumo?.pagos || 0,
          nao_pagos: resumo?.nao_pagos || 0,
        },
        paginacao: { page, limit, total, pages },
        dropdowns: {
          entregadores: (entregadores.results || []).map(r => r.nome),
          vendedores: (vendedores.results || []).map(r => r.nome),
          bairros: (bairros.results || []).map(r => r.nome),
        }
      });
    }

    // Dropdowns auxiliares para consulta
    if (method === 'GET' && path === '/api/consulta/opcoes') {
      const authCheck = await requireAuth(request, env, ['admin', 'atendente']);
      if (authCheck instanceof Response) return authCheck;

      const vendedores = await env.DB.prepare("SELECT DISTINCT vendedor_nome FROM orders WHERE vendedor_nome IS NOT NULL AND vendedor_nome != '' ORDER BY vendedor_nome").all();
      const bairros = await env.DB.prepare("SELECT DISTINCT bairro FROM orders WHERE bairro IS NOT NULL AND bairro != '' ORDER BY bairro").all();
      const entregadores = await env.DB.prepare("SELECT DISTINCT driver_name_cache FROM orders WHERE driver_name_cache IS NOT NULL AND driver_name_cache != '' ORDER BY driver_name_cache").all();

      return json({
        vendedores: (vendedores.results || []).map(r => r.vendedor_nome),
        bairros: (bairros.results || []).map(r => r.bairro),
        entregadores: (entregadores.results || []).map(r => r.driver_name_cache),
      });
    }

    // ── DASHBOARD ───────────────────────────────────────────

    if (method === 'GET' && path === '/api/dashboard') {
      const authCheck = await requireAuth(request, env, ['admin', 'atendente']);
      if (authCheck instanceof Response) return authCheck;

      const date = url.searchParams.get('date') || new Date().toISOString().slice(0, 10);
      // created_at is stored as INTEGER (unixepoch) — use epoch comparison like /api/orders/list
      const dayStartEpoch = Math.floor(new Date(date + 'T00:00:00-04:00').getTime() / 1000);
      const dayEndEpoch = dayStartEpoch + 86400;

      const orders = await env.DB.prepare(
        `SELECT id, customer_name, phone_digits, total_value, tipo_pagamento, pago,
                bling_pedido_id, bling_pedido_num, vendedor_nome, items_json,
                status, driver_name_cache, created_at
         FROM orders WHERE created_at >= ? AND created_at < ? AND status != 'cancelado' ORDER BY id DESC`
      ).bind(dayStartEpoch, dayEndEpoch).all().then(r => r.results || []);

      // Também pegar cancelados separados (para KPI)
      const cancelados = await env.DB.prepare(
        `SELECT COUNT(*) as cnt FROM orders WHERE created_at >= ? AND created_at < ? AND status = 'cancelado'`
      ).bind(dayStartEpoch, dayEndEpoch).first().then(r => r?.cnt || 0);

      const totalPedidos = orders.length;
      const totalValor = orders.reduce((s, o) => s + (o.total_value || 0), 0);
      const comBling = orders.filter(o => o.bling_pedido_id).length;
      const pagos = orders.filter(o => o.pago === 1).length;
      const naoPagos = totalPedidos - pagos;

      // Status breakdown
      const porStatus = {};
      for (const o of orders) {
        const s = o.status || 'novo';
        porStatus[s] = (porStatus[s] || 0) + 1;
      }

      // Por tipo pagamento
      const porTipo = {};
      for (const o of orders) {
        const t = o.tipo_pagamento || 'indefinido';
        if (!porTipo[t]) porTipo[t] = { qtd: 0, valor: 0 };
        porTipo[t].qtd++;
        porTipo[t].valor += o.total_value || 0;
      }

      // Por vendedor
      const porVendedor = {};
      for (const o of orders) {
        const v = o.vendedor_nome || 'Sem vendedor';
        if (!porVendedor[v]) porVendedor[v] = { qtd: 0, valor: 0 };
        porVendedor[v].qtd++;
        porVendedor[v].valor += o.total_value || 0;
      }

      // Por entregador
      const porEntregador = {};
      for (const o of orders) {
        if (o.status === 'cancelado') continue;
        const d = o.driver_name_cache || 'Sem entregador';
        if (!porEntregador[d]) porEntregador[d] = { qtd: 0, valor: 0, entregues: 0 };
        porEntregador[d].qtd++;
        porEntregador[d].valor += o.total_value || 0;
        if (o.status === 'entregue') porEntregador[d].entregues++;
      }

      // Por produto
      const porProduto = {};
      for (const o of orders) {
        try {
          const items = JSON.parse(o.items_json || '[]');
          for (const it of items) {
            const k = it.name || 'Desconhecido';
            if (!porProduto[k]) porProduto[k] = { qtd: 0, valor: 0 };
            porProduto[k].qtd += parseInt(it.qty) || 1;
            porProduto[k].valor += (parseFloat(it.price) || 0) * (parseInt(it.qty) || 1);
          }
        } catch (_) { }
      }

      // Ticket médio
      const ticketMedio = totalPedidos > 0 ? Math.round((totalValor / totalPedidos) * 100) / 100 : 0;

      // Pedidos por hora (histograma) — created_at is epoch, convert to BRT (UTC-4)
      const porHora = {};
      for (const o of orders) {
        const epoch = typeof o.created_at === 'number' ? o.created_at : parseInt(o.created_at) || 0;
        const dt = new Date(epoch * 1000);
        const brtHour = (dt.getUTCHours() - 4 + 24) % 24;
        const h = String(brtHour).padStart(2, '0');
        porHora[h] = (porHora[h] || 0) + 1;
      }

      return json({
        date,
        resumo: {
          totalPedidos, cancelados,
          totalValor: Math.round(totalValor * 100) / 100,
          comBling, pagos, naoPagos, ticketMedio
        },
        porStatus, porTipo, porVendedor, porEntregador, porProduto, porHora,
        pedidos: orders.slice(0, 30).map(o => ({
          id: o.id, cliente: o.customer_name, telefone: o.phone_digits,
          valor: o.total_value, tipo: o.tipo_pagamento, pago: o.pago,
          bling_num: o.bling_pedido_num, vendedor: o.vendedor_nome,
          entregador: o.driver_name_cache, items_json: o.items_json,
          status: o.status, created_at: o.created_at
        }))
      });
    }

    // ══════════════════════════════════════════════════════════
    // RELATÓRIO DIÁRIO POR E-MAIL (v2.29.0)
    // ══════════════════════════════════════════════════════════

    if (method === 'GET' && path === '/api/relatorio/email-config') {
      const authCheck = await requireAuth(request, env, ['admin']);
      if (authCheck instanceof Response) return authCheck;
      const config = await getReportConfig(env);
      return json(config);
    }

    if (method === 'POST' && path === '/api/relatorio/email-config') {
      const authCheck = await requireAuth(request, env, ['admin']);
      if (authCheck instanceof Response) return authCheck;
      const body = await request.json();
      // Salvar resend_api_key separadamente no app_config (fallback quando secret não funciona)
      if (body.resend_api_key) {
        await env.DB.prepare("INSERT OR REPLACE INTO app_config (key, value, updated_at) VALUES ('resend_api_key', ?, datetime('now'))").bind(body.resend_api_key).run();
        delete body.resend_api_key;
      }
      const current = await getReportConfig(env);
      const updated = { ...current, ...body };
      await env.DB.prepare("INSERT OR REPLACE INTO app_config (key, value, updated_at) VALUES ('relatorio_email', ?, datetime('now'))").bind(JSON.stringify(updated)).run();
      return json({ ok: true, config: updated });
    }

    if (method === 'POST' && path === '/api/relatorio/enviar-email') {
      const authCheck = await requireAuth(request, env, ['admin']);
      if (authCheck instanceof Response) return authCheck;
      const body = await request.json().catch(() => ({}));
      const dateStr = body.date || new Date(Date.now() - 86400000).toISOString().slice(0, 10);
      const resendKey = await getResendKey(env, body.resend_key);
      if (!resendKey) return json({ ok: false, error: 'RESEND_API_KEY não encontrada. Configure via: POST /api/relatorio/email-config { "resend_api_key": "re_xxx" }' }, 400);
      const report = await generateDailyReport(env, dateStr);
      if (report.total === 0) return json({ ok: true, message: `Sem pedidos em ${dateStr}`, total: 0 });
      const html = buildReportHTML(report);
      const csv = buildReportCSV(report);
      const config = await getReportConfig(env);
      const destinos = body.email ? [body.email] : config.destinos;
      const fmtBRL = v => 'R$ ' + v.toFixed(2).replace('.', ',');
      const emailPayload = {
        from: 'MoskoGás <relatorio@moskogas.com.br>',
        to: destinos,
        subject: `Pedidos do dia — ${dateStr} — ${report.total} pedidos — ${fmtBRL(report.totalValor)}`,
        html,
        attachments: [{ filename: `pedidos_${dateStr}.csv`, content: btoa(unescape(encodeURIComponent(csv))) }],
      };
      const resp = await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: { Authorization: `Bearer ${resendKey}`, 'Content-Type': 'application/json' },
        body: JSON.stringify(emailPayload),
      });
      if (!resp.ok) {
        const errText = await resp.text().catch(() => '');
        return json({ ok: false, error: `Resend ${resp.status}: ${errText.substring(0, 300)}` });
      }
      const result = await resp.json();
      return json({ ok: true, email_id: result.id, total: report.total, valor: report.totalValor, destinos, date: dateStr });
    }

    if (method === 'GET' && path === '/api/relatorio/preview-email') {
      // Aceita auth por sessão OU API key via query (para abrir direto no browser)
      const apiKeyParam = url.searchParams.get('key');
      if (apiKeyParam && apiKeyParam === env.APP_API_KEY) { /* ok */ }
      else { const authCheck = await requireAuth(request, env, ['admin']); if (authCheck instanceof Response) return authCheck; }
      const dateStr = url.searchParams.get('date') || new Date(Date.now() - 86400000).toISOString().slice(0, 10);
      const report = await generateDailyReport(env, dateStr);
      if (report.total === 0) return new Response(`<h2>Sem pedidos em ${dateStr}</h2>`, { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
      const html = buildReportHTML(report);
      return new Response(html, { headers: { 'Content-Type': 'text/html; charset=utf-8', ...CORS_HEADERS } });
    }

    if (method === 'GET' && path === '/api/relatorio/download-csv') {
      const apiKeyParam = url.searchParams.get('key');
      if (apiKeyParam && apiKeyParam === env.APP_API_KEY) { /* ok */ }
      else { const authCheck = await requireAuth(request, env, ['admin', 'atendente']); if (authCheck instanceof Response) return authCheck; }
      const dateStr = url.searchParams.get('date') || new Date(Date.now() - 86400000).toISOString().slice(0, 10);
      const report = await generateDailyReport(env, dateStr);
      if (report.total === 0) return json({ error: `Sem pedidos em ${dateStr}` }, 404);
      const csv = buildReportCSV(report);
      return new Response(csv, {
        headers: {
          'Content-Type': 'text/csv; charset=utf-8',
          'Content-Disposition': `attachment; filename="pedidos_${dateStr}.csv"`,
          ...CORS_HEADERS,
        }
      });
    }

    // ── AUDITORIA ─────────────────────────────────────────────

    if (method === 'GET' && path === '/api/auditoria/diaria') {
      const authCheck = await requireAuth(request, env, ['admin', 'atendente']);
      if (authCheck instanceof Response) return authCheck;
      await ensureAuditTable(env);

      const date = url.searchParams.get('date') || new Date().toISOString().slice(0, 10);
      const epochStart = Math.floor(new Date(date + 'T00:00:00-04:00').getTime() / 1000);
      const epochEnd = Math.floor(new Date(date + 'T23:59:59-04:00').getTime() / 1000);

      // Pedidos do dia
      const orders = await env.DB.prepare(
        `SELECT id, customer_name, total_value, tipo_pagamento, pago, bling_pedido_id, bling_pedido_num, vendedor_nome, items_json, status, created_at
         FROM orders WHERE created_at >= ? AND created_at <= ? ORDER BY id`
      ).bind(epochStart, epochEnd).all().then(r => r.results || []);

      const totalPedidos = orders.length;
      const totalValor = orders.reduce((s, o) => s + (o.total_value || 0), 0);
      const comBling = orders.filter(o => o.bling_pedido_id).length;
      const semBling = totalPedidos - comBling;
      const pagos = orders.filter(o => o.pago === 1).length;
      const naoPagos = totalPedidos - pagos;

      // Por tipo pagamento
      const porTipo = {};
      for (const o of orders) {
        const t = o.tipo_pagamento || 'indefinido';
        if (!porTipo[t]) porTipo[t] = { qtd: 0, valor: 0 };
        porTipo[t].qtd++;
        porTipo[t].valor += o.total_value || 0;
      }

      // Por vendedor
      const porVendedor = {};
      for (const o of orders) {
        const v = o.vendedor_nome || 'Sem vendedor';
        if (!porVendedor[v]) porVendedor[v] = { qtd: 0, valor: 0 };
        porVendedor[v].qtd++;
        porVendedor[v].valor += o.total_value || 0;
      }

      // Por produto
      const porProduto = {};
      for (const o of orders) {
        try {
          const items = JSON.parse(o.items_json || '[]');
          for (const it of items) {
            const k = it.name || 'Desconhecido';
            if (!porProduto[k]) porProduto[k] = { qtd: 0, valor: 0 };
            porProduto[k].qtd += parseInt(it.qty) || 1;
            porProduto[k].valor += (parseFloat(it.price) || 0) * (parseInt(it.qty) || 1);
          }
        } catch (_) { }
      }

      // Erros de integração do dia (com dados do pedido)
      const erros = await env.DB.prepare(
        `SELECT ia.*, o.customer_name, o.total_value, o.tipo_pagamento AS order_tipo, o.bling_pedido_num
         FROM integration_audit ia
         LEFT JOIN orders o ON o.id = ia.order_id
         WHERE ia.status='error' AND ia.created_at BETWEEN ? AND ? ORDER BY ia.id DESC`
      ).bind(date + ' 00:00:00', date + ' 23:59:59').all().then(r => r.results || []).catch(() => []);

      // Todos os logs de auditoria do dia (com dados do pedido)
      const auditLogs = await env.DB.prepare(
        `SELECT ia.id, ia.order_id, ia.action, ia.status, ia.bling_pedido_id, ia.error_message, ia.created_at,
                o.customer_name, o.total_value, o.tipo_pagamento AS order_tipo, o.vendedor_nome, o.bling_pedido_num
         FROM integration_audit ia
         LEFT JOIN orders o ON o.id = ia.order_id
         WHERE ia.created_at BETWEEN ? AND ? ORDER BY ia.id DESC LIMIT 200`
      ).bind(date + ' 00:00:00', date + ' 23:59:59').all().then(r => r.results || []).catch(() => []);

      return json({
        date,
        resumo: { totalPedidos, totalValor: Math.round(totalValor * 100) / 100, comBling, semBling, pagos, naoPagos },
        porTipo, porVendedor, porProduto,
        erros_integracao: erros,
        audit_logs: auditLogs,
        pedidos: orders.map(o => ({ id: o.id, cliente: o.customer_name, valor: o.total_value, tipo: o.tipo_pagamento, pago: o.pago, bling_id: o.bling_pedido_id, bling_num: o.bling_pedido_num, vendedor: o.vendedor_nome, status: o.status, created_at: o.created_at }))
      });
    }

    if (method === 'GET' && path === '/api/auditoria/conciliacao-bling') {
      const authCheck = await requireAuth(request, env, ['admin']);
      if (authCheck instanceof Response) return authCheck;

      const date = url.searchParams.get('date') || new Date().toISOString().slice(0, 10);
      const epochStart = Math.floor(new Date(date + 'T00:00:00-04:00').getTime() / 1000);
      const epochEnd = Math.floor(new Date(date + 'T23:59:59-04:00').getTime() / 1000);

      const orders = await env.DB.prepare(
        `SELECT id, customer_name, total_value, bling_pedido_id, bling_pedido_num, tipo_pagamento FROM orders WHERE created_at >= ? AND created_at <= ? AND bling_pedido_id IS NOT NULL AND bling_pedido_id != '' ORDER BY id`
      ).bind(epochStart, epochEnd).all().then(r => r.results || []);

      const conciliados = [];
      const faltando_bling = [];
      const erros = [];

      // Rate limit: max 5 por segundo
      for (let i = 0; i < orders.length; i++) {
        const o = orders[i];
        if (i > 0 && i % 5 === 0) {
          await new Promise(r => setTimeout(r, 1100)); // pausa 1.1s a cada 5
        }
        try {
          const resp = await blingFetch(`/pedidos/vendas/${o.bling_pedido_id}`, {}, env);
          if (resp.ok) {
            const data = await resp.json();
            conciliados.push({ order_id: o.id, bling_id: o.bling_pedido_id, bling_num: o.bling_pedido_num, cliente: o.customer_name, valor_local: o.total_value, valor_bling: data.data?.totalProdutos || data.data?.total || null });
          } else if (resp.status === 404) {
            faltando_bling.push({ order_id: o.id, bling_id: o.bling_pedido_id, cliente: o.customer_name, valor: o.total_value, motivo: 'Não encontrado no Bling' });
          } else {
            erros.push({ order_id: o.id, bling_id: o.bling_pedido_id, erro: `HTTP ${resp.status}` });
          }
        } catch (e) {
          erros.push({ order_id: o.id, bling_id: o.bling_pedido_id, erro: e.message });
        }
      }

      return json({
        date,
        total_verificados: orders.length,
        conciliados: { count: conciliados.length, items: conciliados },
        faltando_bling: { count: faltando_bling.length, items: faltando_bling },
        erros: { count: erros.length, items: erros },
      });
    }

    if (method === 'GET' && path === '/api/auditoria/log-detalhado') {
      const authCheck = await requireAuth(request, env, ['admin']);
      if (authCheck instanceof Response) return authCheck;
      await ensureAuditTable(env);
      const orderId = url.searchParams.get('order_id');
      if (!orderId) return err('order_id obrigatório');
      const logs = await env.DB.prepare(
        'SELECT * FROM integration_audit WHERE order_id=? ORDER BY id DESC LIMIT 50'
      ).bind(parseInt(orderId)).all().then(r => r.results || []);
      return json(logs);
    }

    // ── Histórico de status de um pedido ──────────────────────
    const statusLogMatch = path.match(/^\/api\/order\/(\d+)\/status-log$/);
    if (method === 'GET' && statusLogMatch) {
      const authCheck = await requireAuth(request, env, ['admin', 'atendente']);
      if (authCheck instanceof Response) return authCheck;
      await ensureAuditTable(env);
      const orderId = parseInt(statusLogMatch[1]);
      const logs = await env.DB.prepare(
        'SELECT * FROM order_status_log WHERE order_id=? ORDER BY id DESC LIMIT 50'
      ).bind(orderId).all().then(r => r.results || []);
      return json(logs);
    }

    // ══════════════════════════════════════════════════════════════
    // ── PUSHINPAY PIX — Debug + Test ────────────────────────────
    // ══════════════════════════════════════════════════════════════

    // Debug: verificar pix_tx_id de um pedido
    const pixDebugMatch = path.match(/^\/api\/pix\/debug\/(\d+)$/);
    if (method === 'GET' && pixDebugMatch) {
      await ensurePixColumns(env);
      const orderId = parseInt(pixDebugMatch[1]);
      const order = await env.DB.prepare(
        'SELECT id, pix_tx_id, pix_qrcode, pix_paid_at, pago, status, tipo_pagamento, total_value, cora_invoice_id, cora_qrcode, cora_paid_at FROM orders WHERE id=?'
      ).bind(orderId).first();
      return json({ ok: true, order: order || null, configured: isPixConfigured(env) });
    }

    // Test: simular webhook (manual)
    if (method === 'POST' && path === '/api/pub/pix-simulate') {
      const body = await request.json().catch(() => ({}));
      const txId = body.tx_id;
      if (!txId) return err('Informe tx_id', 400);
      await ensurePixColumns(env);
      const order = await env.DB.prepare(
        'SELECT id, pago, status, pix_paid_at FROM orders WHERE pix_tx_id = ?'
      ).bind(txId).first();
      if (!order) return json({ ok: false, error: 'Nenhum pedido com esse pix_tx_id', tx_id: txId });
      if (order.pago === 1) return json({ ok: true, message: 'Já estava pago', order_id: order.id });

      // Marcar como pago (simula webhook)
      await env.DB.prepare('UPDATE orders SET pago=1, pix_paid_at=unixepoch() WHERE id=?').bind(order.id).run();
      await logEvent(env, order.id, 'pushinpay_pix_simulated', { tx_id: txId });
      return json({ ok: true, action: 'marked_paid', order_id: order.id });
    }

    // ══════════════════════════════════════════════════════════════
    // ── PUSHINPAY PIX — Webhook (PÚBLICO — sem auth) ─────────────
    // ══════════════════════════════════════════════════════════════

    if (method === 'GET' && path === '/api/webhooks/pushinpay') {
      return json({ ok: true, status: 'active', service: 'moskogas-pushinpay' });
    }

    if (method === 'POST' && path === '/api/webhooks/pushinpay') {
      try {
        await ensurePixColumns(env);
        const rawBody = await request.text().catch(() => '');
        let bodyData;
        try { bodyData = JSON.parse(rawBody); } catch { bodyData = null; }

        // Log TUDO que chega (debug)
        console.log(`[pushinpay-webhook] RAW BODY: ${rawBody.substring(0, 1000)}`);

        // Salvar webhook recebido no order_events pra debug
        await env.DB.prepare(
          "INSERT INTO order_events (order_id, evento, detalhes, created_at) VALUES (0, 'pushinpay_webhook_received', ?, unixepoch())"
        ).bind(rawBody.substring(0, 2000)).run().catch(() => { });

        if (!bodyData) return json({ ok: true, ignored: 'empty/invalid body' });

        const txId = bodyData.id;
        const status = bodyData.status;
        const endToEnd = bodyData.end_to_end_id || '';
        console.log(`[pushinpay-webhook] tx=${txId}, status=${status}, e2e=${endToEnd}`);

        if (!txId) return json({ ok: true, ignored: 'no tx id' });
        if (status !== 'paid') return json({ ok: true, ignored: `status=${status}` });

        // Buscar pedido pelo pix_tx_id
        const order = await env.DB.prepare(
          'SELECT id, pago, status, tipo_pagamento, pix_paid_at, bling_pedido_id FROM orders WHERE pix_tx_id = ?'
        ).bind(txId).first();

        if (!order) {
          console.log(`[pushinpay-webhook] No order found for tx ${txId}`);
          return json({ ok: true, ignored: 'order not found' });
        }

        if (order.pago === 1 || order.pix_paid_at) {
          console.log(`[pushinpay-webhook] Order #${order.id} already paid`);
          return json({ ok: true, ignored: 'already paid' });
        }

        // Marcar pago
        await env.DB.prepare('UPDATE orders SET pago=1, pix_paid_at=unixepoch() WHERE id=?').bind(order.id).run();
        await logEvent(env, order.id, 'pushinpay_pix_confirmed', { tx_id: txId, end_to_end: endToEnd });

        // Criar Bling se ainda não tem
        let blingResult = null;
        if (!order.bling_pedido_id) {
          try {
            const fullOrder = await env.DB.prepare('SELECT * FROM orders WHERE id=?').bind(order.id).first();
            const cached = fullOrder?.phone_digits
              ? await env.DB.prepare('SELECT bling_contact_id, cpf_cnpj FROM customers_cache WHERE phone_digits=?').bind(fullOrder.phone_digits).first()
              : null;
            let vendBlingId = null, vendNome = fullOrder?.vendedor_nome || '';
            if (fullOrder?.vendedor_id) {
              const vendUser = await env.DB.prepare('SELECT bling_vendedor_id, nome FROM app_users WHERE id=?').bind(fullOrder.vendedor_id).first().catch(() => null);
              if (vendUser?.bling_vendedor_id) vendBlingId = vendUser.bling_vendedor_id;
              if (vendUser?.nome) vendNome = vendUser.nome;
            }
            const blingData = await criarPedidoBling(env, order.id, {
              name: fullOrder?.customer_name,
              items: JSON.parse(fullOrder?.items_json || '[]'),
              total_value: fullOrder?.total_value,
              tipo_pagamento: fullOrder?.tipo_pagamento,
              bling_contact_id: cached?.bling_contact_id || null,
              cpf_cnpj: cached?.cpf_cnpj || null,
              bling_vendedor_id: vendBlingId,
              vendedor_nome: vendNome,
            });
            await env.DB.prepare(
              'UPDATE orders SET bling_pedido_id=?, bling_pedido_num=?, sync_status=? WHERE id=?'
            ).bind(blingData.bling_pedido_id, blingData.bling_pedido_num, 'synced', order.id).run();
            blingResult = { created: true, id: blingData.bling_pedido_id };
          } catch (be) {
            console.error('[pushinpay-webhook] Bling error:', be.message);
            blingResult = { error: be.message };
          }
        }

        // WhatsApp admin: PIX confirmado
        try {
          const admins = await env.DB.prepare("SELECT telefone FROM app_users WHERE role='admin' AND recebe_whatsapp=1 AND ativo=1").all();
          const adminPhones = (admins.results || []).map(a => a.telefone).filter(Boolean);
          const fullOrder = await env.DB.prepare('SELECT customer_name, total_value FROM orders WHERE id=?').bind(order.id).first();
          const valor = parseFloat(fullOrder?.total_value || 0).toFixed(2);
          const msg = `✅ *PIX CONFIRMADO* — Pedido #${order.id}\n\n💰 R$ ${valor} — ${fullOrder?.customer_name || 'Cliente'}\n\nPagamento PIX recebido com sucesso.`;
          for (const phone of adminPhones) {
            await sendWhatsApp(env, phone, msg, { category: 'admin_alerta' });
          }
        } catch (we) {
          console.error('[pushinpay-webhook] WhatsApp admin error:', we.message);
        }

        console.log(`[pushinpay-webhook] Order #${order.id} marked as paid`);
        return json({ ok: true, order_id: order.id, action: 'marked_paid', bling: blingResult });

      } catch (e) {
        console.error('[pushinpay-webhook] Error:', e.message);
        return json({ ok: false, error: e.message }, 500);
      }
    }

    // ── PushInPay PIX — Status endpoint ──────────────────────────
    if (method === 'GET' && (path === '/api/pix/status' || path === '/api/cora/status')) {
      await ensurePixColumns(env);
      const stats = await env.DB.prepare(`
        SELECT 
          COUNT(*) as total,
          SUM(CASE WHEN pix_paid_at IS NOT NULL THEN 1 ELSE 0 END) as paid,
          SUM(CASE WHEN pix_paid_at IS NULL AND pago=0 THEN 1 ELSE 0 END) as pending
        FROM orders WHERE pix_tx_id IS NOT NULL
      `).first().catch(() => ({ total: 0, paid: 0, pending: 0 }));
      return json({ provider: 'pushinpay', configured: isPixConfigured(env), stats, webhook_url: 'https://api.moskogas.com.br/api/webhooks/pushinpay' });
    }

    // ── PushInPay: Diagnóstico de conexão ──────────────────────
    if (method === 'GET' && path === '/api/pix/diagnostico') {
      const authCheck = await requireAuth(request, env, ['admin', 'atendente']);
      if (authCheck instanceof Response) return authCheck;
      const configured = isPixConfigured(env);
      let api_reachable = false;
      let api_error = null;
      let account = null;
      if (configured) {
        try {
          const r = await fetch(`${PUSHINPAY_API}/api/transactions?per_page=1`, {
            headers: { 'Authorization': `Bearer ${env.PUSHINPAY_TOKEN}`, 'Accept': 'application/json' }
          });
          if (r.ok) {
            api_reachable = true;
            account = { note: 'API respondendo normalmente' };
          } else {
            const t = await r.text().catch(() => '');
            api_error = `HTTP ${r.status}: ${t.substring(0, 200)}`;
          }
        } catch (e) {
          api_error = e.message;
        }
      }
      return json({ token_configured: configured, api_reachable, api_error, account, webhook_url: 'https://api.moskogas.com.br/api/webhooks/pushinpay' });
    }

    // ── PushInPay: Logs de webhooks recebidos ──────────────────
    if (method === 'GET' && path === '/api/pix/webhook-logs') {
      const authCheck = await requireAuth(request, env, ['admin', 'atendente']);
      if (authCheck instanceof Response) return authCheck;
      const since = Math.floor(Date.now() / 1000) - 86400; // últimas 24h
      const rows = await env.DB.prepare(
        "SELECT id, evento, detalhes, created_at FROM order_events WHERE event='pushinpay_webhook_received' AND rowid IN (SELECT rowid FROM order_events WHERE event='pushinpay_webhook_received' ORDER BY id DESC LIMIT 50)"
      ).all().catch(() => ({ results: [] }));
      // Tentar também pelo campo evento (nome pode variar)
      const rows2 = await env.DB.prepare(
        "SELECT id, evento, detalhes, created_at FROM order_events WHERE (event='pushinpay_webhook_received' OR evento='pushinpay_webhook_received') ORDER BY id DESC LIMIT 50"
      ).all().catch(() => ({ results: [] }));
      const logs = (rows2.results || rows.results || []);
      return json({ ok: true, logs, webhook_url: 'https://api.moskogas.com.br/api/webhooks/pushinpay' });
    }

    // ── PushInPay: Cobrança teste R$1,01 ───────────────────────
    if (method === 'POST' && path === '/api/pix/teste-cobranca') {
      const authCheck = await requireAuth(request, env, ['admin']);
      if (authCheck instanceof Response) return authCheck;
      if (!isPixConfigured(env)) return err('PUSHINPAY_TOKEN não configurado', 400);
      try {
        const data = await pushInPayCreateCharge(env, 0, 1.01);
        return json({ ok: true, tx_id: data.tx_id || data.id, qr_code: data.qr_code, status: data.status });
      } catch (e) {
        return json({ ok: false, error: e.message });
      }
    }

    // ── PushInPay: Consultar status de transação ────────────────
    const pixTesteConsultarMatch = path.match(/^\/api\/pix\/teste-consultar\/(.+)$/);
    if (method === 'GET' && pixTesteConsultarMatch) {
      const authCheck = await requireAuth(request, env, ['admin']);
      if (authCheck instanceof Response) return authCheck;
      if (!isPixConfigured(env)) return err('PUSHINPAY_TOKEN não configurado', 400);
      const txId = pixTesteConsultarMatch[1];
      try {
        const data = await pushInPayCheckStatus(env, txId);
        return json({ ok: true, status: data.status, value: data.value, end_to_end_id: data.end_to_end_id });
      } catch (e) {
        return json({ ok: false, error: e.message });
      }
    }

    // Legacy: manter /api/webhooks/cora respondendo
    if (path === '/api/webhooks/cora') {
      return json({ ok: true, message: 'Cora deprecated, use /api/webhooks/pushinpay' });
    }

    // ── PIX: Verificar pagamento via API PushInPay ──────────────
    const pixCheckMatch = path.match(/^\/api\/pix\/check\/(\d+)$/);
    if (method === 'POST' && pixCheckMatch) {
      const orderId = parseInt(pixCheckMatch[1]);
      await ensurePixColumns(env);
      const order = await env.DB.prepare('SELECT id, pix_tx_id, pago, pix_paid_at, status, tipo_pagamento, total_value FROM orders WHERE id=?').bind(orderId).first();
      if (!order) return err('Pedido não encontrado', 404);
      if (order.pago === 1) return json({ ok: true, message: 'Já está pago', order_id: orderId });
      if (!order.pix_tx_id) return json({ ok: false, error: 'Pedido sem pix_tx_id — QR não foi gerado via PushInPay' });

      if (!isPixConfigured(env)) return err('PushInPay não configurada', 400);

      try {
        const txData = await pushInPayCheckStatus(env, order.pix_tx_id);
        if (txData.status === 'paid') {
          // Marcar pago
          await env.DB.prepare('UPDATE orders SET pago=1, pix_paid_at=unixepoch() WHERE id=?').bind(orderId).run();
          await logEvent(env, orderId, 'pushinpay_manual_check_paid', { tx_id: order.pix_tx_id, api_status: txData.status });
          return json({ ok: true, action: 'marked_paid', order_id: orderId, tx_status: txData.status });
        }
        return json({ ok: true, action: 'still_pending', order_id: orderId, tx_status: txData.status, tx_data: txData });
      } catch (e) {
        return json({ ok: false, error: e.message }, 500);
      }
    }

    // ── PIX: Confirmar pagamento manualmente ─────────────────────
    const pixConfirmMatch = path.match(/^\/api\/pix\/confirm\/(\d+)$/);
    if (method === 'POST' && pixConfirmMatch) {
      const orderId = parseInt(pixConfirmMatch[1]);
      await ensurePixColumns(env);
      const order = await env.DB.prepare('SELECT id, pago, pix_paid_at FROM orders WHERE id=?').bind(orderId).first();
      if (!order) return err('Pedido não encontrado', 404);
      if (order.pago === 1) return json({ ok: true, message: 'Já estava pago' });
      await env.DB.prepare('UPDATE orders SET pago=1, pix_paid_at=unixepoch() WHERE id=?').bind(orderId).run();
      await logEvent(env, orderId, 'pix_manual_confirm', { confirmed_by: 'admin' });
      return json({ ok: true, action: 'marked_paid', order_id: orderId });
    }

    // ══════════════════════════════════════════════════════════════
    // ── Webhook IzChat — mensagens recebidas (PÚBLICO — sem auth) ──
    if (method === 'POST' && path === '/api/webhooks/izchat') {
      try {
        const payload = await request.json().catch(() => ({}));
        // IzChat envia o evento no header X-Webhook-Event OU no body
        const event = request.headers.get('X-Webhook-Event') || payload?.event || payload?.type || '';
        console.log('[izchat-webhook] Event:', event, '| Payload:', JSON.stringify(payload).slice(0, 500));

        // ── Evento: oportunidade movida no CRM (agente IA moveu após receber nota) ──
        if (event === 'crm.opportunity.moved' || event === 'opportunity.moved') {
          // Payload real IzChat: { event, data: { id, ticketId, toStageTitle, contact: { number, name } } }
          const opp = payload?.data || {};
          const stageName = opp?.toStageTitle || opp?.stageName || '';
          const oppId = String(opp?.id || '');
          const contactPhone = opp?.contact?.number || opp?.contact?.phone || '';
          const contactName = opp?.contact?.name || '';

          console.log(`[izchat-webhook] CRM moved → toStage: "${stageName}", oppId: ${oppId}, phone: ${contactPhone}`);

          if (oppId) {
            // Determinar score pela etapa
            let score = null;
            const stageNorm = stageName.toLowerCase();
            if (stageNorm.includes('google')) score = 5;
            else if (stageNorm.includes('interna') || stageNorm.includes('avalia')) score = 3; // placeholder — será sobrescrito pelo número real

            // Buscar survey pelo opp_id ou phone
            let survey = null;
            if (oppId) {
              survey = await env.DB.prepare(
                `SELECT * FROM satisfaction_surveys WHERE izchat_opp_id=? ORDER BY sent_at DESC LIMIT 1`
              ).bind(oppId).first().catch(() => null);
            }
            if (!survey && contactPhone) {
              const phone = contactPhone.replace(/\D/g, '');
              survey = await env.DB.prepare(
                `SELECT * FROM satisfaction_surveys WHERE phone_digits=? AND status='sent' ORDER BY sent_at DESC LIMIT 1`
              ).bind(phone).first().catch(() => null);
            }

            if (survey) {
              const config = await getAvaliacaoConfig(env);
              const phoneDigits = survey.phone_digits;
              const phoneIntl = phoneDigits.startsWith('55') ? phoneDigits : `55${phoneDigits}`;
              const nomeCliente = contactName || (survey.customer_name || 'Cliente').split(' ')[0];

              // Score final pela etapa
              const scoreFinal = stageNorm.includes('google') ? 5 : (survey.score_raw || 3);

              // Atualizar survey
              await env.DB.prepare(
                `UPDATE satisfaction_surveys SET score=?, answered_at=unixepoch(), status='answered', izchat_opp_id=? WHERE id=?`
              ).bind(scoreFinal, oppId, survey.id).run();

              if (scoreFinal >= 5) {
                // Enviar link Google Review
                const googleUrl = config.google_url || 'https://g.page/r/moskogas';
                const msg = montarMensagemAvaliacao(config.mensagem_positiva, { nome: nomeCliente, google_url: googleUrl });
                await sendWhatsApp(env, phoneIntl, msg, { category: 'avaliacao' });
                await env.DB.prepare('UPDATE satisfaction_surveys SET google_link_sent=1 WHERE id=?').bind(survey.id).run();
                console.log(`[izchat-webhook] ⭐ Score 5 — link Google enviado para ${phoneDigits}`);
              } else {
                // Follow-up é feito pelo próprio Agente IA do IzChat
                // Worker apenas registra e alerta admins
                await env.DB.prepare('UPDATE satisfaction_surveys SET follow_up_sent=1 WHERE id=?').bind(survey.id).run();
                // Alerta admins
                const { results: admins } = await env.DB.prepare(
                  "SELECT telefone FROM app_users WHERE role='admin' AND recebe_whatsapp=1 AND ativo=1 AND telefone IS NOT NULL"
                ).all().catch(() => ({ results: [] }));
                const msgAdmin = montarMensagemAvaliacao(config.mensagem_admin, {
                  nome: survey.customer_name || 'Desconhecido',
                  telefone: phoneDigits,
                  score: scoreFinal,
                  pedido_id: survey.order_id,
                });
                for (const admin of admins) {
                  const ap = admin.telefone.replace(/\D/g, '');
                  await sendWhatsApp(env, ap.startsWith('55') ? ap : `55${ap}`, msgAdmin, { category: 'admin_alerta' });
                  await new Promise(r => setTimeout(r, 1500));
                }
                console.log(`[izchat-webhook] ⚠️ Score ${scoreFinal} — follow-up + admins alertados`);
              }
            } else {
              console.log(`[izchat-webhook] Survey não encontrada para oppId ${oppId}`);
            }
          }
          return json({ ok: true });
        }

        // ── Evento: mensagem recebida (fallback para resposta direta 1-5) ──
        const fromMe = payload?.data?.message?.fromMe ?? payload?.fromMe ?? false;
        if (fromMe) return json({ ok: true, ignored: 'fromMe' });

        const body = payload?.data?.message?.body || payload?.body || payload?.text || '';
        const number = payload?.data?.message?.contact?.number || payload?.data?.contact?.number || payload?.number || '';

        if (body && number) {
          const phoneDigits = number.replace(/\D/g, '');
          // Salvar score_raw para usar quando o CRM mover
          const score = parseInt(body.trim());
          if (!isNaN(score) && score >= 1 && score <= 5) {
            await env.DB.prepare(
              `UPDATE satisfaction_surveys SET score_raw=? WHERE phone_digits=? AND status='sent' ORDER BY sent_at DESC LIMIT 1`
            ).bind(score, phoneDigits).run().catch(() => {});
          }
          const respondeu = await processarRespostaAvaliacao(env, phoneDigits, body);
          console.log(`[izchat-webhook] ${phoneDigits} "${body}" → avaliacao: ${respondeu}`);
        }
        return json({ ok: true });
      } catch (e) {
        console.error('[izchat-webhook] Erro:', e.message);
        return json({ ok: true }); // sempre 200 para webhook
      }
    }

    // ── AVALIAÇÕES — Endpoints (requer auth JWT) ─────────────────
    if (path.startsWith('/api/avaliacoes')) {
      await ensureAvaliacaoTables(env);

      // Config GET/POST
      if (path === '/api/avaliacoes/config') {
        if (method === 'GET') {
          const authErr = requireAuth(request, env, ['admin', 'atendente']);
          if (authErr) return authErr;
          return json(await getAvaliacaoConfig(env));
        }
        if (method === 'POST') {
          const authErr = requireAuth(request, env, ['admin']);
          if (authErr) return authErr;
          const body = await request.json();
          await env.DB.prepare("INSERT OR REPLACE INTO app_config (key, value, updated_at) VALUES ('avaliacao_config', ?, datetime('now'))").bind(JSON.stringify(body)).run();
          return json({ ok: true });
        }
      }

      // Listar avaliações com filtros
      if (method === 'GET' && path === '/api/avaliacoes') {
        const authErr = requireAuth(request, env, ['admin', 'atendente']);
        if (authErr) return authErr;
        const qp = new URL(request.url).searchParams;
        const status = qp.get('status') || '';
        const desde = qp.get('desde') || '';
        const ate = qp.get('ate') || '';
        const page = parseInt(qp.get('page') || '1');
        const pageSize = 50;

        let where = [];
        let binds = [];
        if (status) { where.push("ss.status = ?"); binds.push(status); }
        if (desde) { where.push("ss.sent_at >= ?"); binds.push(Math.floor(new Date(desde).getTime()/1000)); }
        if (ate) { where.push("ss.sent_at <= ?"); binds.push(Math.floor(new Date(ate).getTime()/1000) + 86399); }
        const whereStr = where.length ? 'WHERE ' + where.join(' AND ') : '';

        const countRow = await env.DB.prepare(`SELECT COUNT(*) as c FROM satisfaction_surveys ss ${whereStr}`).bind(...binds).first();
        const total = countRow?.c || 0;

        const rows = await env.DB.prepare(`
          SELECT ss.*, o.total_value, o.tipo_pagamento, o.driver_name_cache
          FROM satisfaction_surveys ss
          LEFT JOIN orders o ON o.id = ss.order_id
          ${whereStr}
          ORDER BY ss.sent_at DESC
          LIMIT ? OFFSET ?
        `).bind(...binds, pageSize, (page - 1) * pageSize).all();

        // Stats
        const stats = await env.DB.prepare(`
          SELECT
            COUNT(*) as total_enviadas,
            SUM(CASE WHEN status='answered' THEN 1 ELSE 0 END) as respondidas,
            ROUND(AVG(CASE WHEN score IS NOT NULL THEN score END), 2) as media,
            SUM(CASE WHEN score = 5 THEN 1 ELSE 0 END) as nota5,
            SUM(CASE WHEN score = 4 THEN 1 ELSE 0 END) as nota4,
            SUM(CASE WHEN score = 3 THEN 1 ELSE 0 END) as nota3,
            SUM(CASE WHEN score <= 2 THEN 1 ELSE 0 END) as nota12
          FROM satisfaction_surveys
        `).first();

        // Série temporal (últimos 30 dias)
        const serie = await env.DB.prepare(`
          SELECT date(sent_at, 'unixepoch', '-3 hours') as dia,
            COUNT(*) as enviadas,
            SUM(CASE WHEN status='answered' THEN 1 ELSE 0 END) as respondidas,
            ROUND(AVG(score), 2) as media_dia
          FROM satisfaction_surveys
          WHERE sent_at >= unixepoch() - 2592000
          GROUP BY dia ORDER BY dia DESC
        `).all();

        return json({
          surveys: rows.results || [],
          total,
          page,
          pages: Math.ceil(total / pageSize),
          stats,
          serie: (serie.results || []).reverse(),
        });
      }

      // Enviar avaliação manual para um pedido específico
      if (method === 'POST' && path === '/api/avaliacoes/enviar') {
        const authErr = requireAuth(request, env, ['admin', 'atendente']);
        if (authErr) return authErr;
        const { order_id } = await request.json();
        if (!order_id) return json({ error: 'order_id obrigatório' }, 400);

        const order = await env.DB.prepare('SELECT * FROM orders WHERE id=?').bind(order_id).first();
        if (!order) return json({ error: 'Pedido não encontrado' }, 404);
        if (!order.phone_digits) return json({ error: 'Pedido sem telefone' }, 400);
        if (order.phone_digits === '00000000000') return json({ error: 'Consumidor Final — sem WhatsApp' }, 400);

        // Verificar flag sem_avaliacao
        const cc = await env.DB.prepare('SELECT sem_avaliacao FROM customers_cache WHERE phone_digits=?').bind(order.phone_digits).first();
        if (cc?.sem_avaliacao) return json({ error: 'Cliente com avaliação desativada' }, 400);

        const config = await getAvaliacaoConfig(env);
        const phoneIntl = order.phone_digits.startsWith('55') ? order.phone_digits : `55${order.phone_digits}`;
        const mensagem = montarMensagemAvaliacao(config.mensagem_pesquisa, {
          nome: (order.customer_name || 'Cliente').split(' ')[0],
        });

        const result = await sendWhatsApp(env, phoneIntl, mensagem, { category: 'avaliacao' });
        if (result?.blocked) return json({ error: 'WhatsApp bloqueado no momento' }, 503);

        await env.DB.prepare('UPDATE orders SET survey_sent=1 WHERE id=?').bind(order_id).run();
        await env.DB.prepare(`
          INSERT OR REPLACE INTO satisfaction_surveys (order_id, phone_digits, customer_name, status)
          VALUES (?, ?, ?, 'sent')
        `).bind(order_id, order.phone_digits, order.customer_name || '').run();

        return json({ ok: true, message: 'Avaliação enviada!' });
      }

      // Toggle sem_avaliacao por telefone
      if (method === 'PATCH' && path.match(/^\/api\/avaliacoes\/cliente\/(.+)\/toggle$/)) {
        const authErr = requireAuth(request, env, ['admin', 'atendente']);
        if (authErr) return authErr;
        const phone = path.split('/')[4];
        const cc = await env.DB.prepare('SELECT sem_avaliacao FROM customers_cache WHERE phone_digits=?').bind(phone).first();
        const novoValor = cc?.sem_avaliacao ? 0 : 1;
        await env.DB.prepare('UPDATE customers_cache SET sem_avaliacao=? WHERE phone_digits=?').bind(novoValor, phone).run();
        return json({ ok: true, sem_avaliacao: novoValor });
      }

      // Enviar bulk (reenviar para respondidas/não respondidas em lote)
      if (method === 'POST' && path === '/api/avaliacoes/enviar-cron') {
        const authErr = requireAuth(request, env, ['admin']);
        if (authErr) return authErr;
        await processarAvaliacoesCron(env);
        return json({ ok: true, message: 'Cron de avaliações executado' });
      }
    }

    // ── CONTRATOS (Comodato) ─────────────────────────────────────
    // ══════════════════════════════════════════════════════════════

    // ── Webhook Assinafy (PÚBLICO — sem auth) ─────────────────
    if (method === 'POST' && path === '/api/webhooks/assinatura') {
      try {
        await ensureContractTables(env);
        const payload = await request.json();
        const event = payload.event;
        const objectId = payload.object?.id;
        const objectName = payload.object?.name;
        console.log(`[assinafy-webhook] Event: ${event}, DocId: ${objectId}`);

        if (!objectId) return json({ ok: true, ignored: 'no object id' });

        // Find contract by assinafy_doc_id
        const contract = await env.DB.prepare(
          'SELECT id, status, assinafy_assignment_id FROM contracts WHERE assinafy_doc_id = ?'
        ).bind(objectId).first();

        if (!contract) {
          console.log(`[assinafy-webhook] No contract found for doc ${objectId}`);
          return json({ ok: true, ignored: 'contract not found' });
        }

        if (event === 'signer_signed_document') {
          // A signer has signed — update their record
          const signerName = payload.subject?.name;
          if (signerName) {
            await env.DB.prepare(
              "UPDATE contract_signers SET status='signed', signed_at=unixepoch() WHERE contract_id=? AND nome=? AND status='pending'"
            ).bind(contract.id, signerName).run();
          }
          // Check if partially signed
          const pending = await env.DB.prepare(
            "SELECT COUNT(*) as c FROM contract_signers WHERE contract_id=? AND status='pending'"
          ).bind(contract.id).first();
          if (pending && pending.c > 0) {
            await env.DB.prepare(
              "UPDATE contracts SET status='partially_signed', updated_at=unixepoch() WHERE id=?"
            ).bind(contract.id).run();
          }
          await logContractEvent(env, contract.id, 'signer_signed', `${signerName} assinou o documento`, null);
        }

        if (event === 'document_ready') {
          // All signers have signed — download certificated PDF
          try {
            const pdfBytes = await assinaryDownloadSigned(env, objectId);
            const r2Key = `contracts/${contract.id}/signed.pdf`;
            await env.BUCKET.put(r2Key, pdfBytes, { httpMetadata: { contentType: 'application/pdf' } });
            await env.DB.prepare(
              "UPDATE contracts SET status='signed', signed_pdf_key=?, signed_at=unixepoch(), updated_at=unixepoch() WHERE id=?"
            ).bind(r2Key, contract.id).run();
            await logContractEvent(env, contract.id, 'document_signed', 'Todos assinaram. PDF certificado salvo.', null);
          } catch (dlErr) {
            console.error('[assinafy-webhook] Download signed PDF error:', dlErr.message);
            await env.DB.prepare(
              "UPDATE contracts SET status='signed', signed_at=unixepoch(), updated_at=unixepoch(), assinafy_error=? WHERE id=?"
            ).bind('Download PDF falhou: ' + dlErr.message, contract.id).run();
          }
        }

        if (event === 'signer_rejected_document') {
          const signerName = payload.subject?.name;
          await env.DB.prepare(
            "UPDATE contract_signers SET status='rejected', reject_reason=? WHERE contract_id=? AND nome=? AND status='pending'"
          ).bind(payload.decline_reason || 'Rejeitado', contract.id, signerName || '').run();
          await env.DB.prepare(
            "UPDATE contracts SET status='error', assinafy_error=?, updated_at=unixepoch() WHERE id=?"
          ).bind(`Rejeitado por ${signerName}: ${payload.decline_reason || ''}`, contract.id).run();
          await logContractEvent(env, contract.id, 'signer_rejected', `${signerName} rejeitou: ${payload.decline_reason || ''}`, null);
        }

        if (event === 'document_processing_failed') {
          await env.DB.prepare(
            "UPDATE contracts SET status='error', assinafy_error='Processamento falhou na Assinafy', updated_at=unixepoch() WHERE id=?"
          ).bind(contract.id).run();
          await logContractEvent(env, contract.id, 'processing_failed', 'Assinafy não conseguiu processar o documento', null);
        }

        return json({ ok: true, processed: event });
      } catch (e) {
        console.error('[assinafy-webhook] Error:', e.message);
        return json({ ok: true, error: e.message });
      }
    }

    // ── Rotas de contratos (requerem auth admin/atendente) ────
    if (path.startsWith('/api/contratos')) {
      await ensureContractTables(env);
    }

    // ── GET /api/contratos — Listar ──────────────────────────
    if (method === 'GET' && path === '/api/contratos') {
      const authCheck = await requireAuth(request, env, ['admin', 'atendente']);
      if (authCheck instanceof Response) return authCheck;

      const status = url.searchParams.get('status');
      const search = url.searchParams.get('search');
      const page = parseInt(url.searchParams.get('page') || '1');
      const limit = parseInt(url.searchParams.get('limit') || '20');
      const offset = (page - 1) * limit;

      let where = '1=1';
      const binds = [];

      if (status) { where += ' AND c.status = ?'; binds.push(status); }
      if (search) {
        where += ' AND (c.numero LIKE ? OR c.razao_social LIKE ? OR c.cnpj_cpf LIKE ? OR c.responsavel_nome LIKE ?)';
        const s = `%${search}%`;
        binds.push(s, s, s, s);
      }

      const countRow = await env.DB.prepare(`SELECT COUNT(*) as total FROM contracts c WHERE ${where}`).bind(...binds).first();
      const total = countRow?.total || 0;

      const rows = await env.DB.prepare(
        `SELECT c.*, (SELECT COUNT(*) FROM contract_signers WHERE contract_id=c.id AND status='signed') as assinaturas_ok,
         (SELECT COUNT(*) FROM contract_signers WHERE contract_id=c.id) as assinaturas_total
         FROM contracts c WHERE ${where} ORDER BY c.id DESC LIMIT ? OFFSET ?`
      ).bind(...binds, limit, offset).all().then(r => r.results || []);

      return json({ ok: true, data: rows, total, page, pages: Math.ceil(total / limit) });
    }

    // ── POST /api/contratos — Criar rascunho ─────────────────
    if (method === 'POST' && path === '/api/contratos') {
      const authCheck = await requireAuth(request, env, ['admin', 'atendente']);
      if (authCheck instanceof Response) return authCheck;

      const body = await request.json();
      const numero = await generateContractNumber(env);

      const result = await env.DB.prepare(
        `INSERT INTO contracts (numero, tipo_pessoa, razao_social, cnpj_cpf, endereco, cep,
         responsavel_nome, responsavel_cpf, responsavel_email, responsavel_telefone,
         itens_json, created_by, created_by_nome)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      ).bind(
        numero,
        body.tipo_pessoa || 'pj',
        body.razao_social || '',
        body.cnpj_cpf || '',
        body.endereco || '',
        body.cep || '',
        body.responsavel_nome || '',
        body.responsavel_cpf || '',
        body.responsavel_email || '',
        body.responsavel_telefone || '',
        JSON.stringify(body.itens || []),
        authCheck.id,
        authCheck.nome
      ).run();

      const contractId = result.meta?.last_row_id;

      // Create default signers if provided
      if (body.signatarios && Array.isArray(body.signatarios)) {
        for (const s of body.signatarios) {
          await env.DB.prepare(
            'INSERT INTO contract_signers (contract_id, role, nome, cpf, telefone, email) VALUES (?, ?, ?, ?, ?, ?)'
          ).bind(contractId, s.role, s.nome, s.cpf || '', s.telefone || '', s.email || '').run();
        }
      }

      await logContractEvent(env, contractId, 'created', `Contrato ${numero} criado como rascunho`, authCheck);
      return json({ ok: true, id: contractId, numero });
    }

    // ── GET /api/contratos/config — Config do comodato ────────
    if (method === 'GET' && path === '/api/contratos/config') {
      const authCheck = await requireAuth(request, env, ['admin', 'atendente']);
      if (authCheck instanceof Response) return authCheck;
      await ensureAuditTable(env); // app_config table

      const keys = ['contrato_comodante', 'contrato_testemunhas', 'contrato_template', 'contrato_produtos'];
      const config = {};
      for (const key of keys) {
        const row = await env.DB.prepare('SELECT value FROM app_config WHERE key=?').bind(key).first();
        try { config[key] = row ? JSON.parse(row.value) : null; } catch { config[key] = row?.value || null; }
      }
      return json({ ok: true, config });
    }

    // ── POST /api/contratos/config — Salvar config ────────────
    if (method === 'POST' && path === '/api/contratos/config') {
      const authCheck = await requireAuth(request, env, ['admin']);
      if (authCheck instanceof Response) return authCheck;
      await ensureAuditTable(env);

      const body = await request.json();
      for (const [key, value] of Object.entries(body)) {
        if (!key.startsWith('contrato_')) continue;
        const val = typeof value === 'string' ? value : JSON.stringify(value);
        await env.DB.prepare(
          "INSERT INTO app_config (key, value, updated_at) VALUES (?, ?, datetime('now')) ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at"
        ).bind(key, val).run();
      }
      await logContractEvent(env, 0, 'config_updated', 'Configuração de contratos atualizada', authCheck);
      return json({ ok: true });
    }

    // ── GET /api/contratos/:id — Detalhe ─────────────────────
    const contratoDetailMatch = path.match(/^\/api\/contratos\/(\d+)$/);
    if (method === 'GET' && contratoDetailMatch) {
      const authCheck = await requireAuth(request, env, ['admin', 'atendente']);
      if (authCheck instanceof Response) return authCheck;
      const id = parseInt(contratoDetailMatch[1]);

      const contract = await env.DB.prepare('SELECT * FROM contracts WHERE id=?').bind(id).first();
      if (!contract) return err('Contrato não encontrado', 404);

      const signers = await env.DB.prepare('SELECT * FROM contract_signers WHERE contract_id=? ORDER BY id').bind(id).all().then(r => r.results || []);
      const attachments = await env.DB.prepare('SELECT * FROM contract_attachments WHERE contract_id=? ORDER BY id').bind(id).all().then(r => r.results || []);
      const events = await env.DB.prepare('SELECT * FROM contract_events WHERE contract_id=? ORDER BY id DESC LIMIT 50').bind(id).all().then(r => r.results || []);

      return json({ ok: true, contract, signers, attachments, events });
    }

    // ── PATCH /api/contratos/:id — Editar rascunho ────────────
    const contratoEditMatch = path.match(/^\/api\/contratos\/(\d+)$/);
    if (method === 'PATCH' && contratoEditMatch) {
      const authCheck = await requireAuth(request, env, ['admin', 'atendente']);
      if (authCheck instanceof Response) return authCheck;
      const id = parseInt(contratoEditMatch[1]);

      const contract = await env.DB.prepare('SELECT status FROM contracts WHERE id=?').bind(id).first();
      if (!contract) return err('Contrato não encontrado', 404);
      if (!['draft', 'ready', 'error'].includes(contract.status)) {
        return err('Só é possível editar contratos em rascunho, pronto ou com erro', 400);
      }

      const body = await request.json();
      const fields = [];
      const vals = [];
      const allowed = ['tipo_pessoa', 'razao_social', 'cnpj_cpf', 'endereco', 'cep',
        'responsavel_nome', 'responsavel_cpf', 'responsavel_email', 'responsavel_telefone',
        'template_html', 'status'];
      for (const key of allowed) {
        if (body[key] !== undefined) { fields.push(`${key}=?`); vals.push(body[key]); }
      }
      if (body.itens !== undefined) { fields.push('itens_json=?'); vals.push(JSON.stringify(body.itens)); }
      if (fields.length === 0 && !body.signatarios) return err('Nada para atualizar');

      if (fields.length > 0) {
        fields.push('updated_at=unixepoch()');
        vals.push(id);
        await env.DB.prepare(`UPDATE contracts SET ${fields.join(', ')} WHERE id=?`).bind(...vals).run();
      }

      // Update signers if provided
      if (body.signatarios && Array.isArray(body.signatarios)) {
        await env.DB.prepare('DELETE FROM contract_signers WHERE contract_id=?').bind(id).run();
        for (const s of body.signatarios) {
          await env.DB.prepare(
            'INSERT INTO contract_signers (contract_id, role, nome, cpf, telefone, email) VALUES (?, ?, ?, ?, ?, ?)'
          ).bind(id, s.role, s.nome, s.cpf || '', s.telefone || '', s.email || '').run();
        }
      }

      await logContractEvent(env, id, 'updated', 'Contrato editado', authCheck);
      return json({ ok: true });
    }

    // ── DELETE /api/contratos/:id — Deletar rascunho ──────────
    const contratoDeleteMatch = path.match(/^\/api\/contratos\/(\d+)$/);
    if (method === 'DELETE' && contratoDeleteMatch) {
      const authCheck = await requireAuth(request, env, ['admin']);
      if (authCheck instanceof Response) return authCheck;
      const id = parseInt(contratoDeleteMatch[1]);

      const contract = await env.DB.prepare('SELECT status FROM contracts WHERE id=?').bind(id).first();
      if (!contract) return err('Contrato não encontrado', 404);
      if (contract.status !== 'draft') return err('Só rascunhos podem ser deletados', 400);

      await env.DB.prepare('DELETE FROM contract_signers WHERE contract_id=?').bind(id).run();
      await env.DB.prepare('DELETE FROM contract_attachments WHERE contract_id=?').bind(id).run();
      await env.DB.prepare('DELETE FROM contract_events WHERE contract_id=?').bind(id).run();
      await env.DB.prepare('DELETE FROM contracts WHERE id=?').bind(id).run();
      return json({ ok: true });
    }

    // ── POST /api/contratos/:id/anexos — Upload anexo ─────────
    const contratoAnexoMatch = path.match(/^\/api\/contratos\/(\d+)\/anexos$/);
    if (method === 'POST' && contratoAnexoMatch) {
      const authCheck = await requireAuth(request, env, ['admin', 'atendente']);
      if (authCheck instanceof Response) return authCheck;
      const id = parseInt(contratoAnexoMatch[1]);

      const contract = await env.DB.prepare('SELECT id FROM contracts WHERE id=?').bind(id).first();
      if (!contract) return err('Contrato não encontrado', 404);

      const formData = await request.formData();
      const file = formData.get('file');
      const tipo = formData.get('tipo') || 'outro';
      if (!file) return err('Arquivo obrigatório');

      const bytes = await file.arrayBuffer();
      const ext = file.name.split('.').pop() || 'pdf';
      const r2Key = `contracts/${id}/anexos/${tipo}_${Date.now()}.${ext}`;

      await env.BUCKET.put(r2Key, bytes, {
        httpMetadata: { contentType: file.type || 'application/octet-stream' },
      });

      const result = await env.DB.prepare(
        'INSERT INTO contract_attachments (contract_id, tipo, nome_arquivo, r2_key, mime, bytes) VALUES (?, ?, ?, ?, ?, ?)'
      ).bind(id, tipo, file.name, r2Key, file.type || '', bytes.byteLength).run();

      await logContractEvent(env, id, 'attachment_added', `Anexo ${tipo}: ${file.name}`, authCheck);
      return json({ ok: true, attachment_id: result.meta?.last_row_id, r2_key: r2Key });
    }

    // ── DELETE /api/contratos/:id/anexos/:aid — Remove anexo ──
    const contratoDelAnexoMatch = path.match(/^\/api\/contratos\/(\d+)\/anexos\/(\d+)$/);
    if (method === 'DELETE' && contratoDelAnexoMatch) {
      const authCheck = await requireAuth(request, env, ['admin', 'atendente']);
      if (authCheck instanceof Response) return authCheck;
      const contractId = parseInt(contratoDelAnexoMatch[1]);
      const attachId = parseInt(contratoDelAnexoMatch[2]);

      const att = await env.DB.prepare('SELECT r2_key FROM contract_attachments WHERE id=? AND contract_id=?').bind(attachId, contractId).first();
      if (!att) return err('Anexo não encontrado', 404);

      await env.BUCKET.delete(att.r2_key).catch(() => { });
      await env.DB.prepare('DELETE FROM contract_attachments WHERE id=?').bind(attachId).run();
      await logContractEvent(env, contractId, 'attachment_removed', `Anexo removido`, authCheck);
      return json({ ok: true });
    }

    // ── POST /api/contratos/:id/gerar-pdf — Salvar PDF no R2 ──
    const contratoGerarPdfMatch = path.match(/^\/api\/contratos\/(\d+)\/gerar-pdf$/);
    if (method === 'POST' && contratoGerarPdfMatch) {
      const authCheck = await requireAuth(request, env, ['admin', 'atendente']);
      if (authCheck instanceof Response) return authCheck;
      const id = parseInt(contratoGerarPdfMatch[1]);

      const contract = await env.DB.prepare('SELECT * FROM contracts WHERE id=?').bind(id).first();
      if (!contract) return err('Contrato não encontrado', 404);

      // Receive PDF bytes from client (generated by html2pdf.js)
      const pdfBytes = await request.arrayBuffer();
      if (!pdfBytes || pdfBytes.byteLength < 100) return err('PDF inválido');

      const r2Key = `contracts/${id}/generated.pdf`;
      await env.BUCKET.put(r2Key, pdfBytes, {
        httpMetadata: { contentType: 'application/pdf' },
      });

      // Save comodante + testemunhas snapshot
      await ensureAuditTable(env);
      const comodanteRow = await env.DB.prepare("SELECT value FROM app_config WHERE key='contrato_comodante'").first();
      const testemunhasRow = await env.DB.prepare("SELECT value FROM app_config WHERE key='contrato_testemunhas'").first();

      await env.DB.prepare(
        "UPDATE contracts SET generated_pdf_key=?, comodante_snapshot=?, testemunhas_snapshot=?, status='ready', updated_at=unixepoch() WHERE id=?"
      ).bind(r2Key, comodanteRow?.value || '{}', testemunhasRow?.value || '[]', id).run();

      await logContractEvent(env, id, 'pdf_generated', `PDF gerado (${Math.round(pdfBytes.byteLength / 1024)}KB)`, authCheck);
      return json({ ok: true, r2_key: r2Key, size: pdfBytes.byteLength });
    }

    // ── POST /api/contratos/:id/enviar-assinatura — Assinafy + WhatsApp ──
    const contratoEnviarMatch = path.match(/^\/api\/contratos\/(\d+)\/enviar-assinatura$/);
    if (method === 'POST' && contratoEnviarMatch) {
      const authCheck = await requireAuth(request, env, ['admin', 'atendente']);
      if (authCheck instanceof Response) return authCheck;
      const id = parseInt(contratoEnviarMatch[1]);

      const contract = await env.DB.prepare('SELECT * FROM contracts WHERE id=?').bind(id).first();
      if (!contract) return err('Contrato não encontrado', 404);
      if (!contract.generated_pdf_key) return err('Gere o PDF antes de enviar para assinatura', 400);
      if (['waiting', 'partially_signed'].includes(contract.status)) {
        return err('Contrato já está aguardando assinaturas', 400);
      }

      const signers = await env.DB.prepare(
        'SELECT * FROM contract_signers WHERE contract_id=? ORDER BY id'
      ).bind(id).all().then(r => r.results || []);
      if (signers.length === 0) return err('Adicione signatários antes de enviar', 400);

      try {
        // 1. Download PDF from R2
        const pdfObject = await env.BUCKET.get(contract.generated_pdf_key);
        if (!pdfObject) return err('PDF não encontrado no R2', 404);
        const pdfBytes = await pdfObject.arrayBuffer();

        // 2. Upload to Assinafy
        const uploadResult = await assinaryUploadDocument(env, pdfBytes, `Comodato_${contract.numero}.pdf`);
        const docId = uploadResult.id || uploadResult.data?.id;
        if (!docId) throw new Error('Assinafy não retornou document ID');

        console.log(`[assinafy] Document uploaded: ${docId}`);

        // 3. Wait for document processing (poll status)
        // Assinafy needs a moment to process the PDF
        await new Promise(r => setTimeout(r, 2000));

        // 4. Create signers in Assinafy and collect their IDs
        const assinarySignerIds = [];
        for (const signer of signers) {
          const created = await assinaryCreateSigner(env, signer);
          const signerId = created.id;
          assinarySignerIds.push(signerId);
          await env.DB.prepare(
            'UPDATE contract_signers SET assinafy_signer_id=? WHERE id=?'
          ).bind(signerId, signer.id).run();
          console.log(`[assinafy] Signer created: ${signerId} (${signer.nome})`);
        }

        // 5. Create assignment (virtual — no input fields needed)
        const assignment = await assinaryCreateAssignment(env, docId, assinarySignerIds);
        const assignmentId = assignment.id;
        const signingUrls = assignment.signing_urls || [];

        console.log(`[assinafy] Assignment created: ${assignmentId}, ${signingUrls.length} URLs`);

        // 6. Save signing URLs to each signer
        for (const su of signingUrls) {
          await env.DB.prepare(
            'UPDATE contract_signers SET signing_url=? WHERE contract_id=? AND assinafy_signer_id=?'
          ).bind(su.url, id, su.signer_id).run();
        }

        // 7. Update contract with Assinafy IDs
        await env.DB.prepare(
          "UPDATE contracts SET assinafy_doc_id=?, assinafy_assignment_id=?, status='waiting', assinafy_error=NULL, updated_at=unixepoch() WHERE id=?"
        ).bind(docId, assignmentId, id).run();

        // 8. Send WhatsApp notifications via IzChat
        const whatsappResults = [];
        for (const signer of signers) {
          const su = signingUrls.find(s => {
            const dbSigner = signers.find(ds => ds.assinafy_signer_id === s.signer_id);
            return dbSigner && dbSigner.id === signer.id;
          });
          const signingUrl = su?.url;
          const phone = signer.telefone?.replace(/\D/g, '');

          if (phone && phone.length >= 10 && signingUrl) {
            try {
              const msg = `📋 *MoskoGás — Contrato de Comodato*\n\nOlá ${signer.nome.split(' ')[0]}!\n\nVocê tem um contrato de comodato (${contract.numero}) para assinar digitalmente.\n\n🔗 Clique para assinar:\n${signingUrl}\n\n📌 Após clicar, siga as instruções na tela.\n\nObrigado!`;
              const izResult = await sendWhatsApp(env, `55${phone}`, msg, { category: 'contrato' });
              if (izResult.ok) {
                await env.DB.prepare('UPDATE contract_signers SET whatsapp_sent_at=unixepoch() WHERE id=?').bind(signer.id).run();
              }
              whatsappResults.push({ nome: signer.nome, sent: izResult.ok });
            } catch (wzErr) {
              whatsappResults.push({ nome: signer.nome, sent: false, error: wzErr.message });
            }
          } else {
            whatsappResults.push({ nome: signer.nome, sent: false, reason: 'sem telefone ou URL' });
          }
        }

        await logContractEvent(env, id, 'sent_for_signature', `Enviado para ${signers.length} signatários via Assinafy`, authCheck);
        return json({ ok: true, assinafy_doc_id: docId, assignment_id: assignmentId, signing_urls: signingUrls, whatsapp: whatsappResults });
      } catch (e) {
        console.error('[assinafy] Error:', e.message);
        await env.DB.prepare(
          "UPDATE contracts SET assinafy_error=?, updated_at=unixepoch() WHERE id=?"
        ).bind(e.message, id).run();
        await logContractEvent(env, id, 'signature_error', e.message, authCheck);
        return err(`Erro ao enviar para Assinafy: ${e.message}`, 500);
      }
    }

    // ── POST /api/contratos/:id/reenviar-links — Reenviar WhatsApp ──
    const contratoReenviarMatch = path.match(/^\/api\/contratos\/(\d+)\/reenviar-links$/);
    if (method === 'POST' && contratoReenviarMatch) {
      const authCheck = await requireAuth(request, env, ['admin', 'atendente']);
      if (authCheck instanceof Response) return authCheck;
      const id = parseInt(contratoReenviarMatch[1]);

      const contract = await env.DB.prepare('SELECT * FROM contracts WHERE id=?').bind(id).first();
      if (!contract) return err('Contrato não encontrado', 404);
      if (!['waiting', 'partially_signed'].includes(contract.status)) return err('Contrato não está aguardando assinaturas', 400);

      const signers = await env.DB.prepare(
        "SELECT * FROM contract_signers WHERE contract_id=? AND status='pending'"
      ).bind(id).all().then(r => r.results || []);

      const body = await request.json().catch(() => ({}));
      const signerId = body.signer_id; // optional: resend to specific signer

      const results = [];
      for (const signer of signers) {
        if (signerId && signer.id !== signerId) continue;
        const phone = signer.telefone?.replace(/\D/g, '');
        if (!phone || phone.length < 10 || !signer.signing_url) continue;

        // Also resend via Assinafy email
        if (signer.assinafy_signer_id && contract.assinafy_doc_id && contract.assinafy_assignment_id) {
          await assinaryResendToSigner(env, contract.assinafy_doc_id, contract.assinafy_assignment_id, signer.assinafy_signer_id).catch(() => { });
        }

        try {
          const msg = `📋 *Lembrete — Contrato de Comodato*\n\nOlá ${signer.nome.split(' ')[0]}!\n\nSeu contrato (${contract.numero}) ainda aguarda sua assinatura.\n\n🔗 Clique para assinar:\n${signer.signing_url}\n\nObrigado!`;
          const izResult = await sendWhatsApp(env, `55${phone}`, msg, { category: 'contrato' });
          await env.DB.prepare('UPDATE contract_signers SET whatsapp_sent_at=unixepoch() WHERE id=?').bind(signer.id).run();
          results.push({ nome: signer.nome, sent: izResult.ok });
        } catch (e) {
          results.push({ nome: signer.nome, sent: false, error: e.message });
        }
      }

      await logContractEvent(env, id, 'links_resent', `Links reenviados para ${results.length} signatário(s)`, authCheck);
      return json({ ok: true, results });
    }

    // ── POST /api/contratos/:id/cancelar — Cancelar ───────────
    const contratoCancelarMatch = path.match(/^\/api\/contratos\/(\d+)\/cancelar$/);
    if (method === 'POST' && contratoCancelarMatch) {
      const authCheck = await requireAuth(request, env, ['admin']);
      if (authCheck instanceof Response) return authCheck;
      const id = parseInt(contratoCancelarMatch[1]);

      const contract = await env.DB.prepare('SELECT * FROM contracts WHERE id=?').bind(id).first();
      if (!contract) return err('Contrato não encontrado', 404);
      if (contract.status === 'canceled') return err('Já está cancelado', 400);

      const body = await request.json();
      if (!body.motivo) return err('Motivo obrigatório para cancelar');

      await env.DB.prepare(
        "UPDATE contracts SET status='canceled', cancel_motivo=?, canceled_at=unixepoch(), updated_at=unixepoch() WHERE id=?"
      ).bind(body.motivo, id).run();

      await logContractEvent(env, id, 'canceled', `Cancelado: ${body.motivo}`, authCheck);
      return json({ ok: true });
    }

    // ── GET /api/contratos/:id/status-assinatura — Poll Assinafy ──
    const contratoStatusMatch = path.match(/^\/api\/contratos\/(\d+)\/status-assinatura$/);
    if (method === 'GET' && contratoStatusMatch) {
      const authCheck = await requireAuth(request, env, ['admin', 'atendente']);
      if (authCheck instanceof Response) return authCheck;
      const id = parseInt(contratoStatusMatch[1]);

      const contract = await env.DB.prepare('SELECT assinafy_doc_id, status FROM contracts WHERE id=?').bind(id).first();
      if (!contract) return err('Contrato não encontrado', 404);
      if (!contract.assinafy_doc_id) return json({ ok: true, status: contract.status, message: 'Ainda não enviado para assinatura' });

      // Get fresh status from Assinafy
      try {
        const doc = await assinaryGetDocument(env, contract.assinafy_doc_id);
        const signers = await env.DB.prepare('SELECT * FROM contract_signers WHERE contract_id=?').bind(id).all().then(r => r.results || []);
        return json({
          ok: true,
          local_status: contract.status,
          assinafy_status: doc?.status || 'unknown',
          assinafy_assignment: doc?.assignment || null,
          signers,
        });
      } catch (e) {
        return json({ ok: true, local_status: contract.status, error: e.message });
      }
    }

    // ── GET /api/contratos/:id/pdf — Download PDF do R2 ───────
    const contratoPdfMatch = path.match(/^\/api\/contratos\/(\d+)\/pdf$/);
    if (method === 'GET' && contratoPdfMatch) {
      const authCheck = await requireAuth(request, env, ['admin', 'atendente']);
      if (authCheck instanceof Response) return authCheck;
      const id = parseInt(contratoPdfMatch[1]);

      const type = url.searchParams.get('type') || 'generated'; // generated or signed
      const contract = await env.DB.prepare('SELECT generated_pdf_key, signed_pdf_key, numero FROM contracts WHERE id=?').bind(id).first();
      if (!contract) return err('Contrato não encontrado', 404);

      const key = type === 'signed' ? contract.signed_pdf_key : contract.generated_pdf_key;
      if (!key) return err(`PDF ${type} não encontrado`, 404);

      const obj = await env.BUCKET.get(key);
      if (!obj) return err('Arquivo não encontrado no R2', 404);

      return new Response(obj.body, {
        headers: {
          'Content-Type': 'application/pdf',
          'Content-Disposition': `inline; filename="Comodato_${contract.numero}_${type}.pdf"`,
          ...CORS_HEADERS,
        },
      });
    }

    // ════════════════════════════════════════════════════════
    // EMPENHOS GOV (v2.41.0)
    // ════════════════════════════════════════════════════════
    if (path.startsWith('/api/empenhos')) {
      await ensureEmpenhoTables(env);
      const authCheck = await requireAuth(request, env, ['admin', 'atendente']);
      if (authCheck instanceof Response) return authCheck;
      const user = authCheck;

      // ── Helpers ──────────────────────────────────────────
      async function getEmpenhoComSaldo(id) {
        const e = await env.DB.prepare('SELECT * FROM gov_empenhos WHERE id=?').bind(id).first();
        if (!e) return null;
        const itens = await env.DB.prepare('SELECT * FROM gov_empenho_itens WHERE empenho_id=?').bind(id).all().then(r => r.results || []);
        const arquivos = await env.DB.prepare('SELECT * FROM gov_empenho_arquivos WHERE empenho_id=?').bind(id).all().then(r => r.results || []);
        // Calcular saldo por item
        const itensComSaldo = itens.map(it => ({
          ...it,
          quantidade_saldo: it.quantidade_total - it.quantidade_usada,
          pct_usado: it.quantidade_total > 0 ? Math.round(it.quantidade_usada / it.quantidade_total * 100) : 0,
          alerta: it.quantidade_total > 0 && (it.quantidade_total - it.quantidade_usada) <= Math.max(10, Math.ceil(it.quantidade_total * 0.1))
        }));
        const temAlerta = itensComSaldo.some(it => it.alerta);
        return { ...e, itens: itensComSaldo, arquivos, tem_alerta: temAlerta };
      }



      // ── GET /api/empenhos — listar ────────────────────────
      if (method === 'GET' && path === '/api/empenhos') {
        const status = url.searchParams.get('status') || 'ativo';
        const q = url.searchParams.get('q') || '';
        let sql = 'SELECT * FROM gov_empenhos WHERE 1=1';
        const p = [];
        if (status !== 'todos') { sql += ' AND status=?'; p.push(status); }
        if (q) { sql += ' AND (numero LIKE ? OR cliente_nome LIKE ?)'; p.push(`%${q}%`, `%${q}%`); }
        sql += ' ORDER BY created_at DESC LIMIT 100';
        const rows = await env.DB.prepare(sql).bind(...p).all().then(r => r.results || []);
        // Enriquecer com itens/saldo
        const result = [];
        for (const e of rows) {
          const itens = await env.DB.prepare('SELECT * FROM gov_empenho_itens WHERE empenho_id=?').bind(e.id).all().then(r => r.results || []);
          const temAlerta = itens.some(it => it.quantidade_total > 0 && (it.quantidade_total - it.quantidade_usada) <= Math.max(10, Math.ceil(it.quantidade_total * 0.1)));
          result.push({ ...e, itens, tem_alerta: temAlerta });
        }
        return json(result);
      }

      // ── POST /api/empenhos — criar ────────────────────────
      if (method === 'POST' && path === '/api/empenhos') {
        const body = await request.json();
        const { numero, cliente_nome, cliente_phone, bling_contact_id, data_emissao, data_validade, valor_total, observacoes, itens } = body;
        if (!numero || !cliente_nome || !bling_contact_id) return err('Número, cliente e Bling ID são obrigatórios');
        const ins = await env.DB.prepare(
          `INSERT INTO gov_empenhos (numero, cliente_nome, cliente_phone, bling_contact_id, data_emissao, data_validade, valor_total, observacoes, created_by, created_by_nome)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        ).bind(numero, cliente_nome, cliente_phone || null, bling_contact_id, data_emissao || null, data_validade || null, parseFloat(valor_total) || 0, observacoes || null, user.id, user.nome).run();
        const empenhoId = ins.meta?.last_row_id;
        // Inserir itens
        if (itens && itens.length > 0) {
          for (const it of itens) {
            await env.DB.prepare(`INSERT INTO gov_empenho_itens (empenho_id, produto_nome, produto_bling_id, quantidade_total, preco_unitario) VALUES (?, ?, ?, ?, ?)`)
              .bind(empenhoId, it.produto_nome, it.produto_bling_id || null, parseInt(it.quantidade_total) || 0, parseFloat(it.preco_unitario) || 0).run();
          }
        }
        return json({ ok: true, id: empenhoId });
      }

      // ── DEBUG temporário empenhos ─────────────────────────────────
      if (method === 'GET' && path === '/api/empenhos/debug') {
        const phone = url.searchParams.get('phone') || '';
        const digits = phone.replace(/\D/g, '');
        const cc = await env.DB.prepare('SELECT phone_digits, bling_contact_id, name FROM customers_cache WHERE phone_digits=?').bind(digits).first().catch(() => null);
        const empenhos = await env.DB.prepare('SELECT id, numero, cliente_nome, cliente_phone, bling_contact_id, status FROM gov_empenhos WHERE status=\'ativo\'').all().then(r => r.results || []);
        return json({ digits, cc, empenhos });
      }

      // ── GET /api/empenhos/cliente/bling/:blingId — por bling_contact_id ──
      const blingMatch = path.match(/^\/api\/empenhos\/cliente\/bling\/(.+)$/);
      if (method === 'GET' && blingMatch) {
        const blingId = blingMatch[1].trim();
        const rows = await env.DB.prepare(
          `SELECT e.* FROM gov_empenhos e WHERE e.status='ativo' AND e.bling_contact_id=? ORDER BY e.created_at DESC`
        ).bind(blingId).all().then(r => r.results || []);
        const result = [];
        for (const e of rows) {
          const itens = await env.DB.prepare('SELECT * FROM gov_empenho_itens WHERE empenho_id=?').bind(e.id).all().then(r => r.results || []);
          result.push({ ...e, itens });
        }
        return json(result);
      }

      // ── GET /api/empenhos/cliente/:phone ──
      const clienteMatch = path.match(/^\/api\/empenhos\/cliente\/(.+)$/);
      if (method === 'GET' && clienteMatch) {
        const phone = clienteMatch[1].replace(/\D/g, '');
        // Busca o bling_contact_id do cliente pelo phone (para buscar empenhos cadastrados pelo ID Bling)
        const cc = await env.DB.prepare('SELECT bling_contact_id FROM customers_cache WHERE phone_digits=?').bind(phone).first().catch(() => null);
        const blingId = cc?.bling_contact_id ? String(cc.bling_contact_id) : null;
        const rows = await env.DB.prepare(
          `SELECT e.* FROM gov_empenhos e
           WHERE e.status='ativo'
             AND (e.cliente_phone=? OR (? IS NOT NULL AND e.bling_contact_id=?))
           ORDER BY e.created_at DESC`
        ).bind(phone, blingId, blingId).all().then(r => r.results || []);
        const result = [];
        for (const e of rows) {
          const itens = await env.DB.prepare('SELECT * FROM gov_empenho_itens WHERE empenho_id=?').bind(e.id).all().then(r => r.results || []);
          result.push({ ...e, itens });
        }
        return json(result);
      }

      // ── GET /api/empenhos/:id — detalhe ──────────────────
      const empIdMatch = path.match(/^\/api\/empenhos\/(\d+)$/);
      if (method === 'GET' && empIdMatch) {
        const e = await getEmpenhoComSaldo(parseInt(empIdMatch[1]));
        if (!e) return err('Empenho não encontrado', 404);
        return json(e);
      }

      // ── PATCH /api/empenhos/:id — editar ─────────────────
      if (method === 'PATCH' && empIdMatch) {
        const id = parseInt(empIdMatch[1]);
        const body = await request.json();
        const { numero, cliente_nome, cliente_phone, bling_contact_id, data_emissao, data_validade, valor_total, observacoes, status } = body;
        await env.DB.prepare(
          `UPDATE gov_empenhos SET numero=COALESCE(?,numero), cliente_nome=COALESCE(?,cliente_nome), cliente_phone=COALESCE(?,cliente_phone),
           bling_contact_id=COALESCE(?,bling_contact_id), data_emissao=COALESCE(?,data_emissao), data_validade=COALESCE(?,data_validade),
           valor_total=COALESCE(?,valor_total), observacoes=COALESCE(?,observacoes), status=COALESCE(?,status), updated_at=unixepoch()
           WHERE id=?`
        ).bind(numero || null, cliente_nome || null, cliente_phone || null, bling_contact_id || null, data_emissao || null, data_validade || null,
          valor_total != null ? parseFloat(valor_total) : null, observacoes || null, status || null, id).run();
        return json({ ok: true });
      }

      // ── POST /api/empenhos/:id/upload-pdf ─────────────────
      if (method === 'POST' && path.match(/^\/api\/empenhos\/(\d+)\/upload-pdf$/)) {
        const id = parseInt(path.match(/\/empenhos\/(\d+)\//)[1]);
        const formData = await request.formData();
        const file = formData.get('arquivo');
        if (!file) return err('Arquivo não enviado');
        const bytes = await file.arrayBuffer();
        const r2Key = `empenhos/${id}/${Date.now()}_${file.name}`;
        await env.BUCKET.put(r2Key, bytes, { httpMetadata: { contentType: file.type || 'application/pdf' } });
        const ins = await env.DB.prepare(`INSERT INTO gov_empenho_arquivos (empenho_id, nome_arquivo, r2_key, bytes) VALUES (?, ?, ?, ?)`)
          .bind(id, file.name, r2Key, bytes.byteLength).run();
        return json({ ok: true, id: ins.meta?.last_row_id, nome: file.name, r2_key: r2Key });
      }

      // ── DELETE /api/empenhos/:id/arquivos/:fid ────────────
      const delArqMatch = path.match(/^\/api\/empenhos\/(\d+)\/arquivos\/(\d+)$/);
      if (method === 'DELETE' && delArqMatch) {
        const [, empId, fid] = delArqMatch;
        const arq = await env.DB.prepare('SELECT r2_key FROM gov_empenho_arquivos WHERE id=? AND empenho_id=?').bind(parseInt(fid), parseInt(empId)).first();
        if (arq?.r2_key) await env.BUCKET.delete(arq.r2_key).catch(() => { });
        await env.DB.prepare('DELETE FROM gov_empenho_arquivos WHERE id=?').bind(parseInt(fid)).run();
        return json({ ok: true });
      }

      // ── GET /api/empenhos/:id/pdf/:fid — download PDF ─────
      const getPdfMatch = path.match(/^\/api\/empenhos\/(\d+)\/pdf\/(\d+)$/);
      if (method === 'GET' && getPdfMatch) {
        const [, empId, fid] = getPdfMatch;
        const arq = await env.DB.prepare('SELECT * FROM gov_empenho_arquivos WHERE id=? AND empenho_id=?').bind(parseInt(fid), parseInt(empId)).first();
        if (!arq) return err('Arquivo não encontrado', 404);
        const obj = await env.BUCKET.get(arq.r2_key);
        if (!obj) return err('Arquivo não encontrado no storage', 404);
        return new Response(obj.body, { headers: { 'Content-Type': 'application/pdf', 'Content-Disposition': `inline; filename="${arq.nome_arquivo}"` } });
      }

      // ── POST /api/empenhos/:id/vincular-venda — abater saldo ──
      if (method === 'POST' && path.match(/^\/api\/empenhos\/(\d+)\/vincular-venda$/)) {
        const id = parseInt(path.match(/\/empenhos\/(\d+)\//)[1]);
        const body = await request.json();
        const { order_id, itens_vendidos } = body; // itens_vendidos: [{produto_nome, qty}]
        if (!order_id || !itens_vendidos?.length) return err('Dados inválidos');

        // Verificar empenho
        const empenho = await env.DB.prepare('SELECT * FROM gov_empenhos WHERE id=? AND status=?').bind(id, 'ativo').first();
        if (!empenho) return err('Empenho não encontrado ou inativo', 404);

        // Abater cada item
        const qtdJson = {};
        for (const iv of itens_vendidos) {
          const item = await env.DB.prepare(`SELECT * FROM gov_empenho_itens WHERE empenho_id=? AND produto_nome=?`).bind(id, iv.produto_nome).first();
          if (!item) continue;
          const saldo = item.quantidade_total - item.quantidade_usada;
          if (iv.qty > saldo) return err(`Saldo insuficiente para ${iv.produto_nome}: saldo ${saldo}, pedido ${iv.qty}`, 400);
          await env.DB.prepare(`UPDATE gov_empenho_itens SET quantidade_usada=quantidade_usada+? WHERE id=?`).bind(iv.qty, item.id).run();
          qtdJson[iv.produto_nome] = iv.qty;
          // Verificar alerta após abate
          const itemAtualizado = { ...item, quantidade_usada: item.quantidade_usada + iv.qty };
          await alertarSaldoBaixo(env, empenho, itemAtualizado).catch(() => { });
        }

        // Registrar venda
        await env.DB.prepare(`INSERT INTO gov_empenho_vendas (empenho_id, order_id, quantidade_json) VALUES (?, ?, ?)`)
          .bind(id, order_id, JSON.stringify(qtdJson)).run();

        // Salvar empenho_id no pedido
        await env.DB.prepare(`UPDATE orders SET notes=CASE WHEN notes IS NULL OR notes='' THEN ? ELSE notes||' | '||? END WHERE id=?`)
          .bind(`[Empenho: ${empenho.numero}]`, `[Empenho: ${empenho.numero}]`, order_id).run().catch(() => { });

        // Verificar se todos itens esgotados → fechar empenho
        const todosItens = await env.DB.prepare('SELECT * FROM gov_empenho_itens WHERE empenho_id=?').bind(id).all().then(r => r.results || []);
        const todosEsgotados = todosItens.every(it => it.quantidade_usada >= it.quantidade_total);
        if (todosEsgotados) await env.DB.prepare(`UPDATE gov_empenhos SET status='esgotado', updated_at=unixepoch() WHERE id=?`).bind(id).run();

        return json({ ok: true, qtd_abatida: qtdJson });
      }

      // ── GET /api/empenhos/:id/historico ───────────────────
      if (method === 'GET' && path.match(/^\/api\/empenhos\/(\d+)\/historico$/)) {
        const id = parseInt(path.match(/\/empenhos\/(\d+)\//)[1]);
        const vendas = await env.DB.prepare(
          `SELECT ev.*, o.customer_name, o.created_at as pedido_data, o.tipo_pagamento, o.total_value, o.status as pedido_status
           FROM gov_empenho_vendas ev
           LEFT JOIN orders o ON o.id = ev.order_id
           WHERE ev.empenho_id=? ORDER BY ev.created_at DESC`
        ).bind(id).all().then(r => r.results || []);
        return json(vendas);
      }

      // ── POST /api/empenhos/:id/itens — add/replace itens ─
      if (method === 'POST' && path.match(/^\/api\/empenhos\/(\d+)\/itens$/)) {
        const id = parseInt(path.match(/\/empenhos\/(\d+)\//)[1]);
        const { itens } = await request.json();
        // Deletar itens sem uso e reinserir
        await env.DB.prepare('DELETE FROM gov_empenho_itens WHERE empenho_id=? AND quantidade_usada=0').bind(id).run();
        for (const it of (itens || [])) {
          const exists = await env.DB.prepare('SELECT id FROM gov_empenho_itens WHERE empenho_id=? AND produto_nome=?').bind(id, it.produto_nome).first();
          if (exists) {
            await env.DB.prepare('UPDATE gov_empenho_itens SET quantidade_total=?, preco_unitario=? WHERE id=?').bind(parseInt(it.quantidade_total) || 0, parseFloat(it.preco_unitario) || 0, exists.id).run();
          } else {
            await env.DB.prepare('INSERT INTO gov_empenho_itens (empenho_id, produto_nome, produto_bling_id, quantidade_total, preco_unitario) VALUES (?,?,?,?,?)')
              .bind(id, it.produto_nome, it.produto_bling_id || null, parseInt(it.quantidade_total) || 0, parseFloat(it.preco_unitario) || 0).run();
          }
        }
        return json({ ok: true });
      }
    }

    // ═══════════════════════════════════════════════════════════
    // ─── ESTOQUE — Controle Diário de Gás (v2.42.0) ─────────
    // ═══════════════════════════════════════════════════════════

    if (path.startsWith('/api/estoque')) {
      const authCheck = await requireAuth(request, env, ['admin', 'atendente']);
      if (authCheck instanceof Response) return authCheck;
      await ensureStockTables(env);
      const userName = authCheck.nome || 'Sistema';

      if (method === 'GET' && path === '/api/estoque/dia') {
        const data = url.searchParams.get('data') || new Date().toISOString().slice(0, 10);
        const tipos = ['P13', 'P20', 'P45', 'P05'];
        const rows = await env.DB.prepare('SELECT * FROM stock_daily WHERE data = ?').bind(data).all().then(r => r.results || []);
        const byTipo = {}; for (const r of rows) byTipo[r.tipo] = r;
        const ontem = new Date(data + 'T12:00:00Z'); ontem.setDate(ontem.getDate() - 1);
        const dataOntem = ontem.toISOString().slice(0, 10);
        const rowsOntem = await env.DB.prepare('SELECT * FROM stock_daily WHERE data = ?').bind(dataOntem).all().then(r => r.results || []);
        const ontemByTipo = {}; for (const r of rowsOntem) ontemByTipo[r.tipo] = r;
        const vendasOntem = await calcVendasAuto(env, dataOntem);
        const vendasHoje = await calcVendasAuto(env, data);
        const resultado = tipos.map(tipo => {
          const hoje = byTipo[tipo] || {}, ont = ontemByTipo[tipo] || {};
          const cheios_manha = hoje.cheios_manha ?? null, vazios_manha = hoje.vazios_manha ?? null;
          const ont_cheios = ont.cheios_manha ?? null, ont_vazios = ont.vazios_manha ?? null;
          const ont_compras = ont.compras || 0, ont_vendas = vendasOntem[tipo] || 0;
          const cheios_esperado = ont_cheios !== null ? ont_cheios + ont_compras - ont_vendas : null;
          const vazios_esperado = ont_vazios !== null ? ont_vazios - ont_compras + ont_vendas : null;
          let div_cheios = null, div_vazios = null;
          if (cheios_manha !== null && cheios_esperado !== null) div_cheios = cheios_manha - cheios_esperado;
          if (vazios_manha !== null && vazios_esperado !== null) div_vazios = vazios_manha - vazios_esperado;
          const total_vasil_ontem = ont_cheios !== null ? ont_cheios + (ont_vazios || 0) : null;
          const ont_cd = ont.cascos_devolucao || 0, ont_ce = ont.cascos_emprestimo || 0, ont_cv = ont.cascos_venda || 0, ont_ca = ont.cascos_aquisicao || 0;
          const total_vasil_esperado = total_vasil_ontem !== null ? total_vasil_ontem + ont_cd + ont_ca - ont_ce - ont_cv : null;
          const total_vasil_real = cheios_manha !== null ? cheios_manha + (vazios_manha || 0) : null;
          let div_vasil = null;
          if (total_vasil_esperado !== null && total_vasil_real !== null) div_vasil = total_vasil_real - total_vasil_esperado;
          return {
            tipo, data, cheios_manha, vazios_manha, contagem_manha_por: hoje.contagem_manha_por || null, contagem_manha_at: hoje.contagem_manha_at || null,
            compras_hoje: hoje.compras || 0, vendas_hoje: vendasHoje[tipo] || 0,
            cascos_devolucao: hoje.cascos_devolucao || 0, cascos_emprestimo: hoje.cascos_emprestimo || 0, cascos_venda: hoje.cascos_venda || 0, cascos_aquisicao: hoje.cascos_aquisicao || 0,
            observacao: hoje.observacao || '', ontem_cheios: ont_cheios, ontem_vazios: ont_vazios, ontem_compras: ont_compras, ontem_vendas: ont_vendas,
            ontem_cascos_dev: ont_cd, ontem_cascos_emp: ont_ce, ontem_cascos_venda: ont_cv, ontem_cascos_aquis: ont_ca,
            cheios_esperado, vazios_esperado, div_cheios, div_vazios, total_vasil_ontem, total_vasil_esperado, total_vasil_real, div_vasil, tem_ontem: ont_cheios !== null
          };
        });
        return json({ ok: true, data, resultado });
      }

      if (method === 'POST' && path === '/api/estoque/contagem') {
        const body = await request.json();
        const data = body.data || new Date().toISOString().slice(0, 10);
        const contagens = body.contagens || {};
        const tipos = ['P13', 'P20', 'P45', 'P05'];
        const now = new Date().toISOString();
        const divergencias = [];
        const ontem = new Date(data + 'T12:00:00Z'); ontem.setDate(ontem.getDate() - 1);
        const dataOntem = ontem.toISOString().slice(0, 10);
        const rowsOntem = await env.DB.prepare('SELECT * FROM stock_daily WHERE data = ?').bind(dataOntem).all().then(r => r.results || []);
        const ontemByTipo = {}; for (const r of rowsOntem) ontemByTipo[r.tipo] = r;
        const vendasOntem = await calcVendasAuto(env, dataOntem);
        for (const tipo of tipos) {
          const c = contagens[tipo]; if (!c) continue;
          const cheios = parseInt(c.cheios) || 0, vazios = parseInt(c.vazios) || 0;
          await env.DB.prepare(`INSERT INTO stock_daily (data, tipo, cheios_manha, vazios_manha, contagem_manha_por, contagem_manha_at) VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(data, tipo) DO UPDATE SET cheios_manha=excluded.cheios_manha, vazios_manha=excluded.vazios_manha, contagem_manha_por=excluded.contagem_manha_por, contagem_manha_at=excluded.contagem_manha_at, updated_at=datetime('now')
          `).bind(data, tipo, cheios, vazios, userName, now).run();
          const ont = ontemByTipo[tipo] || {};
          if (ont.cheios_manha !== null && ont.cheios_manha !== undefined) {
            const ont_compras = ont.compras || 0, ont_vendas = vendasOntem[tipo] || 0;
            const esp_c = ont.cheios_manha + ont_compras - ont_vendas, esp_v = (ont.vazios_manha || 0) - ont_compras + ont_vendas;
            if (cheios - esp_c !== 0) divergencias.push({ tipo, campo: 'cheios', expected: esp_c, real: cheios, diff: cheios - esp_c });
            if (vazios - esp_v !== 0) divergencias.push({ tipo, campo: 'vazios', expected: esp_v, real: vazios, diff: vazios - esp_v });
            const tv_o = ont.cheios_manha + (ont.vazios_manha || 0);
            const tv_e = tv_o + (ont.cascos_devolucao || 0) + (ont.cascos_aquisicao || 0) - (ont.cascos_emprestimo || 0) - (ont.cascos_venda || 0);
            if (cheios + vazios - tv_e !== 0) divergencias.push({ tipo, campo: 'vasilhames', expected: tv_e, real: cheios + vazios, diff: cheios + vazios - tv_e });
          }
        }
        if (divergencias.length > 0) {
          try {
            let divMsg = `⚠️ *DIVERGÊNCIA ESTOQUE* — ${data}\n\n`;
            for (const d of divergencias) divMsg += `${d.tipo} ${d.campo}: esperado ${d.expected}, contou ${d.real} (${d.diff > 0 ? '+' : ''}${d.diff})\n`;
            divMsg += `\nContagem por: ${userName}`;
            const admins = await env.DB.prepare("SELECT telefone FROM app_users WHERE role='admin' AND ativo=1 AND recebe_whatsapp=1 AND telefone IS NOT NULL AND telefone != ''").all().then(r => r.results || []);
            for (const adm of admins) await sendWhatsApp(env, adm.telefone, divMsg, { category: 'admin_alerta', skipSafety: true });
            for (const tipo of tipos) await env.DB.prepare('UPDATE stock_daily SET divergencia_notificada=1 WHERE data=? AND tipo=?').bind(data, tipo).run().catch(() => { });
          } catch (e) { console.error('[estoque] WhatsApp erro:', e.message); }
        }
        return json({ ok: true, data, contagens_salvas: Object.keys(contagens).length, divergencias, total_divergencias: divergencias.length });
      }

      if (method === 'POST' && path === '/api/estoque/compras') {
        const body = await request.json(); const data = body.data || new Date().toISOString().slice(0, 10); const compras = body.compras || {}; let total = 0;
        for (const tipo of ['P13', 'P20', 'P45', 'P05']) {
          const qty = parseInt(compras[tipo]) || 0; if (!qty) continue; total += qty;
          await env.DB.prepare('INSERT INTO stock_daily (data,tipo,compras) VALUES (?,?,?) ON CONFLICT(data,tipo) DO UPDATE SET compras=excluded.compras, updated_at=datetime(\'now\')').bind(data, tipo, qty).run();
        }
        return json({ ok: true, data, total_compras: total });
      }

      if (method === 'POST' && path === '/api/estoque/cascos') {
        const body = await request.json(); const data = body.data || new Date().toISOString().slice(0, 10); const cascos = body.cascos || {};
        for (const tipo of ['P13', 'P20', 'P45', 'P05']) {
          const c = cascos[tipo]; if (!c) continue;
          await env.DB.prepare(`INSERT INTO stock_daily (data,tipo,cascos_devolucao,cascos_emprestimo,cascos_venda,cascos_aquisicao) VALUES (?,?,?,?,?,?)
            ON CONFLICT(data,tipo) DO UPDATE SET cascos_devolucao=excluded.cascos_devolucao, cascos_emprestimo=excluded.cascos_emprestimo, cascos_venda=excluded.cascos_venda, cascos_aquisicao=excluded.cascos_aquisicao, updated_at=datetime('now')
          `).bind(data, tipo, parseInt(c.devolucao) || 0, parseInt(c.emprestimo) || 0, parseInt(c.venda) || 0, parseInt(c.aquisicao) || 0).run();
        }
        return json({ ok: true, data });
      }

      if (method === 'POST' && path === '/api/estoque/observacao') {
        const body = await request.json(); const data = body.data || new Date().toISOString().slice(0, 10); const obs = body.observacao || '';
        for (const tipo of ['P13', 'P20', 'P45', 'P05']) await env.DB.prepare('INSERT INTO stock_daily (data,tipo,observacao) VALUES (?,?,?) ON CONFLICT(data,tipo) DO UPDATE SET observacao=excluded.observacao, updated_at=datetime(\'now\')').bind(data, tipo, obs).run();
        return json({ ok: true, data, observacao: obs });
      }

      if (method === 'GET' && path === '/api/estoque/historico') {
        const dias = parseInt(url.searchParams.get('dias') || '7');
        const rows = await env.DB.prepare(`SELECT * FROM stock_daily WHERE data >= date('now', '-${dias} days') ORDER BY data DESC, tipo ASC`).all().then(r => r.results || []);
        return json({ ok: true, dias, registros: rows });
      }

      if (method === 'GET' && path === '/api/estoque/bling-compras') {
        const data = url.searchParams.get('data') || new Date().toISOString().slice(0, 10);
        const mapRow = await env.DB.prepare("SELECT value FROM app_config WHERE key='estoque_mapeamento'").first().catch(() => null);
        let mapeamento = {}; try { mapeamento = JSON.parse(mapRow?.value || '{}'); } catch { }
        try {
          const nfeResp = await blingFetch(`/nfe?tipo=0&situacao=5&dataEmissaoInicial=${data}&dataEmissaoFinal=${data}&pagina=1&limite=50`, {}, env);
          if (!nfeResp.ok) { const t = await nfeResp.text().catch(() => ''); return json({ ok: false, error: `Bling NFe ${nfeResp.status}: ${t.substring(0, 200)}` }); }
          const notas = (await nfeResp.json()).data || [];
          const compras = { P13: 0, P20: 0, P45: 0, P05: 0 }; const notasDet = []; let notasComGas = 0;
          for (const nfe of notas) {
            let items = []; try { const d = await blingFetch(`/nfe/${nfe.id}`, {}, env); if (d.ok) items = (await d.json()).data?.itens || []; } catch { }
            const nc = { P13: 0, P20: 0, P45: 0, P05: 0 }; let temGas = false;
            for (const item of items) {
              const pId = String(item.produto?.id || ''), pN = (item.produto?.nome || item.descricao || '').toUpperCase(), pC = (item.produto?.codigo || '').toUpperCase(), qty = parseFloat(item.quantidade) || 0;
              let tipo = mapeamento[pId] || null;
              if (!tipo) { if (pN.includes('P13') || pC.includes('P13')) tipo = 'P13'; else if (pN.includes('P20') || pC.includes('P20')) tipo = 'P20'; else if (pN.includes('P45') || pC.includes('P45')) tipo = 'P45'; else if (pN.includes('P05') || pN.includes('P5') || pC.includes('P05') || pC.includes('P5')) tipo = 'P05'; }
              if (tipo && compras[tipo] !== undefined) { compras[tipo] += qty; nc[tipo] += qty; temGas = true; }
            }
            if (temGas) notasComGas++;
            notasDet.push({ id: nfe.id, numero: nfe.numero, fornecedor: nfe.contato?.nome || 'Desconhecido', data_emissao: nfe.dataEmissao, compras: nc, total_itens: items.length });
          }
          return json({ ok: true, data, total_notas: notas.length, notas_com_gas: notasComGas, compras, notas: notasDet });
        } catch (e) { return json({ ok: false, error: e.message }, 500); }
      }

      if (method === 'POST' && path === '/api/estoque/importar-bling') {
        const body = await request.json(); const data = body.data || new Date().toISOString().slice(0, 10); const compras = body.compras || {}; let total = 0;
        for (const tipo of ['P13', 'P20', 'P45', 'P05']) {
          const qty = parseInt(compras[tipo]) || 0; if (!qty) continue; total += qty;
          await env.DB.prepare('INSERT INTO stock_daily (data,tipo,compras) VALUES (?,?,?) ON CONFLICT(data,tipo) DO UPDATE SET compras=excluded.compras, updated_at=datetime(\'now\')').bind(data, tipo, qty).run();
        }
        await logEvent(env, 0, 'estoque_bling_import', { data, compras, total, imported_by: userName });
        return json({ ok: true, data, total_importado: total, compras });
      }

      if (method === 'GET' && path === '/api/estoque/config') {
        const row = await env.DB.prepare("SELECT value FROM app_config WHERE key='estoque_mapeamento'").first().catch(() => null);
        let m = {}; try { m = JSON.parse(row?.value || '{}'); } catch { } return json({ ok: true, mapeamento: m });
      }
      if (method === 'POST' && path === '/api/estoque/config') {
        const ac = await requireAuth(request, env, ['admin']); if (ac instanceof Response) return ac;
        const body = await request.json();
        if (body.mapeamento) await env.DB.prepare("INSERT OR REPLACE INTO app_config (key, value, updated_at) VALUES ('estoque_mapeamento', ?, datetime('now'))").bind(JSON.stringify(body.mapeamento)).run();
        return json({ ok: true });
      }

      return err('Endpoint estoque não encontrado', 404);
    }

    // ══════════════════════════════════════════════════════════════
    // ── MÓDULO VALES/TICKETS ──────────────────────────────────────
    // ══════════════════════════════════════════════════════════════
    if (path.startsWith('/api/vales')) {
      await ensureValesTables(env);
      const authCheck = await requireAuth(request, env, ['admin', 'atendente']);
      if (authCheck instanceof Response) return authCheck;

      // GET /api/vales/notas - Listar Notas criadas
      if (method === 'GET' && path === '/api/vales/notas') {
        const rows = await env.DB.prepare('SELECT * FROM notas_vales ORDER BY id DESC LIMIT 50').all().then(r => r.results || []);
        for (const n of rows) {
          const vales = await env.DB.prepare('SELECT COUNT(*) as total, SUM(CASE WHEN status="resgatado" THEN 1 ELSE 0 END) as resgatados FROM vales WHERE nota_id=?').bind(n.id).first();
          n.resgatados = vales?.resgatados || 0;
          n.total_vales = vales?.total || n.quantidade;
        }
        return json({ ok: true, notas: rows });
      }

      // GET /api/vales/notas/:id - Ver vales de uma nota
      const notaDetailMatch = path.match(/^\/api\/vales\/notas\/(\d+)$/);
      if (method === 'GET' && notaDetailMatch) {
        const notaId = parseInt(notaDetailMatch[1]);
        const nota = await env.DB.prepare('SELECT * FROM notas_vales WHERE id=?').bind(notaId).first();
        if (!nota) return err('Nota não encontrada', 404);
        const vales = await env.DB.prepare('SELECT * FROM vales WHERE nota_id=? ORDER BY id ASC').bind(notaId).all().then(r => r.results || []);
        return json({ ok: true, nota, vales });
      }

      // POST /api/vales/notas - Criar Nota e Vales
      if (method === 'POST' && path === '/api/vales/notas') {
        const body = await request.json();
        const { cliente_nome, itens, forma_pagamento, nota_fiscal, empenho, validade } = body;
        if (!cliente_nome) return err('Nome do cliente obrigatório');
        if (!itens || !Array.isArray(itens) || itens.length === 0) return err('Adicione pelo menos um produto');
        const quantidade = itens.reduce((s, it) => s + parseInt(it.quantidade || 0), 0);
        if (quantidade < 1) return err('Quantidade total deve ser maior que zero');
        let notaResult;
        try {
          notaResult = await env.DB.prepare(
            'INSERT INTO notas_vales (cliente_nome, cliente_doc, quantidade, valor_unit, total, forma_pagamento, nota_fiscal, empenho, itens_json, validade, created_by, created_by_nome) VALUES (?, ?, ?, 0, 0, ?, ?, ?, ?, ?, ?, ?)'
          ).bind(cliente_nome, '', quantidade, forma_pagamento || 'dinheiro', nota_fiscal || '', empenho || '', JSON.stringify(itens), validade || '', authCheck.id, authCheck.nome).run();
        } catch (dbErr) {
          return err('Erro ao salvar nota: ' + dbErr.message, 500);
        }
        const notaId = notaResult.meta?.last_row_id;

        // Gerar vales por produto com prefixo (P13-001, P45-001, A20-001)
        const prefixMap = { 'P13': 'P13', 'P20': 'P20', 'P45': 'P45', 'Água 20L': 'A20' };
        for (const item of itens) {
          const prefix = prefixMap[item.produto] || item.produto.replace(/\s+/g, '').toUpperCase().slice(0, 3);
          const qtd = parseInt(item.quantidade || 0);
          for (let i = 1; i <= qtd; i++) {
            const num = `${prefix}-${String(i).padStart(3, '0')}`;
            await env.DB.prepare('INSERT INTO vales (nota_id, numero, produto, status) VALUES (?, ?, ?, "pendente")').bind(notaId, num, item.produto).run();
          }
        }

        return json({ ok: true, nota_id: notaId });
      }

      // DELETE /api/vales/notas/:id — apagar nota e seus vales (admin only)
      const delNotaMatch = path.match(/^\/api\/vales\/notas\/(\d+)$/);
      if (method === 'DELETE' && delNotaMatch) {
        const adminCheck = await requireAuth(request, env, ['admin']);
        if (adminCheck instanceof Response) return adminCheck;
        const notaId = parseInt(delNotaMatch[1]);
        await env.DB.prepare('DELETE FROM vales WHERE nota_id=?').bind(notaId).run();
        await env.DB.prepare('DELETE FROM notas_vales WHERE id=?').bind(notaId).run();
        return json({ ok: true, message: 'Nota e vales apagados com sucesso.' });
      }

      // PATCH /api/vales/:id/baixa - Dar baixa
      const baixaValeMatch = path.match(/^\/api\/vales\/(\d+)\/baixa$/);
      if (method === 'PATCH' && baixaValeMatch) {
        const valeId = parseInt(baixaValeMatch[1]);
        const vale = await env.DB.prepare('SELECT * FROM vales WHERE id=?').bind(valeId).first();
        if (!vale) return err('Vale não existe', 404);
        if (vale.status === 'resgatado') return err(`Este vale já foi Resgatado em ${new Date(vale.resgatado_em * 1000).toLocaleString('pt-BR', { timeZone: 'America/Campo_Grande' })} por ${vale.resgatado_por}!`, 400);

        await env.DB.prepare('UPDATE vales SET status="resgatado", resgatado_em=unixepoch(), resgatado_por=? WHERE id=?').bind(authCheck.nome, valeId).run();
        return json({ ok: true, message: 'Baixa efetuada com sucesso!' });
      }

      return err(`Endpoint vales não encontrado (${method} ${path})`, 404);
    }

    // ===== MARKETING MODULE =====
    if (path.startsWith('/api/marketing/')) {
      const authCheck = await requireAuth(request, env, ['admin', 'atendente']);
      if (authCheck.error) return authCheck.error;

      // --- Google OAuth ---
      if (path === '/api/marketing/google/auth-url' && method === 'GET') {
        const clientId = env.MARKETING_GOOGLE_CLIENT_ID;
        const redirectUri = 'https://api.moskogas.com.br/api/marketing/oauth/google/callback';
        const scopes = [
          'https://www.googleapis.com/auth/business.manage',
          'https://www.googleapis.com/auth/adwords',
          'openid','email','profile'
        ].join(' ');
        const state = crypto.randomUUID();
        const url = `https://accounts.google.com/o/oauth2/v2/auth?client_id=${encodeURIComponent(clientId)}&redirect_uri=${encodeURIComponent(redirectUri)}&response_type=code&scope=${encodeURIComponent(scopes)}&access_type=offline&prompt=consent&state=${state}`;
        return json({ url });
      }

      if (path === '/api/marketing/oauth/google/callback' && method === 'GET') {
        const code = url.searchParams.get('code');
        if (!code) return err('Missing code', 400);
        const clientId = env.MARKETING_GOOGLE_CLIENT_ID;
        const clientSecret = env.MARKETING_GOOGLE_CLIENT_SECRET;
        const redirectUri = 'https://api.moskogas.com.br/api/marketing/oauth/google/callback';
        const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({ code, client_id: clientId, client_secret: clientSecret, redirect_uri: redirectUri, grant_type: 'authorization_code' })
        });
        const tokenData = await tokenRes.json();
        if (!tokenData.access_token) return err('Falha ao obter token Google', 400);
        // Busca email do usuário
        const profileRes = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', { headers: { Authorization: `Bearer ${tokenData.access_token}` } });
        const profile = await profileRes.json();
        // Salva tokens no D1
        await env.DB.prepare(`INSERT OR REPLACE INTO app_config (key, value, updated_at) VALUES (?,?,datetime('now'))`).bind('marketing_google_tokens', JSON.stringify({ access_token: tokenData.access_token, refresh_token: tokenData.refresh_token, email: profile.email, expires_at: Date.now() + (tokenData.expires_in * 1000) })).run();
        // Redireciona para config.html com âncora marketing
        return new Response(null, { status: 302, headers: { Location: 'https://luismosko.github.io/moskogas-app/config.html#marketing' } });
      }

      if (path === '/api/marketing/google/status' && method === 'GET') {
        const row = await env.DB.prepare(`SELECT value FROM app_config WHERE key='marketing_google_tokens'`).first();
        if (!row) return json({ connected: false });
        const tokens = JSON.parse(row.value);
        return json({ connected: true, email: tokens.email });
      }

      if (path === '/api/marketing/google/disconnect' && method === 'POST') {
        await env.DB.prepare(`DELETE FROM app_config WHERE key='marketing_google_tokens'`).run();
        return json({ ok: true });
      }

      // --- Google Meu Negócio: Reviews ---
      if (path === '/api/marketing/gmb/reviews' && method === 'GET') {
        const row = await env.DB.prepare(`SELECT value FROM app_config WHERE key='marketing_google_tokens'`).first();
        if (!row) return err('Google não conectado', 401);
        const tokens = JSON.parse(row.value);
        // Lista contas GMB
        const accsRes = await fetch('https://mybusinessaccountmanagement.googleapis.com/v1/accounts', { headers: { Authorization: `Bearer ${tokens.access_token}` } });
        const accs = await accsRes.json();
        if (!accs.accounts || !accs.accounts.length) return json({ reviews: [] });
        const accountName = accs.accounts[0].name;
        // Lista locais
        const locsRes = await fetch(`https://mybusinessaccountmanagement.googleapis.com/v1/${accountName}/locations`, { headers: { Authorization: `Bearer ${tokens.access_token}` } });
        const locs = await locsRes.json();
        if (!locs.locations || !locs.locations.length) return json({ reviews: [] });
        const locationName = locs.locations[0].name;
        // Lista reviews
        const revRes = await fetch(`https://mybusiness.googleapis.com/v4/${locationName}/reviews`, { headers: { Authorization: `Bearer ${tokens.access_token}` } });
        const revData = await revRes.json();
        const reviews = (revData.reviews || []).slice(0, 10).map(r => ({
          id: r.reviewId,
          author: r.reviewer?.displayName || 'Anônimo',
          rating: { ONE:1,TWO:2,THREE:3,FOUR:4,FIVE:5 }[r.starRating] || 0,
          comment: r.comment || '',
          reply: r.reviewReply?.comment || null
        }));
        return json({ reviews });
      }

      if (path.match(/^\/api\/marketing\/gmb\/reviews\/[^/]+\/reply$/) && method === 'POST') {
        const reviewId = path.split('/')[5];
        const body = await request.json();
        const row = await env.DB.prepare(`SELECT value FROM app_config WHERE key='marketing_google_tokens'`).first();
        if (!row) return err('Google não conectado', 401);
        const tokens = JSON.parse(row.value);
        const accsRes = await fetch('https://mybusinessaccountmanagement.googleapis.com/v1/accounts', { headers: { Authorization: `Bearer ${tokens.access_token}` } });
        const accs = await accsRes.json();
        const accountName = accs.accounts[0].name;
        const locsRes = await fetch(`https://mybusinessaccountmanagement.googleapis.com/v1/${accountName}/locations`, { headers: { Authorization: `Bearer ${tokens.access_token}` } });
        const locs = await locsRes.json();
        const locationName = locs.locations[0].name;
        await fetch(`https://mybusiness.googleapis.com/v4/${locationName}/reviews/${reviewId}/reply`, {
          method: 'PUT',
          headers: { Authorization: `Bearer ${tokens.access_token}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ comment: body.text })
        });
        return json({ ok: true });
      }

      // --- GMB Post ---
      if (path === '/api/marketing/gmb/post' && method === 'POST') {
        const body = await request.json();
        const row = await env.DB.prepare(`SELECT value FROM app_config WHERE key='marketing_google_tokens'`).first();
        if (!row) return err('Google não conectado', 401);
        const tokens = JSON.parse(row.value);
        const accsRes = await fetch('https://mybusinessaccountmanagement.googleapis.com/v1/accounts', { headers: { Authorization: `Bearer ${tokens.access_token}` } });
        const accs = await accsRes.json();
        const accountName = accs.accounts[0].name;
        const locsRes = await fetch(`https://mybusinessaccountmanagement.googleapis.com/v1/${accountName}/locations`, { headers: { Authorization: `Bearer ${tokens.access_token}` } });
        const locs = await locsRes.json();
        const locationName = locs.locations[0].name;
        const postRes = await fetch(`https://mybusiness.googleapis.com/v4/${locationName}/localPosts`, {
          method: 'POST',
          headers: { Authorization: `Bearer ${tokens.access_token}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ languageCode: 'pt-BR', summary: body.text, topicType: 'STANDARD' })
        });
        const postData = await postRes.json();
        if (postData.name) return json({ ok: true, name: postData.name });
        return err(postData.error?.message || 'Erro ao publicar', 400);
      }

      // --- IA: Sugerir post (OpenAI) ---
      if (path === '/api/marketing/suggest-post' && method === 'POST') {
        const body = await request.json();
        const prompt = `Você é um especialista em marketing para revenda de gás de cozinha e água mineral em Campo Grande, MS. Crie um post curto, direto e persuasivo (máximo 3 parágrafos) para redes sociais sobre: "${body.context}". Tom amigável, local. Não use hashtags em excesso. Retorne apenas o texto do post.`;
        const aiRes = await fetch('https://api.openai.com/v1/chat/completions', {
          method: 'POST',
          headers: { 'Authorization': `Bearer ${env.OPENAI_API_KEY}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ model: 'gpt-4o-mini', max_tokens: 300, messages: [{ role: 'user', content: prompt }] })
        });
        const aiData = await aiRes.json();
        const text = aiData.choices?.[0]?.message?.content || 'Promoção especial! Gás P13 com entrega rápida em Campo Grande. Ligue agora: (67) 99333-0303 🔥';
        return json({ text });
      }

      // --- Meta OAuth (placeholder) ---
      if (path === '/api/marketing/meta/status' && method === 'GET') {
        const row = await env.DB.prepare(`SELECT value FROM app_config WHERE key='marketing_meta_tokens'`).first();
        if (!row) return json({ connected: false });
        const tokens = JSON.parse(row.value);
        return json({ connected: true, page_name: tokens.page_name, instagram_id: tokens.instagram_id });
      }

      if (path === '/api/marketing/meta/auth-url' && method === 'GET') {
        return json({ url: null, message: 'Integração Meta em breve' });
      }

      return err(`Endpoint marketing não encontrado (${method} ${path})`, 404);
    }

    return err(`Not found (${method} ${path})`, 404);
  },

  async scheduled(event, env, ctx) {
    ctx.waitUntil(keepBlingTokenFresh(env));
    const hour = new Date().getUTCHours();
    // Snapshot diário às 22h BRT (01:00 UTC)
    if (hour === 1) {
      ctx.waitUntil(dailyAuditSnapshot(env));
    }
    // Relatório diário por email — verifica config para hora + dedup
    try {
      const reportConfig = await getReportConfig(env);
      if (reportConfig.ativo && hour === (reportConfig.hora_utc || 6)) {
        const yesterday = new Date(Date.now() - 86400000).toISOString().slice(0, 10);
        // Dedup: verificar se já enviou relatório desse dia
        const lastSent = await env.DB.prepare("SELECT value FROM app_config WHERE key='relatorio_last_sent'").first().catch(() => null);
        if (lastSent?.value !== yesterday) {
          await env.DB.prepare("INSERT OR REPLACE INTO app_config (key, value, updated_at) VALUES ('relatorio_last_sent', ?, datetime('now'))").bind(yesterday).run();
          ctx.waitUntil(sendDailyReportEmail(env, yesterday));
        } else {
          console.log(`[relatorio-cron] Já enviado para ${yesterday}, pulando.`);
        }
      }
    } catch (e) { console.error('[relatorio-cron] Erro:', e.message); }
    // Lembretes PIX automáticos — verificar config para hora
    try {
      const config = await getLembreteConfig(env);
      if (config.cron_ativo && hour === (config.cron_hora_utc || 14)) {
        ctx.waitUntil(processarLembretesCron(env));
      }
    } catch (e) { console.error('[lembrete-cron] Config error:', e.message); }
    // PIX auto-check: verificar pagamentos pendentes na PushInPay a cada execução do cron
    if (isPixConfigured(env)) {
      ctx.waitUntil(checkPendingPixPayments(env));
    }
    // Avaliações pós-compra: cron a cada execução (filtra por horário internamente)
    ctx.waitUntil(processarAvaliacoesCron(env));
  },
};

// ══════════════════════════════════════════════════════════════
// MÓDULO AVALIAÇÃO PÓS-COMPRA (v2.44.0)
// NPS 1-5 via WhatsApp + webhook IzChat + cron automático
// ══════════════════════════════════════════════════════════════

async function ensureAvaliacaoTables(env) {
  try {
    await env.DB.prepare(`CREATE TABLE IF NOT EXISTS satisfaction_surveys (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      order_id INTEGER NOT NULL UNIQUE,
      phone_digits TEXT NOT NULL,
      customer_name TEXT DEFAULT '',
      sent_at INTEGER DEFAULT (unixepoch()),
      answered_at INTEGER,
      score INTEGER,
      score_raw INTEGER,
      izchat_opp_id TEXT,
      follow_up_sent INTEGER DEFAULT 0,
      google_link_sent INTEGER DEFAULT 0,
      status TEXT DEFAULT 'sent',
      FOREIGN KEY(order_id) REFERENCES orders(id)
    )`).run();
    await env.DB.prepare(`ALTER TABLE customers_cache ADD COLUMN sem_avaliacao INTEGER DEFAULT 0`).run().catch(() => {});
    await env.DB.prepare(`ALTER TABLE orders ADD COLUMN survey_sent INTEGER DEFAULT 0`).run().catch(() => {});
    await env.DB.prepare(`ALTER TABLE satisfaction_surveys ADD COLUMN score_raw INTEGER`).run().catch(() => {});
    await env.DB.prepare(`ALTER TABLE satisfaction_surveys ADD COLUMN izchat_opp_id TEXT`).run().catch(() => {});
  } catch (e) { /* table já existe */ }
}

// Criar oportunidade no CRM IzChat para rastrear avaliação
async function criarOportunidadeCRM(env, survey, config) {
  try {
    const companyToken = env.IZCHAT_COMPANY_TOKEN;
    if (!companyToken) { console.log('[crm] IZCHAT_COMPANY_TOKEN não configurado'); return null; }

    // Buscar pipelines para pegar o ID correto do pipeline de avaliação
    const pipelinesRes = await fetch('https://chatapi.izchat.com.br/api/external/pipelines', {
      headers: { 'Authorization': `Bearer ${companyToken}` }
    });
    const pipelinesData = await pipelinesRes.json();
    const pipelines = pipelinesData?.data?.pipelines || pipelinesData?.pipelines || [];
    const pipeline = pipelines.find(p => p.name?.toLowerCase().includes('avalia') || p.name?.toLowerCase().includes('pós venda') || p.name?.toLowerCase().includes('pos venda'));
    if (!pipeline) { console.log('[crm] Pipeline de avaliação não encontrado'); return null; }

    // Primeira etapa = "Avaliação Interna" (onde entra ao enviar)
    const firstStage = pipeline.stages?.[0] || pipeline.lanes?.[0];
    if (!firstStage) { console.log('[crm] Etapas do pipeline não encontradas'); return null; }

    // Buscar ou criar contato
    const phoneSearch = await fetch(`https://chatapi.izchat.com.br/api/external/contacts/search?phone=${survey.phone_digits}`, {
      headers: { 'Authorization': `Bearer ${companyToken}` }
    });
    const phoneData = await phoneSearch.json();
    const contact = phoneData?.data?.contact || phoneData?.contact;
    const contactId = contact?.id;

    // Criar oportunidade
    const oppBody = {
      title: `Avaliação #${survey.order_id} — ${survey.customer_name || survey.phone_digits}`,
      pipeline_id: pipeline.id,
      stage_id: firstStage.id,
      contact_id: contactId || undefined,
      value: 0,
    };

    const oppRes = await fetch('https://chatapi.izchat.com.br/api/external/crm/opportunity', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${companyToken}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(oppBody)
    });
    const oppData = await oppRes.json();
    const oppId = oppData?.data?.opportunity?.id || oppData?.opportunity?.id || oppData?.id;
    console.log(`[crm] Oportunidade criada: ${oppId} para pedido #${survey.order_id}`);
    return String(oppId);
  } catch (e) {
    console.error('[crm] Erro ao criar oportunidade:', e.message);
    return null;
  }
}

async function getAvaliacaoConfig(env) {
  const defaults = {
    ativo: true,
    delay_horas: 2,
    cron_ativo: true,
    mensagem_pesquisa: 'Obrigado por comprar no Mosko Gás. 🙏\n\nEstamos buscando sempre melhorar nosso atendimento e para isso sua opinião é muito importante.\n\nResponda por gentileza como você avalia o atendimento prestado.\nDe 1 a 5.\n\nConte para nós como foi seu atendimento por telefone e como foi sua entrega?\n\n😃 Ficaremos felizes em saber 😃\nTenha uma semana abençoada 🙌',
    mensagem_positiva: 'Agradecemos sua avaliação\n\nPor gentileza, faça uma avaliação no Google pra gente...\nisso nos ajuda muito a continuar prestando um bom serviço. 🙏🏻😀\né só clicar no link abaixo, marcar 5 estrelas ⭐⭐⭐⭐⭐ e fazer um comentário.\n\n{google_url}',
    mensagem_negativa: 'Obrigado pelo retorno, {nome}. Sentimos muito que sua experiência não foi como esperado. 😔\n\nPode nos contar o que aconteceu? Assim podemos melhorar!',
    mensagem_admin: '⚠️ *Avaliação baixa recebida!*\n\nCliente: {nome}\nTelefone: {telefone}\nNota: {score}/5\nPedido: #{pedido_id}',
    google_url: 'https://g.page/r/CY7yl-zGUwODEBM/review',
    horario_inicio: 8,
    horario_fim: 20,
  };
  try {
    const row = await env.DB.prepare("SELECT value FROM app_config WHERE key='avaliacao_config'").first();
    if (row?.value) return { ...defaults, ...JSON.parse(row.value) };
  } catch (_) {}
  return defaults;
}

function montarMensagemAvaliacao(template, vars) {
  return template
    .replace(/{nome}/g, vars.nome || 'Cliente')
    .replace(/{telefone}/g, vars.telefone || '')
    .replace(/{score}/g, vars.score || '')
    .replace(/{pedido_id}/g, vars.pedido_id || '')
    .replace(/{google_url}/g, vars.google_url || '');
}

async function processarAvaliacoesCron(env) {
  console.log('[avaliacao-cron] Iniciando processamento...');
  try {
    await ensureAvaliacaoTables(env);
    const config = await getAvaliacaoConfig(env);
    if (!config.ativo || !config.cron_ativo) {
      console.log('[avaliacao-cron] Desativado nas configs');
      return;
    }

    const hourBRT = new Date(Date.now() - 3*3600000).getUTCHours();
    if (hourBRT < config.horario_inicio || hourBRT >= config.horario_fim) {
      console.log(`[avaliacao-cron] Fora do horário permitido (${hourBRT}h BRT)`);
      return;
    }

    const delayEpoch = Math.floor(Date.now() / 1000) - (config.delay_horas * 3600);
    // Buscar pedidos entregues há >= delay_horas, sem survey enviada, sem flag sem_avaliacao
    const { results: orders } = await env.DB.prepare(`
      SELECT o.id, o.phone_digits, o.customer_name, o.delivered_at
      FROM orders o
      LEFT JOIN customers_cache cc ON cc.phone_digits = o.phone_digits
      WHERE o.status = 'entregue'
        AND o.survey_sent = 0
        AND o.delivered_at IS NOT NULL
        AND o.delivered_at <= ?
        AND o.phone_digits IS NOT NULL
        AND o.phone_digits != ''
        AND o.phone_digits != '00000000000'
        AND (cc.sem_avaliacao IS NULL OR cc.sem_avaliacao = 0)
      ORDER BY o.delivered_at ASC
      LIMIT 10
    `).bind(delayEpoch).all();

    if (!orders?.length) {
      console.log('[avaliacao-cron] Nenhum pedido pendente de avaliação');
      return;
    }

    console.log(`[avaliacao-cron] ${orders.length} pedido(s) para avaliar`);
    let enviados = 0, erros = 0;

    for (const order of orders) {
      try {
        const phone = order.phone_digits.replace(/\D/g, '');
        const phoneIntl = phone.startsWith('55') ? phone : `55${phone}`;
        const mensagem = montarMensagemAvaliacao(config.mensagem_pesquisa, {
          nome: (order.customer_name || 'Cliente').split(' ')[0],
        });

        const result = await sendWhatsApp(env, phoneIntl, mensagem, { category: 'avaliacao' });

        if (result?.blocked) {
          console.log('[avaliacao-cron] ⚠️ WhatsApp bloqueado — parando envios!');
          break;
        }

        // Marcar no orders
        await env.DB.prepare('UPDATE orders SET survey_sent=1 WHERE id=?').bind(order.id).run();
        // Registrar no satisfaction_surveys
        await env.DB.prepare(`
          INSERT OR IGNORE INTO satisfaction_surveys (order_id, phone_digits, customer_name, status)
          VALUES (?, ?, ?, 'sent')
        `).bind(order.id, order.phone_digits, order.customer_name || '').run();

        // Criar oportunidade no CRM IzChat para rastrear resposta do agente IA
        const surveyRow = await env.DB.prepare(`SELECT id FROM satisfaction_surveys WHERE order_id=?`).bind(order.id).first().catch(() => null);
        if (surveyRow) {
          const oppId = await criarOportunidadeCRM(env, {
            order_id: order.id,
            phone_digits: order.phone_digits,
            customer_name: order.customer_name,
          }, config);
          if (oppId) {
            await env.DB.prepare('UPDATE satisfaction_surveys SET izchat_opp_id=? WHERE id=?').bind(oppId, surveyRow.id).run();
          }
        }

        enviados++;
        console.log(`[avaliacao-cron] ✅ Enviado para pedido #${order.id} (${phone})`);
        await new Promise(r => setTimeout(r, 3000));
      } catch (e) {
        erros++;
        console.error(`[avaliacao-cron] ❌ Erro pedido #${order.id}:`, e.message);
      }
    }
    console.log(`[avaliacao-cron] Concluído: ${enviados} enviados, ${erros} erros`);
  } catch (e) {
    console.error('[avaliacao-cron] Erro fatal:', e.message);
  }
}

async function processarRespostaAvaliacao(env, phoneDigits, mensagemTexto) {
  try {
    const config = await getAvaliacaoConfig(env);
    const score = parseInt((mensagemTexto || '').trim());
    if (isNaN(score) || score < 1 || score > 5) return false; // não é uma resposta de avaliação

    // Buscar survey pendente para este telefone (mais recente)
    const survey = await env.DB.prepare(`
      SELECT ss.*, o.id as oid
      FROM satisfaction_surveys ss
      JOIN orders o ON o.id = ss.order_id
      WHERE ss.phone_digits = ? AND ss.status = 'sent'
      ORDER BY ss.sent_at DESC LIMIT 1
    `).bind(phoneDigits).first();

    if (!survey) return false; // sem pesquisa pendente para este número

    // Registrar resposta
    await env.DB.prepare(`
      UPDATE satisfaction_surveys SET score=?, answered_at=unixepoch(), status='answered'
      WHERE id=?
    `).bind(score, survey.id).run();

    const nomeCliente = (survey.customer_name || 'Cliente').split(' ')[0];
    const phoneIntl = phoneDigits.startsWith('55') ? phoneDigits : `55${phoneDigits}`;

    if (score >= 5) {
      // Enviar link Google Review
      const googleUrl = config.google_url || 'https://g.page/r/moskogas';
      const msg = montarMensagemAvaliacao(config.mensagem_positiva, {
        nome: nomeCliente,
        google_url: googleUrl,
      });
      await sendWhatsApp(env, phoneIntl, msg, { category: 'avaliacao' });
      await env.DB.prepare('UPDATE satisfaction_surveys SET google_link_sent=1 WHERE id=?').bind(survey.id).run();
      console.log(`[avaliacao-webhook] ⭐ Score 5 para pedido #${survey.order_id} — link Google enviado`);
    } else {
      // Enviar mensagem de follow-up ao cliente
      const msgCliente = montarMensagemAvaliacao(config.mensagem_negativa, { nome: nomeCliente });
      await sendWhatsApp(env, phoneIntl, msgCliente, { category: 'avaliacao' });
      await env.DB.prepare('UPDATE satisfaction_surveys SET follow_up_sent=1 WHERE id=?').bind(survey.id).run();

      // Alertar admins
      try {
        const { results: admins } = await env.DB.prepare(
          "SELECT telefone FROM app_users WHERE role='admin' AND recebe_whatsapp=1 AND ativo=1 AND telefone IS NOT NULL"
        ).all();
        const msgAdmin = montarMensagemAvaliacao(config.mensagem_admin, {
          nome: survey.customer_name || 'Desconhecido',
          telefone: phoneDigits,
          score: score,
          pedido_id: survey.order_id,
        });
        for (const admin of (admins || [])) {
          const adminPhone = admin.telefone.replace(/\D/g, '');
          const adminIntl = adminPhone.startsWith('55') ? adminPhone : `55${adminPhone}`;
          await sendWhatsApp(env, adminIntl, msgAdmin, { category: 'admin_alerta' });
          await new Promise(r => setTimeout(r, 1500));
        }
      } catch (e) { console.error('[avaliacao] Erro alertar admins:', e.message); }
      console.log(`[avaliacao-webhook] ⚠️ Score ${score} para pedido #${survey.order_id} — follow-up enviado + admins alertados`);
    }
    return true;
  } catch (e) {
    console.error('[avaliacao] Erro processarResposta:', e.message);
    return false;
  }
}
// ══════════════════════════════════════════════════════════════
// FIM MÓDULO AVALIAÇÃO
// ══════════════════════════════════════════════════════════════

// Roda a cada execução do cron (5 min default)
// ══════════════════════════════════════════════════════════════
async function checkPendingPixPayments(env) {
  try {
    await ensurePixColumns(env);
    const pending = await env.DB.prepare(
      "SELECT id, pix_tx_id, total_value, customer_name FROM orders WHERE pix_tx_id IS NOT NULL AND pago=0 AND pix_paid_at IS NULL AND status != 'cancelado' ORDER BY id DESC LIMIT 20"
    ).all();
    const rows = pending.results || [];
    if (!rows.length) { console.log('[pix-autocheck] Nenhum PIX pendente'); return; }

    console.log(`[pix-autocheck] Verificando ${rows.length} PIX pendente(s)...`);
    let confirmed = 0;

    for (const order of rows) {
      try {
        const txData = await pushInPayCheckStatus(env, order.pix_tx_id);
        if (txData.status === 'paid') {
          await env.DB.prepare('UPDATE orders SET pago=1, pix_paid_at=unixepoch() WHERE id=?').bind(order.id).run();
          await logEvent(env, order.id, 'pix_autocheck_confirmed', { tx_id: order.pix_tx_id });
          confirmed++;
          console.log(`[pix-autocheck] ✅ Pedido #${order.id} confirmado como pago!`);

          // WhatsApp admin
          try {
            const admins = await env.DB.prepare("SELECT telefone FROM app_users WHERE role='admin' AND recebe_whatsapp=1 AND ativo=1").all();
            const phones = (admins.results || []).map(a => a.telefone).filter(Boolean);
            const valor = parseFloat(order.total_value || 0).toFixed(2);
            const msg = `✅ *PIX CONFIRMADO (auto-check)* — Pedido #${order.id}\n\n💰 R$ ${valor} — ${order.customer_name || 'Cliente'}`;
            for (const ph of phones) {
              await sendWhatsApp(env, ph, msg, { category: 'admin_alerta' });
            }
          } catch (we) { console.error('[pix-autocheck] WhatsApp error:', we.message); }

          // Criar Bling se necessário
          try {
            const fullOrder = await env.DB.prepare('SELECT * FROM orders WHERE id=?').bind(order.id).first();
            if (!fullOrder.bling_pedido_id && fullOrder.status === 'entregue') {
              const cached = await env.DB.prepare('SELECT bling_contact_id, cpf_cnpj FROM customers_cache WHERE phone_digits=?').bind(fullOrder.phone_digits).first().catch(() => null);
              let vendBlingId = null, vendNome = null;
              if (fullOrder.vendedor_id) {
                const vu = await env.DB.prepare('SELECT bling_vendedor_id, nome FROM app_users WHERE id=?').bind(fullOrder.vendedor_id).first().catch(() => null);
                if (vu?.bling_vendedor_id) vendBlingId = vu.bling_vendedor_id;
                if (vu?.nome) vendNome = vu.nome;
              }
              const blingData = await criarPedidoBling(env, order.id, {
                name: fullOrder.customer_name,
                items: JSON.parse(fullOrder.items_json || '[]'),
                total_value: fullOrder.total_value,
                tipo_pagamento: fullOrder.tipo_pagamento,
                bling_contact_id: cached?.bling_contact_id || null,
                cpf_cnpj: cached?.cpf_cnpj || null,
                bling_vendedor_id: vendBlingId,
                vendedor_nome: vendNome,
              });
              await env.DB.prepare('UPDATE orders SET bling_pedido_id=?, bling_pedido_num=?, sync_status=? WHERE id=?')
                .bind(blingData.bling_pedido_id, blingData.bling_pedido_num, 'synced', order.id).run();
              console.log(`[pix-autocheck] Bling criado para pedido #${order.id}`);
            }
          } catch (be) { console.error('[pix-autocheck] Bling error:', be.message); }
        }
        // Rate limit: esperar 1s entre consultas
        await new Promise(r => setTimeout(r, 1000));
      } catch (e) {
        console.error(`[pix-autocheck] Erro pedido #${order.id}:`, e.message);
      }
    }
    console.log(`[pix-autocheck] Concluído: ${confirmed}/${rows.length} confirmado(s)`);
  } catch (e) {
    console.error('[pix-autocheck] Erro geral:', e.message);
  }
}

// ══════════════════════════════════════════════════════════════
// RELATÓRIO DIÁRIO POR E-MAIL — v2.29.0
// Envia resumo + CSV dos pedidos do dia anterior via Resend
// ══════════════════════════════════════════════════════════════

async function getReportConfig(env) {
  const row = await env.DB.prepare("SELECT value FROM app_config WHERE key='relatorio_email'").first().catch(() => null);
  const defaults = {
    ativo: false,
    destinos: ['luismosko@gmail.com'],
    hora_utc: 6, // 03:00 BRT
    incluir_csv: true,
    incluir_cancelados: true,
  };
  try { if (row?.value) return { ...defaults, ...JSON.parse(row.value) }; } catch { }
  return defaults;
}

// Busca RESEND_API_KEY: 1) env secret, 2) app_config, 3) body do request
async function getResendKey(env, bodyKey) {
  if (env.RESEND_API_KEY) return env.RESEND_API_KEY;
  try {
    const row = await env.DB.prepare("SELECT value FROM app_config WHERE key='resend_api_key'").first();
    if (row?.value) return row.value;
  } catch { }
  if (bodyKey) return bodyKey;
  return null;
}

async function generateDailyReport(env, dateStr) {
  // dateStr = 'YYYY-MM-DD'
  const dayStart = Math.floor(new Date(dateStr + 'T00:00:00-04:00').getTime() / 1000);
  const dayEnd = dayStart + 86400;

  const orders = await env.DB.prepare(`
    SELECT o.*, cc.email, cc.cpf_cnpj, cc.bling_contact_id
    FROM orders o
    LEFT JOIN customers_cache cc ON cc.phone_digits = o.phone_digits
    WHERE o.created_at >= ? AND o.created_at < ?
    ORDER BY o.id ASC
  `).bind(dayStart, dayEnd).all().then(r => r.results || []);

  // ── Resumo ──
  const total = orders.length;
  const totalValor = orders.reduce((s, o) => s + (parseFloat(o.total_value) || 0), 0);
  const entregues = orders.filter(o => o.status === 'entregue').length;
  const cancelados = orders.filter(o => o.status === 'cancelado').length;
  const pendentes = total - entregues - cancelados;
  const pagos = orders.filter(o => o.pago === 1).length;
  const comBling = orders.filter(o => o.bling_pedido_id).length;

  // Por tipo pagamento
  const porTipo = {};
  for (const o of orders) {
    const t = o.tipo_pagamento || 'indefinido';
    if (!porTipo[t]) porTipo[t] = { qtd: 0, valor: 0 };
    porTipo[t].qtd++;
    porTipo[t].valor += parseFloat(o.total_value) || 0;
  }

  // Por vendedor
  const porVendedor = {};
  for (const o of orders) {
    const v = o.vendedor_nome || 'Sem vendedor';
    if (!porVendedor[v]) porVendedor[v] = { qtd: 0, valor: 0 };
    porVendedor[v].qtd++;
    porVendedor[v].valor += parseFloat(o.total_value) || 0;
  }

  // Por entregador
  const porEntregador = {};
  for (const o of orders) {
    if (o.driver_name_cache) {
      const d = o.driver_name_cache;
      if (!porEntregador[d]) porEntregador[d] = { qtd: 0, valor: 0 };
      porEntregador[d].qtd++;
      porEntregador[d].valor += parseFloat(o.total_value) || 0;
    }
  }

  // Produtos vendidos (soma)
  const produtosTotal = {};
  for (const o of orders) {
    if (o.status === 'cancelado') continue;
    try {
      const items = JSON.parse(o.items_json || '[]');
      for (const it of items) {
        const nome = it.name || '?';
        if (!produtosTotal[nome]) produtosTotal[nome] = { qtd: 0, valor: 0 };
        produtosTotal[nome].qtd += parseInt(it.qty) || 1;
        produtosTotal[nome].valor += (parseInt(it.qty) || 1) * (parseFloat(it.price) || 0);
      }
    } catch { }
  }

  return {
    dateStr, total, totalValor, entregues, cancelados, pendentes, pagos, comBling,
    porTipo, porVendedor, porEntregador, produtosTotal, orders,
  };
}

function buildReportHTML(report) {
  const d = report.dateStr;
  const fmtBRL = v => 'R$ ' + v.toFixed(2).replace('.', ',');
  const fmtFone = f => f ? f.replace(/(\d{2})(\d{5})(\d{4})/, '($1) $2-$3') : '—';
  const fmtEpoch = ts => {
    if (!ts) return '—';
    return new Date(ts * 1000).toLocaleString('pt-BR', { timeZone: 'America/Campo_Grande', dateStyle: 'short', timeStyle: 'short' });
  };

  const statusLabel = {
    novo: '🔴 NOVO', encaminhado: '🟡 ENCAMINHADO',
    whatsapp_enviado: '🟢 WHATS ENVIADO', entregue: '🔵 ENTREGUE',
    cancelado: '⚫ CANCELADO'
  };
  const pgtoLabel = {
    dinheiro: '💵 Dinheiro', pix_vista: '⚡ PIX Vista', pix_receber: '⏳ PIX Aberto',
    debito: '💳 Débito', credito: '💳 Crédito', mensalista: '📅 Mensalista', boleto: '🧾 Boleto'
  };

  let html = `<!DOCTYPE html><html><head><meta charset="utf-8"></head>
<body style="font-family:system-ui,-apple-system,sans-serif;background:#f8fafc;padding:20px;color:#1e293b">
<div style="max-width:800px;margin:0 auto;background:#fff;border-radius:12px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,0.1)">

<!-- Header -->
<div style="background:linear-gradient(135deg,#1e40af,#3b82f6);color:#fff;padding:24px 32px">
  <h1 style="margin:0;font-size:22px">🔥 MoskoGás — Pedidos do Dia</h1>
  <p style="margin:4px 0 0;opacity:0.9;font-size:14px">${d} (Campo Grande/MS)</p>
</div>

<!-- KPIs -->
<div style="padding:24px 32px">
  <table style="width:100%;border-collapse:collapse;margin-bottom:20px">
    <tr>
      <td style="text-align:center;padding:16px;background:#eff6ff;border-radius:8px">
        <div style="font-size:28px;font-weight:800;color:#1e40af">${report.total}</div>
        <div style="font-size:12px;color:#64748b">Total Pedidos</div>
      </td>
      <td style="width:8px"></td>
      <td style="text-align:center;padding:16px;background:#f0fdf4;border-radius:8px">
        <div style="font-size:28px;font-weight:800;color:#16a34a">${fmtBRL(report.totalValor)}</div>
        <div style="font-size:12px;color:#64748b">Faturamento</div>
      </td>
      <td style="width:8px"></td>
      <td style="text-align:center;padding:16px;background:#fef3c7;border-radius:8px">
        <div style="font-size:28px;font-weight:800;color:#d97706">${report.entregues}</div>
        <div style="font-size:12px;color:#64748b">Entregues</div>
      </td>
    </tr>
  </table>

  <table style="width:100%;border-collapse:collapse;margin-bottom:20px;font-size:13px">
    <tr>
      <td style="padding:6px 0;color:#64748b">📦 Pendentes:</td><td style="font-weight:700">${report.pendentes}</td>
      <td style="padding:6px 0;color:#64748b">❌ Cancelados:</td><td style="font-weight:700">${report.cancelados}</td>
      <td style="padding:6px 0;color:#64748b">✅ Pagos:</td><td style="font-weight:700">${report.pagos}</td>
      <td style="padding:6px 0;color:#64748b">📋 No Bling:</td><td style="font-weight:700">${report.comBling}</td>
    </tr>
  </table>

  <!-- Produtos -->
  <h3 style="margin:20px 0 8px;font-size:15px;color:#1e40af">📦 Produtos Vendidos</h3>
  <table style="width:100%;border-collapse:collapse;font-size:13px">
    <thead><tr style="background:#f1f5f9">
      <th style="padding:8px;text-align:left">Produto</th>
      <th style="padding:8px;text-align:center">Qtd</th>
      <th style="padding:8px;text-align:right">Total</th>
    </tr></thead><tbody>`;

  for (const [nome, p] of Object.entries(report.produtosTotal).sort((a, b) => b[1].valor - a[1].valor)) {
    html += `<tr><td style="padding:6px 8px">${nome}</td><td style="padding:6px 8px;text-align:center;font-weight:700">${p.qtd}</td><td style="padding:6px 8px;text-align:right">${fmtBRL(p.valor)}</td></tr>`;
  }
  html += `</tbody></table>`;

  // Por tipo pagamento
  html += `<h3 style="margin:20px 0 8px;font-size:15px;color:#1e40af">💰 Por Forma de Pagamento</h3>
  <table style="width:100%;border-collapse:collapse;font-size:13px">
    <thead><tr style="background:#f1f5f9"><th style="padding:8px;text-align:left">Tipo</th><th style="padding:8px;text-align:center">Qtd</th><th style="padding:8px;text-align:right">Total</th></tr></thead><tbody>`;
  for (const [tipo, d] of Object.entries(report.porTipo)) {
    html += `<tr><td style="padding:6px 8px">${pgtoLabel[tipo] || tipo}</td><td style="padding:6px 8px;text-align:center;font-weight:700">${d.qtd}</td><td style="padding:6px 8px;text-align:right">${fmtBRL(d.valor)}</td></tr>`;
  }
  html += `</tbody></table>`;

  // Por vendedor
  if (Object.keys(report.porVendedor).length > 0) {
    html += `<h3 style="margin:20px 0 8px;font-size:15px;color:#1e40af">👤 Por Vendedor</h3>
    <table style="width:100%;border-collapse:collapse;font-size:13px">
      <thead><tr style="background:#f1f5f9"><th style="padding:8px;text-align:left">Vendedor</th><th style="padding:8px;text-align:center">Qtd</th><th style="padding:8px;text-align:right">Total</th></tr></thead><tbody>`;
    for (const [v, d] of Object.entries(report.porVendedor).sort((a, b) => b[1].valor - a[1].valor)) {
      html += `<tr><td style="padding:6px 8px">${v}</td><td style="padding:6px 8px;text-align:center;font-weight:700">${d.qtd}</td><td style="padding:6px 8px;text-align:right">${fmtBRL(d.valor)}</td></tr>`;
    }
    html += `</tbody></table>`;
  }

  // Lista detalhada
  html += `<h3 style="margin:24px 0 8px;font-size:15px;color:#1e40af">📋 Lista Detalhada (${report.orders.length} pedidos)</h3>
  <table style="width:100%;border-collapse:collapse;font-size:11px;line-height:1.4">
    <thead><tr style="background:#1e40af;color:#fff">
      <th style="padding:6px 4px">#</th>
      <th style="padding:6px 4px">Status</th>
      <th style="padding:6px 4px">Cliente</th>
      <th style="padding:6px 4px">Telefone</th>
      <th style="padding:6px 4px">Endereço</th>
      <th style="padding:6px 4px">Itens</th>
      <th style="padding:6px 4px;text-align:right">Valor</th>
      <th style="padding:6px 4px">Pgto</th>
      <th style="padding:6px 4px">Pago</th>
      <th style="padding:6px 4px">Bling</th>
      <th style="padding:6px 4px">Vendedor</th>
      <th style="padding:6px 4px">Entregador</th>
      <th style="padding:6px 4px">Hora</th>
    </tr></thead><tbody>`;

  for (const o of report.orders) {
    let itensStr = '';
    try {
      const items = JSON.parse(o.items_json || '[]');
      itensStr = items.map(i => `${i.qty}x ${i.name}`).join(', ');
    } catch { }
    const bg = o.status === 'cancelado' ? '#fef2f2' : (o.status === 'entregue' ? '#f0fdf4' : '#fff');
    html += `<tr style="background:${bg};border-bottom:1px solid #e2e8f0">
      <td style="padding:4px;font-weight:700">${o.id}</td>
      <td style="padding:4px;font-size:10px">${statusLabel[o.status] || o.status}</td>
      <td style="padding:4px">${o.customer_name || '—'}</td>
      <td style="padding:4px;font-size:10px">${fmtFone(o.phone_digits)}</td>
      <td style="padding:4px;font-size:10px">${o.address_line || ''} ${o.bairro ? '(' + o.bairro + ')' : ''}</td>
      <td style="padding:4px;font-size:10px">${itensStr}</td>
      <td style="padding:4px;text-align:right;font-weight:700">${fmtBRL(parseFloat(o.total_value) || 0)}</td>
      <td style="padding:4px;font-size:10px">${pgtoLabel[o.tipo_pagamento] || o.tipo_pagamento || '—'}</td>
      <td style="padding:4px;text-align:center">${o.pago ? '✅' : '❌'}</td>
      <td style="padding:4px;font-size:10px">${o.bling_pedido_id || '—'}</td>
      <td style="padding:4px;font-size:10px">${o.vendedor_nome || '—'}</td>
      <td style="padding:4px;font-size:10px">${o.driver_name_cache || '—'}</td>
      <td style="padding:4px;font-size:10px">${fmtEpoch(o.created_at)}</td>
    </tr>`;
  }

  html += `</tbody></table></div>

<!-- Footer -->
<div style="padding:16px 32px;background:#f1f5f9;text-align:center;font-size:11px;color:#94a3b8">
  MoskoGás — Relatório automático gerado em ${new Date().toLocaleString('pt-BR', { timeZone: 'America/Campo_Grande' })}<br>
  Sistema: moskogas-app.pages.dev | API: api.moskogas.com.br
</div>
</div></body></html>`;

  return html;
}

function buildReportCSV(report) {
  const BOM = '\uFEFF'; // UTF-8 BOM para Excel abrir corretamente
  const headers = ['ID', 'Status', 'Cliente', 'Telefone', 'Email', 'CPF_CNPJ', 'Endereco', 'Bairro', 'Complemento', 'Referencia', 'Itens', 'Quantidade_Total', 'Valor', 'Tipo_Pagamento', 'Pago', 'Bling_ID', 'Bling_Num', 'Vendedor', 'Entregador', 'Observacoes', 'Obs_Entregador', 'Criado_Em', 'Entregue_Em'];

  const escape = v => {
    if (v == null) return '';
    const s = String(v);
    if (s.includes(',') || s.includes('"') || s.includes('\n')) return '"' + s.replace(/"/g, '""') + '"';
    return s;
  };

  const fmtEpoch = ts => {
    if (!ts) return '';
    return new Date(ts * 1000).toLocaleString('pt-BR', { timeZone: 'America/Campo_Grande', dateStyle: 'short', timeStyle: 'short' });
  };

  let csv = BOM + headers.join(',') + '\n';
  for (const o of report.orders) {
    let itensStr = '', qtdTotal = 0;
    try {
      const items = JSON.parse(o.items_json || '[]');
      itensStr = items.map(i => `${i.qty}x ${i.name}`).join(' | ');
      qtdTotal = items.reduce((s, i) => s + (parseInt(i.qty) || 1), 0);
    } catch { }

    csv += [
      o.id, o.status, o.customer_name || '', o.phone_digits || '', o.email || '', o.cpf_cnpj || '',
      o.address_line || '', o.bairro || '', o.complemento || '', o.referencia || '',
      itensStr, qtdTotal, (parseFloat(o.total_value) || 0).toFixed(2),
      o.tipo_pagamento || '', o.pago ? 'Sim' : 'Não',
      o.bling_pedido_id || '', o.bling_pedido_num || '',
      o.vendedor_nome || '', o.driver_name_cache || '',
      o.notes || '', o.observacao_entregador || '',
      fmtEpoch(o.created_at), fmtEpoch(o.delivered_at),
    ].map(escape).join(',') + '\n';
  }
  return csv;
}

async function sendDailyReportEmail(env, dateStr) {
  const config = await getReportConfig(env);
  if (!config.ativo) {
    console.log('[relatorio] Relatório por email desativado');
    return { ok: false, reason: 'desativado' };
  }
  const resendKey = await getResendKey(env);
  if (!resendKey) {
    console.error('[relatorio] RESEND_API_KEY não encontrada (env nem app_config)');
    return { ok: false, reason: 'sem_api_key' };
  }

  const report = await generateDailyReport(env, dateStr);
  if (report.total === 0) {
    console.log(`[relatorio] Sem pedidos em ${dateStr}`);
    return { ok: true, reason: 'sem_pedidos', total: 0 };
  }

  const html = buildReportHTML(report);
  const csv = config.incluir_csv ? buildReportCSV(report) : null;

  const fmtBRL = v => 'R$ ' + v.toFixed(2).replace('.', ',');
  const subject = `Pedidos do dia — ${dateStr} — ${report.total} pedidos — ${fmtBRL(report.totalValor)}`;

  const emailPayload = {
    from: 'MoskoGás <relatorio@moskogas.com.br>',
    to: config.destinos,
    subject,
    html,
  };

  if (csv) {
    emailPayload.attachments = [{
      filename: `pedidos_${dateStr}.csv`,
      content: btoa(unescape(encodeURIComponent(csv))),
    }];
  }

  const resp = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${resendKey}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(emailPayload),
  });

  if (!resp.ok) {
    const errText = await resp.text().catch(() => '');
    console.error(`[relatorio] Resend erro ${resp.status}: ${errText}`);
    return { ok: false, error: `Resend ${resp.status}: ${errText.substring(0, 200)}` };
  }

  const result = await resp.json();
  console.log(`[relatorio] Email enviado: ${dateStr} — ${report.total} pedidos — ID: ${result.id}`);
  return { ok: true, email_id: result.id, total: report.total, valor: report.totalValor, destinos: config.destinos };
}

async function keepBlingTokenFresh(env) {
  try {
    const row = await getTokenRow(env);
    if (!row) { console.log('[cron] Nenhum token Bling encontrado.'); return; }
    const now = Math.floor(Date.now() / 1000);
    const expiresAt = (row.obtained_at || 0) + (row.expires_in || 3600);
    const minutesLeft = Math.floor((expiresAt - now) / 60);
    console.log(`[cron] Token Bling expira em ${minutesLeft} minutos.`);
    if (minutesLeft < 120) {
      const newToken = await refreshBlingToken(env, row.refresh_token);
      console.log(`[cron] Token renovado com sucesso. Novo: ${newToken.substring(0, 10)}...`);
    } else {
      console.log('[cron] Token ainda válido.');
    }
  } catch (e) { console.error('[cron] Erro:', e.message); }
}

async function dailyAuditSnapshot(env) {
  try {
    await ensureAuditTable(env);
    // Snapshot do dia anterior (já encerrado)
    const yesterday = new Date(Date.now() - 86400000).toISOString().slice(0, 10);
    const dateStart = `${yesterday} 00:00:00`;
    const dateEnd = `${yesterday} 23:59:59`;

    // Verificar se já existe snapshot desse dia
    const existing = await env.DB.prepare('SELECT id FROM audit_snapshots WHERE snapshot_date=?').bind(yesterday).first();
    if (existing) { console.log(`[audit] Snapshot ${yesterday} já existe`); return; }

    const orders = await env.DB.prepare(
      `SELECT total_value, tipo_pagamento, pago, bling_pedido_id, vendedor_nome, items_json FROM orders WHERE created_at BETWEEN ? AND ?`
    ).bind(dateStart, dateEnd).all().then(r => r.results || []);

    const totalPedidos = orders.length;
    const totalValor = orders.reduce((s, o) => s + (o.total_value || 0), 0);
    const comBling = orders.filter(o => o.bling_pedido_id).length;
    const pagos = orders.filter(o => o.pago === 1).length;

    const porTipo = {};
    for (const o of orders) { const t = o.tipo_pagamento || 'indefinido'; if (!porTipo[t]) porTipo[t] = { qtd: 0, valor: 0 }; porTipo[t].qtd++; porTipo[t].valor += o.total_value || 0; }

    const errosCount = await env.DB.prepare(
      `SELECT COUNT(*) as c FROM integration_audit WHERE status='error' AND created_at BETWEEN ? AND ?`
    ).bind(dateStart, dateEnd).first().then(r => r?.c || 0).catch(() => 0);

    const snapshot = { totalPedidos, totalValor: Math.round(totalValor * 100) / 100, comBling, semBling: totalPedidos - comBling, pagos, naoPagos: totalPedidos - pagos, porTipo, errosIntegracao: errosCount };

    await env.DB.prepare('INSERT INTO audit_snapshots (snapshot_date, data_json) VALUES (?, ?)').bind(yesterday, JSON.stringify(snapshot)).run();
    console.log(`[audit] Snapshot ${yesterday} salvo: ${totalPedidos} pedidos, R$${snapshot.totalValor}`);
  } catch (e) { console.error('[audit] Snapshot error:', e.message); }
}
