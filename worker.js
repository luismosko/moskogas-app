// v2.25.2
// =============================================================
// MOSKOGAS BACKEND v2 — Cloudflare Worker (ES Module)
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
  await env.DB.prepare("ALTER TABLE app_users ADD COLUMN pode_entregar INTEGER DEFAULT 0").run().catch(()=>{});
  await env.DB.prepare("ALTER TABLE app_users ADD COLUMN recebe_whatsapp INTEGER DEFAULT 0").run().catch(()=>{});
  // Set defaults: entregadores existentes ganham pode_entregar=1, recebe_whatsapp=1
  await env.DB.prepare("UPDATE app_users SET pode_entregar=1, recebe_whatsapp=1 WHERE role='entregador' AND pode_entregar=0 AND recebe_whatsapp=0 AND ativo=1").run().catch(()=>{});
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
  )`).run().catch(()=>{});
  await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_login_ip ON login_attempts(ip, created_at)').run().catch(()=>{});
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
  ).bind(ip, loginUsado || '', sucesso ? 1 : 0).run().catch(() => {});
  // Limpar tentativas antigas (>24h)
  const ontem = Math.floor(Date.now() / 1000) - 86400;
  await env.DB.prepare('DELETE FROM login_attempts WHERE created_at < ?').bind(ontem).run().catch(() => {});
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
    throw new Error('bling_reauth_required:' + resp.status + ':' + errBody.substring(0,100));
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
  } catch(e) {
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
    } catch(e) {
      return new Response(JSON.stringify({ error: 'bling_reauth_required', message: 'Sessão Bling expirada. Reautorize em Config → Conectar Bling.' }), { status: 401, headers: { 'Content-Type': 'application/json' } });
    }
  }

  return resp;
}

// ── Formas de pagamento mapeadas (IDs do Bling da Mosko Gás) ──────
const FORMAS_PAGAMENTO = {
  dinheiro:      { id: 23368,   descricao: 'Dinheiro',           tipoPagamento: 1  },
  pix:           { id: 3138153, descricao: 'PIX (Bradesco)',      tipoPagamento: 16 },
  pix_itau:      { id: 9052024, descricao: 'ITAU PIX, TED',      tipoPagamento: 18 },
  debito:        { id: 188552,  descricao: 'Cartão Débito',       tipoPagamento: 4  },
  credito:       { id: 188555,  descricao: 'Cartão Crédito',      tipoPagamento: 3  },
  fiado:         { id: 188534,  descricao: 'Duplicata Mercantil', tipoPagamento: 14 },
  pix_aguardando:{ id: 9315924, descricao: 'PIX Aguardando (Bradesco)', tipoPagamento: 18 },
};

const CONSUMIDOR_FINAL_ID = 726746364;

// ── Mapeia tipo_pagamento → forma de pagamento Bling ──────────
function getFormaPagamentoForTipo(tipoPg, formaKey, formaId) {
  if (formaId) return formaId;
  if (formaKey && FORMAS_PAGAMENTO[formaKey]) return FORMAS_PAGAMENTO[formaKey].id;
  switch (tipoPg) {
    case 'dinheiro':    return FORMAS_PAGAMENTO.dinheiro.id;
    case 'pix_vista':   return FORMAS_PAGAMENTO.pix.id;
    case 'pix_receber': return FORMAS_PAGAMENTO.pix_aguardando.id;
    case 'debito':      return FORMAS_PAGAMENTO.debito.id;
    case 'credito':     return FORMAS_PAGAMENTO.credito.id;
    case 'mensalista':  return FORMAS_PAGAMENTO.fiado.id;
    case 'boleto':      return FORMAS_PAGAMENTO.fiado.id;
    case 'nfe':         return FORMAS_PAGAMENTO.fiado.id;
    default:            return FORMAS_PAGAMENTO.dinheiro.id;
  }
}

function buildItemBling(item) {
  const blingId = item.bling_id || item.id || null;
  const code = item.code || item.sku || '';
  const desc = String(item.name || 'Produto').substring(0, 120);
  const result = {
    descricao: desc,
    quantidade: item.qty || 1,
    valor: item.price || 0,
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
  const total = total_value || itensBling.reduce((s, i) => s + i.valor * i.quantidade, 0);

  const obsVendedor = vendedor_nome ? ` | ${vendedor_nome}` : '';
  const obsTipo = tipo_pagamento ? ` | ${tipo_pagamento}` : '';

  // v2.17.0: Só vincula contato real no Bling se cliente tem CPF/CNPJ
  // Sem CPF → Consumidor Final (evita erro de pendência cadastral na NFCe)
  const usarContatoReal = bling_contact_id && cpf_cnpj && cpf_cnpj.replace(/\D/g, '').length >= 11;

  const pedidoBody = {
    contato:  usarContatoReal ? { id: bling_contact_id } : { id: CONSUMIDOR_FINAL_ID, tipoPessoa: 'F' },
    data:     today,
    dataSaida: today,
    itens:    itensBling,
    parcelas: [{
      formaPagamento: { id: fpId },
      valor:          total,
      dataVencimento: today,
    }],
    observacoes: `MoskoGás #${orderId}${obsVendedor}${obsTipo} - ${name}`,
  };

  if (bling_vendedor_id) {
    pedidoBody.vendedor = { id: bling_vendedor_id };
  }

  await logEvent(env, orderId, 'bling_payload', { itens: itensBling, contato: pedidoBody.contato }).catch(() => {});

  const pedidoResp = await blingFetch('/pedidos/vendas', {
    method: 'POST',
    body: JSON.stringify(pedidoBody),
  }, env);

  if (!pedidoResp.ok) {
    const errText = await pedidoResp.text();
    console.error('[Bling] Pedido venda erro:', pedidoResp.status, errText);
    await logEvent(env, orderId, 'bling_error_detail', { status: pedidoResp.status, body: errText.substring(0, 500) }).catch(() => {});
    await logBlingAudit(env, orderId, 'criar_venda', 'error', {
      request_payload: pedidoBody,
      error_message: `HTTP ${pedidoResp.status}: ${errText.substring(0, 300)}`
    });
    throw new Error(`Bling pedido ${pedidoResp.status}: ${errText.substring(0, 300)}`);
  }

  const pedidoData = await pedidoResp.json();
  const bling_pedido_id  = pedidoData.data?.id  ?? null;
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

// ── IzChat WhatsApp ───────────────────────────────────────────

async function sendWhatsApp(env, to, message) {
  const resp = await fetch('https://chatapi.izchat.com.br/api/messages/send', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${env.IZCHAT_TOKEN}`,
    },
    body: JSON.stringify({ number: to, body: message }),
  });
  const data = await resp.json().catch(() => ({}));
  return { ok: resp.ok, status: resp.status, data };
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
  )`).run().catch(() => {});
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
  )`).run().catch(() => {});
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS audit_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    snapshot_date TEXT NOT NULL,
    data_json TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now'))
  )`).run().catch(() => {});
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS order_status_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id INTEGER NOT NULL,
    status_anterior TEXT NOT NULL,
    status_novo TEXT NOT NULL,
    motivo TEXT,
    usuario_id INTEGER,
    usuario_nome TEXT,
    created_at TEXT DEFAULT (datetime('now'))
  )`).run().catch(() => {});
  // Migração: coluna cancel_motivo em orders
  await env.DB.prepare(`ALTER TABLE orders ADD COLUMN cancel_motivo TEXT`).run().catch(() => {});
  // Tabela config (key-value)
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS app_config (
    key TEXT PRIMARY KEY, value TEXT, updated_at TEXT DEFAULT (datetime('now'))
  )`).run().catch(() => {});
  // Índices para consulta de pedidos (performance)
  await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_orders_created ON orders(created_at)').run().catch(() => {});
  await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_orders_status ON orders(status)').run().catch(() => {});
  await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_orders_customer ON orders(customer_name)').run().catch(() => {});
  await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_orders_phone ON orders(phone_digits)').run().catch(() => {});
  await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_orders_driver ON orders(driver_name_cache)').run().catch(() => {});
  await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_orders_pago ON orders(pago)').run().catch(() => {});
  await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_orders_bling ON orders(bling_pedido_id)').run().catch(() => {});
  // Produtos favoritos (v2.23.0)
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS product_favorites (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    bling_id TEXT NOT NULL,
    name TEXT NOT NULL,
    code TEXT DEFAULT '',
    price REAL DEFAULT 0,
    sort_order INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now'))
  )`).run().catch(() => {});
  await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_orders_bairro ON orders(bairro)').run().catch(() => {});
}

// ── Contratos (Comodato) — Tabelas e Helpers ─────────────────

async function ensureContractTables(env) {
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS contracts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    numero TEXT NOT NULL UNIQUE,
    status TEXT DEFAULT 'draft',
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
  )`).run().catch(() => {});

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
  )`).run().catch(() => {});

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
  )`).run().catch(() => {});

  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS contract_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    contract_id INTEGER NOT NULL,
    evento TEXT NOT NULL,
    detalhes TEXT,
    usuario_id INTEGER,
    usuario_nome TEXT,
    created_at INTEGER DEFAULT (unixepoch())
  )`).run().catch(() => {});

  await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_contracts_status ON contracts(status)').run().catch(() => {});
  await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_contracts_numero ON contracts(numero)').run().catch(() => {});
  await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_csigners_contract ON contract_signers(contract_id)').run().catch(() => {});
  await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_cattach_contract ON contract_attachments(contract_id)').run().catch(() => {});
  await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_cevents_contract ON contract_events(contract_id)').run().catch(() => {});
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
  if (!resp.ok) {
    const errBody = await resp.text().catch(() => '');
    throw new Error(`Assinafy create signer failed (${resp.status}): ${errBody}`);
  }
  const result = await resp.json();
  return result.data || result;
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
${mapsLink}`;
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
    } catch(e) { lastError = e.message; }
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
    const ph   = batch.map(() => '(?,?,?)').join(',');
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
    };
  });
}

async function saveContactsCache(result, env) {
  for (const r of result) {
    if (r.phone_digits || r.bling_contact_id) {
      try {
        await env.DB.prepare(`
          INSERT OR REPLACE INTO customers_cache (phone_digits, name, address_line, bairro, complemento, bling_contact_id, updated_at)
          VALUES (?, ?, ?, ?, ?, ?, unixepoch())
        `).bind(r.phone_digits||null, r.name, r.address_line, r.bairro, r.complemento, r.bling_contact_id||null).run();
      } catch(_) {}
    }
  }
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
      } catch(_) {}
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
      } catch(e) {
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
          const minutesLeft = Math.floor(((row.obtained_at||0) + (row.expires_in||3600) - now) / 60);
          return json({ ok: true, connected: true, minutesLeft, message: `Token válido e testado (${minutesLeft}min)` });
        }

        console.log('[keep-alive] Token rejeitado pelo Bling (status ' + testResp.status + '), tentando refresh...');
        try {
          const newToken = await refreshBlingToken(env, row.refresh_token);
          console.log('[keep-alive] Token renovado com sucesso!');
          const newRow = await getTokenRow(env);
          const now2 = Math.floor(Date.now() / 1000);
          const ml2 = Math.floor(((newRow.obtained_at||0) + (newRow.expires_in||3600) - now2) / 60);
          return json({ ok: true, connected: true, minutesLeft: ml2, refreshed: true, message: `Token renovado! (${ml2}min)` });
        } catch(refreshErr) {
          console.error('[keep-alive] Refresh falhou:', refreshErr.message);
          return json({ ok: false, connected: false, error: 'refresh_failed: ' + refreshErr.message, message: 'Token expirado e refresh falhou. Reautorize em Config.' });
        }
      } catch(e) {
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
        const formasPgto = fpResp.ok  ? (await fpResp.json()).data : { error: fpResp.status };
        return json({ depositos, formasPgto });
      } catch(e) {
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
      } catch(_) { return json([]); }
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
      } catch(e) { return json({ ok: false, letter, error: e.message }, 500); }
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
      } catch(_) { return json({ bairros: [] }); }
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
        if (!resp.ok) return json({ error: 'not_found' }, 404);
        const data = await resp.json();
        const c = data.data || data;
        const end = (c.endereco && c.endereco.geral) ? c.endereco.geral : (c.endereco || {});
        const rua = (end.endereco || end.logradouro || '').trim();
        const num = (end.numero || '').trim();
        const address_line = num ? `${rua}, ${num}` : rua;
        const phone = (c.celular || c.telefone || c.fone || '').replace(/\D/g, '');
        const result = { name: c.nome, phone_digits: phone, address_line, bairro: end.bairro || '', complemento: end.complemento || '', referencia: '', bling_contact_id: c.id };
        if (phone || address_line) {
          await env.DB.prepare(`INSERT OR REPLACE INTO customers_cache (phone_digits, name, address_line, bairro, complemento, bling_contact_id, updated_at) VALUES (?, ?, ?, ?, ?, ?, unixepoch())`).bind(phone || null, result.name, address_line, result.bairro, result.complemento, c.id).run();
        }
        return json(result);
      } catch(e) { return json({ error: e.message }, 500); }
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
      if (!resp.ok) return err('oauth_failed:' + resp.status);
      const data = await resp.json();
      await saveToken(env, data);
      return json({ ok: true, message: 'Token salvo com sucesso!' });
    }

    if (method === 'POST' && path === '/izchat/notificar-entrega') {
      const auth = requireApiKey(request, env);
      if (auth) return auth;
      const body = await request.json();
      const result = await sendWhatsApp(env, body.to, body.message);
      return json(result);
    }

    if (method === 'GET' && path === '/izchat/teste') {
      const to = url.searchParams.get('to');
      if (!to) return err('missing to');
      const result = await sendWhatsApp(env, to, '✅ Teste MoskoGás — Sistema funcionando!');
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
      } catch(e) { return json({ ok: false, error: e.message }); }
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
        const today = new Date().toISOString().slice(0,10);
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
      } catch(e) { return json({ ok: false, error: e.message }); }
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
      await env.DB.prepare('DELETE FROM auth_sessions WHERE expires_at < ?').bind(now).run().catch(() => {});
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
      if (token) await env.DB.prepare('DELETE FROM auth_sessions WHERE token = ?').bind(token).run().catch(() => {});
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

    // Contratos e webhooks têm auth próprio (requireAuth ou público)
    if (!path.startsWith('/api/contratos') && !path.startsWith('/api/webhooks')) {
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
            .bind(nome, login.toLowerCase().trim(), hash, salt, role||'entregador', bling_vendedor_id||null, bling_vendedor_nome||null, telefone||null, pode_entregar?1:0, recebe_whatsapp?1:0, ativo !== undefined ? (ativo?1:0) : 1, id).run();
        } else {
          await env.DB.prepare('UPDATE app_users SET nome=?, login=?, role=?, bling_vendedor_id=?, bling_vendedor_nome=?, telefone=?, pode_entregar=?, recebe_whatsapp=?, ativo=?, updated_at=unixepoch() WHERE id=?')
            .bind(nome, login.toLowerCase().trim(), role||'entregador', bling_vendedor_id||null, bling_vendedor_nome||null, telefone||null, pode_entregar?1:0, recebe_whatsapp?1:0, ativo !== undefined ? (ativo?1:0) : 1, id).run();
        }
        if (ativo !== undefined && !ativo) {
          await env.DB.prepare('DELETE FROM auth_sessions WHERE user_id = ?').bind(id).run().catch(() => {});
        }
        return json({ ok: true, id });
      } else {
        if (!senha) return err('Senha obrigatória para novo usuário');
        const dup = await env.DB.prepare('SELECT id FROM app_users WHERE login = ?').bind(login.toLowerCase().trim()).first();
        if (dup) return err('Login já existe');
        const salt = crypto.randomUUID();
        const hash = await hashPassword(senha, salt);
        const result = await env.DB.prepare('INSERT INTO app_users (nome, login, senha_hash, senha_salt, role, bling_vendedor_id, bling_vendedor_nome, telefone, pode_entregar, recebe_whatsapp, ativo) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)')
          .bind(nome, login.toLowerCase().trim(), hash, salt, role||'entregador', bling_vendedor_id||null, bling_vendedor_nome||null, telefone||null, pode_entregar?1:0, recebe_whatsapp?1:0, ativo !== undefined ? (ativo?1:0) : 1).run();
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
            } catch(_) {}
          }
          return {
            id: v.id,
            name: name || ('Vendedor #' + v.id),
            contato_id: contatoId,
            situacao: v.contato?.situacao || v.situacao || '',
          };
        }));
        return json(result);
      } catch(e) { return json([]); }
    }

    if (method === 'GET' && path === '/api/products/search') {
      const q = (url.searchParams.get('q') || '').trim().toLowerCase();
      try {
        const blingUrl = q.length >= 2 ? `/produtos?pagina=1&limite=50&criterio=1&pesquisa=${encodeURIComponent(q)}` : `/produtos?pagina=1&limite=50&criterio=1`;
        const resp = await blingFetch(blingUrl, {}, env);
        if (!resp.ok) { const errText = await resp.text().catch(() => ''); return json({ error: `Bling ${resp.status}: ${errText.substring(0,200)}` }, 502); }
        const data = await resp.json();
        const all = (data.data || []);
        const filtered = q ? all.filter(p => { const nome = (p.descricao||p.nome||'').toLowerCase(); return nome.includes(q); }) : all;
        const produtos = (filtered.length ? filtered : all).map(p => ({ id: p.id, name: p.descricao||p.nome||'', code: p.codigo||'', price: parseFloat(p.preco)||0, unit: p.unidade||'un' }));
        return json(produtos.slice(0, 15));
      } catch(e) { return json({ error: e.message }, 500); }
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
      const qName  = (url.searchParams.get('name')  || '').trim();
      const qAddr  = (url.searchParams.get('addr')  || '').trim();
      const results = []; const seenPhone = new Set();

      { let sql = 'SELECT * FROM customers_cache WHERE 1=1'; const p = [];
        if (qPhone) { sql += ' AND phone_digits LIKE ?'; p.push(`%${qPhone}%`); }
        if (qName)  { sql += ' AND name LIKE ?';         p.push(`%${qName}%`); }
        if (qAddr)  { sql += ' AND (address_line LIKE ? OR bairro LIKE ?)'; p.push(`%${qAddr}%`, `%${qAddr}%`); }
        sql += ' ORDER BY name ASC LIMIT 15';
        const rows = await env.DB.prepare(sql).bind(...p).all().then(r => r.results || []);
        for (const r of rows) { if (!seenPhone.has(r.phone_digits)) { seenPhone.add(r.phone_digits); results.push(r); } }
      }

      if (qAddr || qName) {
        const addrCond = qAddr ? '(ca.address_line LIKE ? OR ca.bairro LIKE ? OR ca.obs LIKE ?)' : null;
        const nameCond = qName ? '(cc.name LIKE ? OR ca.obs LIKE ?)' : null;
        const conditions = [addrCond, nameCond].filter(Boolean).join(' AND ');
        let sql2 = `SELECT cc.*, ca.address_line AS ca_addr, ca.bairro AS ca_bairro, ca.complemento AS ca_comp, ca.referencia AS ca_ref, ca.obs AS ca_obs FROM customer_addresses ca JOIN customers_cache cc ON cc.phone_digits = ca.phone_digits WHERE ${conditions}`;
        const p2 = [];
        if (qAddr) p2.push(`%${qAddr}%`, `%${qAddr}%`, `%${qAddr}%`);
        if (qName) p2.push(`%${qName}%`, `%${qName}%`);
        if (qPhone) { sql2 += ' AND ca.phone_digits LIKE ?'; p2.push(`%${qPhone}%`); }
        sql2 += ' ORDER BY cc.name ASC LIMIT 15';
        const extraRows = await env.DB.prepare(sql2).bind(...p2).all().then(r => r.results || []);
        for (const r of extraRows) {
          const enriched = { ...r, address_line: r.ca_addr||r.address_line, bairro: r.ca_bairro||r.bairro, complemento: r.ca_comp||r.complemento, referencia: r.ca_ref||r.referencia, _extra_obs: r.ca_obs };
          if (!seenPhone.has(r.phone_digits)) { seenPhone.add(r.phone_digits); results.push(enriched); }
          else { const idx = results.findIndex(x => x.phone_digits === r.phone_digits); if (idx >= 0) results[idx] = enriched; }
        }
      }

      if (results.length < 5) {
        try {
          const blingQ = qName || qAddr;
          if (blingQ) {
            const resp = await blingFetch(`/contatos?pagina=1&limite=20&pesquisa=${encodeURIComponent(blingQ)}`, {}, env);
            if (resp.ok) {
              const data = await resp.json();
              const ql_name = qName.toLowerCase(); const ql_addr = qAddr.toLowerCase();
              const filtrados = (data.data || []).filter(cont => {
                const nome = (cont.nome||'').toLowerCase();
                const end = cont.endereco || {};
                const rua = ((end.geral?.endereco||end.endereco||'')+' '+(end.geral?.bairro||end.bairro||'')).toLowerCase();
                const fone = (cont.celular||cont.telefone||'').replace(/\D/g,'');
                return (!qName||nome.includes(ql_name)) && (!qAddr||rua.includes(ql_addr)) && (!qPhone||fone.includes(qPhone));
              });
              const blingRows = mapContatos(filtrados);
              if (blingRows.length) await saveContactsCache(blingRows, env);
              for (const r of blingRows) { if (!seenPhone.has(r.phone_digits)) { seenPhone.add(r.phone_digits); results.push(r); } }
            }
          }
        } catch(_) {}
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
        } catch(_) {}
        return json([]);
      }

      if (type === 'address') {
        const cacheRows = await env.DB.prepare("SELECT * FROM customers_cache WHERE address_line LIKE ? OR bairro LIKE ? LIMIT 10").bind(`%${q}%`, `%${q}%`).all().then(r => r.results);
        let multiRows = [];
        try {
          const mr = await env.DB.prepare(`SELECT ca.phone_digits, ca.address_line, ca.bairro, ca.complemento, ca.referencia, ca.obs, cc.name FROM customer_addresses ca LEFT JOIN customers_cache cc ON cc.phone_digits = ca.phone_digits WHERE ca.obs LIKE ? OR ca.address_line LIKE ? OR ca.bairro LIKE ? LIMIT 10`).bind(`%${q}%`, `%${q}%`, `%${q}%`).all().then(r => r.results);
          multiRows = mr.map(r => ({ name: r.name||r.phone_digits, phone_digits: r.phone_digits, address_line: r.address_line, bairro: r.bairro, complemento: r.complemento, referencia: r.referencia, obs: r.obs }));
        } catch(_) {}
        const orderRows = await env.DB.prepare(`SELECT DISTINCT customer_name AS name, phone_digits, address_line, bairro, complemento, referencia FROM orders WHERE address_line LIKE ? OR bairro LIKE ? ORDER BY created_at DESC LIMIT 10`).bind(`%${q}%`, `%${q}%`).all().then(r => r.results);
        let blingRows = [];
        try {
          const resp = await blingFetch(`/contatos?pagina=1&limite=20&pesquisa=${encodeURIComponent(q)}`, {}, env);
          if (resp.ok) {
            const data = await resp.json(); const ql = q.toLowerCase();
            const filtrados = (data.data||[]).filter(c => { const end = ((c.endereco?.geral?.endereco||c.endereco?.endereco||'')+' '+(c.endereco?.geral?.bairro||c.endereco?.bairro||'')).toLowerCase(); return end.includes(ql); });
            blingRows = mapContatos(filtrados); if (blingRows.length > 0) await saveContactsCache(blingRows, env);
          }
        } catch(_) {}
        const seen = new Set();
        const merged = [...multiRows, ...blingRows, ...cacheRows, ...orderRows].filter(r => { const key = r.phone_digits||r.name||Math.random(); if (seen.has(key)) return false; seen.add(key); return true; });
        return json(merged.slice(0, 12));
      }

      // Nome
      let blingByName = [];
      try {
        const resp = await blingFetch(`/contatos?pagina=1&limite=30&pesquisa=${encodeURIComponent(q)}`, {}, env);
        if (resp.ok) {
          const data = await resp.json(); const ql = q.toLowerCase();
          const filtrados = (data.data||[]).filter(c => (c.nome||'').toLowerCase().includes(ql)||(c.fantasia||'').toLowerCase().includes(ql));
          blingByName = mapContatos(filtrados); if (blingByName.length > 0) await saveContactsCache(blingByName, env);
        }
      } catch(_) {}
      const cacheByName = await env.DB.prepare("SELECT * FROM customers_cache WHERE name LIKE ? ORDER BY name LIMIT 20").bind(`%${q}%`).all().then(r => r.results || []);
      const orderByName = await env.DB.prepare(`SELECT DISTINCT customer_name AS name, phone_digits, address_line, bairro, complemento, referencia FROM orders WHERE customer_name LIKE ? ORDER BY created_at DESC LIMIT 10`).bind(`%${q}%`).all().then(r => r.results || []);
      const seenId = new Set(); const seenName = new Set(); const merged = [];
      for (const r of [...blingByName, ...cacheByName, ...orderByName]) {
        const bid = r.bling_contact_id ? String(r.bling_contact_id) : null;
        const nome = (r.name||'').trim().toLowerCase();
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
      for (const col of extraCols) { await env.DB.prepare(`ALTER TABLE customers_cache ADD COLUMN ${col}`).run().catch(() => {}); }

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
          const errMsg = bData?.error?.message || bData?.error?.description || JSON.stringify(bData).substring(0, 300);
          return json({ ok: false, error: errMsg, bling_status: bResp.status });
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
      } catch(e) {
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
    if (path.startsWith('/api/app-products')) {
      await env.DB.prepare(`CREATE TABLE IF NOT EXISTS app_products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        bling_id TEXT,
        name TEXT NOT NULL,
        code TEXT DEFAULT '',
        price REAL DEFAULT 0,
        is_favorite INTEGER DEFAULT 0,
        sort_order INTEGER DEFAULT 0,
        ativo INTEGER DEFAULT 1,
        created_at TEXT DEFAULT (datetime('now'))
      )`).run().catch(()=>{});
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
      return json(rows);
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
        ).bind(bling_id||null, name, code||'', parseFloat(price)||0, is_favorite?1:0, sort_order||0, ativo!==undefined?(ativo?1:0):1, id).run();
        return json({ ok: true, id });
      } else {
        // Insert
        const maxSort = await env.DB.prepare('SELECT MAX(sort_order) as mx FROM app_products').first();
        const result = await env.DB.prepare(
          `INSERT INTO app_products (bling_id, name, code, price, is_favorite, sort_order, ativo) VALUES (?,?,?,?,?,?,?)`
        ).bind(bling_id||null, name, code||'', parseFloat(price)||0, is_favorite?1:0, (maxSort?.mx||0)+1, 1).run();
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
      ).bind(String(bling_id||''), name, code||'', parseFloat(price)||0, is_favorite?1:0, (maxSort?.mx||0)+1).run();
      return json({ ok: true, id: result.meta?.last_row_id });
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
      } catch(e) { return json({ results: [], error: e.message }); }
    }

    if (method === 'POST' && path === '/api/customer/upsert') {
      const body = await request.json();
      const { phone, name, address_line, bairro, complemento, referencia } = body;
      const digits = (phone || '').replace(/\D/g, '');
      await env.DB.prepare(`INSERT OR REPLACE INTO customers_cache (phone_digits, name, address_line, bairro, complemento, referencia, updated_at) VALUES (?, ?, ?, ?, ?, ?, unixepoch())`).bind(digits, name, address_line, bairro, complemento, referencia).run();
      // v2.17.0: NÃO cria contato no Bling aqui — só cliente com CPF/CNPJ cadastrado via /customer/save-bling cria contato
      return json({ ok: true });
    }

    // ── PEDIDOS ──────────────────────────────────────────────

    if (method === 'POST' && path === '/api/order/create') {
      const body = await request.json();
      const { phone, name, address_line, bairro, complemento, referencia, items, total_value, notes, emitir_nfce, forma_pagamento_key, forma_pagamento_id, bling_contact_id, tipo_pagamento } = body;
      const digits = (phone || '').replace(/\D/g, '');

      const cols = ['forma_pagamento_id INTEGER','forma_pagamento_key TEXT','emitir_nfce INTEGER','nfce_gerada INTEGER','nfce_numero TEXT','nfce_chave TEXT','bling_pedido_id INTEGER','bling_pedido_num INTEGER','pago INTEGER DEFAULT 0','tipo_pagamento TEXT','vendedor_id INTEGER','vendedor_nome TEXT','foto_comprovante TEXT','observacao_entregador TEXT','tipo_pagamento_original TEXT','delivered_at TEXT'];
      for (const col of cols) { await env.DB.prepare(`ALTER TABLE orders ADD COLUMN ${col}`).run().catch(() => {}); }

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
      `).bind(digits||'', name||'', address_line||'', bairro||'', complemento||'', referencia||'', JSON.stringify(items||[]), total_value!=null?total_value:null, notes||null, forma_pagamento_key||null, forma_pagamento_id!=null?Number(forma_pagamento_id):null, emitir_nfce?1:0, tipoPg, pago, vendedorId, vendedorNome).run();

      const orderId = result.meta?.last_row_id;
      await env.DB.prepare('INSERT OR IGNORE INTO payments (order_id, status, method) VALUES (?, ?, ?)').bind(orderId, 'pendente', forma_pagamento_key||null).run();
      await logEvent(env, orderId, 'created', { name, address_line, tipo_pagamento: tipoPg, pago, vendedor: vendedorNome });
      await logBlingAudit(env, orderId, 'criar_venda', 'skipped', { error_message: `Bling será criado ao marcar entregue` });

      return json({ ok: true, id: orderId, bling_pedido_id: null, pago, vendedor: vendedorNome });
    }

    // [REMOVIDO v2.12.0] POST /api/order/:id/gerar-nfce — NFCe não existe na API Bling v3

    if (method === 'POST' && path === '/api/bling/debug-pedido') {
      try {
        const body = await request.json();
        const { items, total_value, forma_pagamento_key, forma_pagamento_id } = body;
        const today = new Date().toISOString().slice(0, 10);
        const fpId = forma_pagamento_id || FORMAS_PAGAMENTO[forma_pagamento_key]?.id || 23368;
        const total = total_value || (items||[]).reduce((s,i) => s + (i.price||0)*(i.qty||1), 0);
        const itensBling = (items||[]).map(it => buildItemBling(it));
        const payload = { contato: { id: CONSUMIDOR_FINAL_ID, tipoPessoa: 'F' }, data: today, dataSaida: today, itens: itensBling, parcelas: [{ formaPagamento: { id: fpId }, valor: total, dataVencimento: today }] };
        const resp = await blingFetch('/pedidos/vendas', { method: 'POST', body: JSON.stringify(payload) }, env);
        const result = await resp.json();
        return json({ payload_sent: payload, bling_status: resp.status, bling_response: result });
      } catch(e) { return json({ error: e.message }); }
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
          try { if (permRow?.value) perms = { ...perms, ...JSON.parse(permRow.value) }; } catch {}
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
      const params = [customer_name, phone_digits||'', address_line||'', bairro||'', complemento||'', referencia||'', JSON.stringify(items||[]), total_value||0, notes||''];
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
      if (q) { sql += ` AND (o.customer_name LIKE ? OR o.phone_digits LIKE ? OR o.address_line LIKE ?)`; params.push(`%${q}%`, `%${q}%`, `%${q}%`); }
      sql += ' ORDER BY o.created_at DESC LIMIT 200';
      const rows = await env.DB.prepare(sql).bind(...params).all();
      return json(rows.results || []);
    }

    const selectDriverMatch = path.match(/^\/api\/order\/(\d+)\/select-driver$/);
    if (method === 'POST' && selectDriverMatch) {
      const id = selectDriverMatch[1];
      const user = await getSessionUser(request, env);
      const { driver_id } = await request.json();
      const driver = await env.DB.prepare('SELECT id, nome, telefone FROM app_users WHERE id=?').bind(driver_id).first();
      if (!driver) return err('driver not found');
      await env.DB.prepare(`UPDATE orders SET driver_id=?, driver_name_cache=?, driver_phone_cache=?, status='encaminhado', updated_at=unixepoch() WHERE id=?`).bind(driver_id, driver.nome, driver.telefone || '', id).run();
      await logEvent(env, id, 'driver_selected', { driver_id, driver_name: driver.nome });
      const prevOrder = await env.DB.prepare('SELECT status FROM orders WHERE id=?').bind(id).first();
      await logStatusChange(env, id, 'novo', 'encaminhado', `Entregador: ${driver.nome}`, user);
      return json({ ok: true, status: 'encaminhado' });
    }

    const sendWaMatch = path.match(/^\/api\/order\/(\d+)\/send-whatsapp$/);
    if (method === 'POST' && sendWaMatch) {
      const id = sendWaMatch[1];
      const { observation, driver_id } = await request.json();
      let order = await env.DB.prepare('SELECT * FROM orders WHERE id=?').bind(id).first();
      if (!order) return err('order not found', 404);
      if (driver_id && !order.driver_id) {
        const driver = await env.DB.prepare('SELECT id, nome, telefone FROM app_users WHERE id=?').bind(driver_id).first();
        if (driver) {
          await env.DB.prepare(`UPDATE orders SET driver_id=?, driver_name_cache=?, driver_phone_cache=?, status='encaminhado', updated_at=unixepoch() WHERE id=?`).bind(driver_id, driver.nome, driver.telefone || '', id).run();
          order = { ...order, driver_id, driver_name_cache: driver.nome, driver_phone_cache: driver.telefone || '' };
        }
      }
      if (!order.driver_id) return err('Nenhum entregador selecionado');
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
      const result = await sendWhatsApp(env, order.driver_phone_cache, message);
      if (result.ok) {
        await env.DB.prepare(`UPDATE orders SET status='whatsapp_enviado', whatsapp_sent_at=unixepoch(), updated_at=unixepoch() WHERE id=?`).bind(id).run();
        await logEvent(env, id, 'whatsapp_sent', { to: order.driver_phone_cache });
        return json({ ok: true, status: 'whatsapp_enviado' });
      } else { return json({ ok: false, error: 'IzChat falhou', detail: result }, 500); }
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

        console.log(`[R2] Foto salva: ${photoKey} (${(photoFile.size/1024).toFixed(1)}KB)`);
      } else if (ct.includes('application/json')) {
        // Fallback JSON (sem foto — só admin pode)
        const body = await request.json();
        tipoPagamento = body.tipo_pagamento || null;
        obsEntregador = body.observacao_entregador || null;
        // Admin pode marcar sem foto
        if (user?.role !== 'admin') {
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
      let blingResult = null;
      if (!order.bling_pedido_id) {
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

      sql += ` WHERE id=?`;
      params.push(id);

      await env.DB.prepare(sql).bind(...params).run();
      await logEvent(env, id, 'delivered', {
        foto: photoKey,
        tipo_pagamento_changed: tipoPagamento !== order.tipo_pagamento ? tipoPagamento : null,
        observacao: obsEntregador,
      });

      return json({ ok: true, status: 'entregue', foto_key: photoKey, bling_result: blingResult });
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
        try { if (permRow?.value) perms = { ...perms, ...JSON.parse(permRow.value) }; } catch {}
        if (!perms.atendente_cancelar) return err('Sem permissão para cancelar pedido. Peça ao admin.', 403);
      }

      // Motivo obrigatório
      let motivo = '';
      try {
        const body = await request.json();
        motivo = (body.motivo || '').trim();
      } catch (e) {}
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
              const waResult = await sendWhatsApp(env, adm.telefone, msg);
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
      try { body = await request.json(); } catch (e) {}
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
      try { if (permRow?.value) perms = { ...perms, ...JSON.parse(permRow.value) }; } catch {}

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
              await sendWhatsApp(env, adm.telefone, `⚠️ ${user.nome} reverteu pedido #${id}: ${statusAnterior.toUpperCase()} → ${novoStatus.toUpperCase()}\nMotivo: ${motivo}`);
            }
          }
        } catch (_) {} // não bloqueia se WhatsApp falhar
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
      if (dateFrom) { sql += ' AND o.created_at >= ?'; params.push(Math.floor(new Date(dateFrom+'T00:00:00-04:00').getTime()/1000)); }
      if (dateTo) { sql += ' AND o.created_at <= ?'; params.push(Math.floor(new Date(dateTo+'T23:59:59-04:00').getTime()/1000)); }
      sql += ' ORDER BY o.created_at DESC LIMIT 500';
      const rows = await env.DB.prepare(sql).bind(...params).all();
      return json(rows.results || []);
    }

    if (method === 'POST' && path === '/api/payment/set') {
      const { order_id, status, method: payMethod, notes } = await request.json();
      const received_at = status === 'recebido' ? Math.floor(Date.now()/1000) : null;
      await env.DB.prepare(`INSERT INTO payments (order_id, status, method, notes, received_at, updated_at) VALUES (?, ?, ?, ?, ?, unixepoch()) ON CONFLICT(order_id) DO UPDATE SET status=excluded.status, method=excluded.method, notes=excluded.notes, received_at=excluded.received_at, updated_at=excluded.updated_at`).bind(order_id, status, payMethod||null, notes||null, received_at).run();
      return json({ ok: true });
    }

    // ══════════════════════════════════════════════════════════
    // GESTÃO DE PAGAMENTOS — MoskoGás v2.8.0
    // ══════════════════════════════════════════════════════════
    
    if (method === 'GET' && path === '/api/pagamentos') {
      const rows = await env.DB.prepare(`
        SELECT 
          o.id, o.customer_name, o.phone_digits, o.address_line, o.total_value, 
          o.tipo_pagamento, o.pago, o.bling_pedido_id, o.bling_pedido_num,
          o.created_at, o.status, o.items_json,
          o.forma_pagamento_key, o.forma_pagamento_id,
          cc.bling_contact_id
        FROM orders o
        LEFT JOIN customers_cache cc ON cc.phone_digits = o.phone_digits
        WHERE o.pago = 0 AND o.status = 'entregue'
        ORDER BY o.created_at DESC
        LIMIT 200
      `).all();
      return json(rows.results || []);
    }

    if (method === 'PATCH' && /^\/api\/pagamentos\/\d+$/.test(path)) {
      const orderId = parseInt(path.split('/')[3]);
      const order = await env.DB.prepare('SELECT * FROM orders WHERE id=?').bind(orderId).first();
      if (!order) return err('Pedido não encontrado', 404);
      if (order.pago === 1) return json({ ok: true, message: 'Já estava pago' });

      if (!order.bling_pedido_id) {
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
        } catch(e) {
          await logEvent(env, orderId, 'bling_error_on_pay', { error: e.message });
          return json({ ok: false, error: 'Falha ao criar venda no Bling: ' + e.message }, 500);
        }
      }

      await env.DB.prepare('UPDATE orders SET pago=1 WHERE id=?').bind(orderId).run();
      await env.DB.prepare('UPDATE payments SET status=?, received_at=unixepoch() WHERE order_id=?').bind('pago', orderId).run();
      await logBlingAudit(env, orderId, 'marcar_pago', 'success', { bling_pedido_id: order.bling_pedido_id || '' });
      await logEvent(env, orderId, 'payment_confirmed', {});
      return json({ ok: true });
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
        return err(`Pedidos ${invalidos.map(o => '#'+o.id).join(', ')} não são mensalista/boleto`);
      }

      const grupos = {};
      for (const o of orders) {
        const key = o.phone_digits || o.customer_name || 'sem_id_' + o.id;
        if (!grupos[key]) {
          grupos[key] = { cliente: o.customer_name, phone: o.phone_digits, bling_contact_id: o.bling_contact_id || null, cpf_cnpj: o.cpf_cnpj || null, pedidos: [], produtos: {}, total: 0 };
        }
        grupos[key].pedidos.push(o);
        grupos[key].total += o.total_value || 0;
        try {
          const items = JSON.parse(o.items_json || '[]');
          for (const item of items) {
            const prodKey = item.bling_id || item.code || item.name;
            if (!grupos[key].produtos[prodKey]) {
              grupos[key].produtos[prodKey] = { name: item.name, bling_id: item.bling_id || null, code: item.code || item.sku || '', sku: item.code || item.sku || '', qty: 0, price: item.price || 0 };
            }
            grupos[key].produtos[prodKey].qty += item.qty || 1;
          }
        } catch(_) {}
      }

      const resultados = [];
      const today = new Date().toISOString().slice(0, 10);

      for (const [key, grupo] of Object.entries(grupos)) {
        const produtos = Object.values(grupo.produtos);
        const pedidoIds = grupo.pedidos.map(p => p.id);

        const itensBling = produtos.map(p => buildItemBling(p));

        // v2.17.1: Só vincula contato real se tem CPF/CNPJ (>=11 dígitos)
        const usarContatoReal = grupo.bling_contact_id && grupo.cpf_cnpj && grupo.cpf_cnpj.replace(/\D/g, '').length >= 11;

        const pedidoBody = {
          contato: usarContatoReal ? { id: grupo.bling_contact_id } : { id: CONSUMIDOR_FINAL_ID, tipoPessoa: 'F' },
          data: today,
          dataSaida: today,
          itens: itensBling,
          parcelas: [{ formaPagamento: { id: FORMAS_PAGAMENTO.fiado.id }, valor: grupo.total, dataVencimento: today }],
          observacoes: `NFe Agrupada MoskoGás — ${grupo.cliente} — Pedidos: ${pedidoIds.map(i => '#'+i).join(', ')}`,
        };

        try {
          const resp = await blingFetch('/pedidos/vendas', { method: 'POST', body: JSON.stringify(pedidoBody) }, env);

          if (!resp.ok) {
            const errText = await resp.text();
            for (const oid of pedidoIds) {
              await logBlingAudit(env, oid, 'criar_venda_lote', 'error', { request_payload: pedidoBody, error_message: `HTTP ${resp.status}: ${errText.substring(0,200)}` });
            }
            resultados.push({ cliente: grupo.cliente, ok: false, error: `Bling ${resp.status}: ${errText.substring(0, 200)}`, pedidos: pedidoIds });
            continue;
          }

          const pedidoData = await resp.json();
          const blingId  = pedidoData.data?.id ?? null;
          const blingNum = pedidoData.data?.numero ?? null;

          for (const orderId of pedidoIds) {
            await env.DB.prepare('UPDATE orders SET bling_pedido_id=?, bling_pedido_num=?, pago=1, sync_status=? WHERE id=?').bind(blingId, blingNum, 'synced_nfe', orderId).run();
            await env.DB.prepare('UPDATE payments SET status=?, received_at=unixepoch() WHERE order_id=?').bind('pago', orderId).run();
            await logEvent(env, orderId, 'nfe_agrupada', { bling_pedido_id: blingId, bling_pedido_num: blingNum, grupo_pedidos: pedidoIds });
            await logBlingAudit(env, orderId, 'criar_venda_lote', 'success', { bling_pedido_id: String(blingId||''), request_payload: pedidoBody, response_data: pedidoData });
          }

          resultados.push({ cliente: grupo.cliente, ok: true, bling_pedido_id: blingId, bling_pedido_num: blingNum, pedidos: pedidoIds, total: grupo.total, itens_count: itensBling.length });
        } catch(e) {
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

      conditions.push('created_at >= ?'); params.push(data_de + 'T00:00:00');
      conditions.push('created_at <= ?'); params.push(data_ate + 'T23:59:59');

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
      if (cliente) { conditions.push("customer_name LIKE ?"); params.push(`%${cliente}%`); }
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

    // ── CONSULTA DE PEDIDOS (paginada + filtros) ──────────────

    if (method === 'GET' && path === '/api/consulta/pedidos') {
      const authCheck = await requireAuth(request, env, ['admin', 'atendente']);
      if (authCheck instanceof Response) return authCheck;

      const page = Math.max(1, parseInt(url.searchParams.get('page')) || 1);
      const limit = Math.min(50, Math.max(1, parseInt(url.searchParams.get('limit')) || 30));
      const offset = (page - 1) * limit;

      // Período (default 7 dias, máx 90)
      const hoje = new Date().toISOString().slice(0, 10);
      const seteAtras = new Date(Date.now() - 7 * 86400000).toISOString().slice(0, 10);
      const data_de = url.searchParams.get('data_de') || seteAtras;
      const data_ate = url.searchParams.get('data_ate') || hoje;

      // Validar máximo 90 dias
      const diffDias = (new Date(data_ate) - new Date(data_de)) / 86400000;
      if (diffDias > 92) return err('Período máximo: 90 dias', 400);

      const conditions = ['created_at >= ?', 'created_at <= ?'];
      const params = [data_de + 'T00:00:00', data_ate + 'T23:59:59'];

      // Filtros textuais
      const pedido_id = url.searchParams.get('pedido_id');
      const cliente = url.searchParams.get('cliente');
      const telefone = url.searchParams.get('telefone');
      const produto = url.searchParams.get('produto');
      const entregador = url.searchParams.get('entregador');
      const vendedor = url.searchParams.get('vendedor');
      const rua = url.searchParams.get('rua');
      const bairro = url.searchParams.get('bairro');
      const status_f = url.searchParams.get('status');
      const tipo_pagamento = url.searchParams.get('tipo_pagamento');
      const pago = url.searchParams.get('pago');
      const tem_foto = url.searchParams.get('tem_foto');
      const tem_bling = url.searchParams.get('tem_bling');
      const consumidor_final = url.searchParams.get('consumidor_final');

      if (pedido_id) { conditions.push('id = ?'); params.push(parseInt(pedido_id)); }
      if (cliente) { conditions.push("customer_name LIKE ?"); params.push('%' + cliente + '%'); }
      if (telefone) { conditions.push("phone_digits LIKE ?"); params.push('%' + telefone + '%'); }
      if (produto) { conditions.push("items_json LIKE ?"); params.push('%' + produto + '%'); }
      if (entregador) { conditions.push("driver_name_cache = ?"); params.push(entregador); }
      if (vendedor) { conditions.push("vendedor_nome = ?"); params.push(vendedor); }
      if (rua) { conditions.push("address_line LIKE ?"); params.push('%' + rua + '%'); }
      if (bairro) { conditions.push("bairro = ?"); params.push(bairro); }
      if (status_f) { conditions.push("status = ?"); params.push(status_f); }
      if (tipo_pagamento) { conditions.push("tipo_pagamento = ?"); params.push(tipo_pagamento); }
      if (pago === 'sim') conditions.push("pago = 1");
      if (pago === 'nao') conditions.push("pago = 0");
      if (tem_foto === 'sim') conditions.push("foto_comprovante IS NOT NULL AND foto_comprovante != ''");
      if (tem_foto === 'nao') conditions.push("(foto_comprovante IS NULL OR foto_comprovante = '')");
      if (tem_bling === 'sim') conditions.push("bling_pedido_id IS NOT NULL AND bling_pedido_id != ''");
      if (tem_bling === 'nao') conditions.push("(bling_pedido_id IS NULL OR bling_pedido_id = '')");
      if (consumidor_final === 'sim') conditions.push("customer_name = 'CONSUMIDOR FINAL'");

      const where = conditions.join(' AND ');

      // Ordenação
      const validCols = ['created_at', 'total_value', 'customer_name', 'id', 'status'];
      let order_by = url.searchParams.get('order_by') || 'created_at';
      if (!validCols.includes(order_by)) order_by = 'created_at';
      let order_dir = (url.searchParams.get('order_dir') || 'DESC').toUpperCase();
      if (order_dir !== 'ASC' && order_dir !== 'DESC') order_dir = 'DESC';

      // Resumo (COUNT + SUM)
      const resumoSQL = `SELECT
        COUNT(*) as total_pedidos,
        COALESCE(SUM(total_value), 0) as total_valor,
        SUM(CASE WHEN foto_comprovante IS NOT NULL AND foto_comprovante != '' THEN 1 ELSE 0 END) as com_foto,
        SUM(CASE WHEN foto_comprovante IS NULL OR foto_comprovante = '' THEN 1 ELSE 0 END) as sem_foto,
        SUM(CASE WHEN bling_pedido_id IS NOT NULL AND bling_pedido_id != '' THEN 1 ELSE 0 END) as com_bling,
        SUM(CASE WHEN bling_pedido_id IS NULL OR bling_pedido_id = '' THEN 1 ELSE 0 END) as sem_bling,
        SUM(CASE WHEN pago = 1 THEN 1 ELSE 0 END) as pagos,
        SUM(CASE WHEN pago = 0 THEN 1 ELSE 0 END) as nao_pagos
      FROM orders WHERE ${where}`;

      const resumoRow = await env.DB.prepare(resumoSQL).bind(...params).first();

      // Dados paginados
      const dadosSQL = `SELECT id, phone_digits, customer_name, address_line, bairro, complemento, referencia,
        items_json, total_value, notes, status, driver_name_cache, created_at,
        bling_pedido_id, bling_pedido_num, tipo_pagamento, pago, vendedor_nome,
        foto_comprovante, delivered_at, obs_entrega, pagamento_final, cancel_motivo
      FROM orders WHERE ${where} ORDER BY ${order_by} ${order_dir} LIMIT ? OFFSET ?`;

      const dados = await env.DB.prepare(dadosSQL).bind(...params, limit, offset).all();
      const total = resumoRow?.total_pedidos || 0;

      return json({
        ok: true,
        pedidos: dados.results || [],
        resumo: {
          total_pedidos: total,
          total_valor: resumoRow?.total_valor || 0,
          com_foto: resumoRow?.com_foto || 0,
          sem_foto: resumoRow?.sem_foto || 0,
          com_bling: resumoRow?.com_bling || 0,
          sem_bling: resumoRow?.sem_bling || 0,
          pagos: resumoRow?.pagos || 0,
          nao_pagos: resumoRow?.nao_pagos || 0,
        },
        paginacao: { page, limit, total, pages: Math.ceil(total / limit) || 1 }
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
        } catch(_) {}
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

    // ── AUDITORIA ─────────────────────────────────────────────

    if (method === 'GET' && path === '/api/auditoria/diaria') {
      const authCheck = await requireAuth(request, env, ['admin', 'atendente']);
      if (authCheck instanceof Response) return authCheck;
      await ensureAuditTable(env);

      const date = url.searchParams.get('date') || new Date().toISOString().slice(0, 10);
      const dateStart = `${date} 00:00:00`;
      const dateEnd = `${date} 23:59:59`;

      // Pedidos do dia
      const orders = await env.DB.prepare(
        `SELECT id, customer_name, total_value, tipo_pagamento, pago, bling_pedido_id, bling_pedido_num, vendedor_nome, items_json, status, created_at
         FROM orders WHERE created_at BETWEEN ? AND ? ORDER BY id`
      ).bind(dateStart, dateEnd).all().then(r => r.results || []);

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
        } catch(_) {}
      }

      // Erros de integração do dia (com dados do pedido)
      const erros = await env.DB.prepare(
        `SELECT ia.*, o.customer_name, o.total_value, o.tipo_pagamento AS order_tipo, o.bling_pedido_num
         FROM integration_audit ia
         LEFT JOIN orders o ON o.id = ia.order_id
         WHERE ia.status='error' AND ia.created_at BETWEEN ? AND ? ORDER BY ia.id DESC`
      ).bind(dateStart, dateEnd).all().then(r => r.results || []).catch(() => []);

      // Todos os logs de auditoria do dia (com dados do pedido)
      const auditLogs = await env.DB.prepare(
        `SELECT ia.id, ia.order_id, ia.action, ia.status, ia.bling_pedido_id, ia.error_message, ia.created_at,
                o.customer_name, o.total_value, o.tipo_pagamento AS order_tipo, o.vendedor_nome, o.bling_pedido_num
         FROM integration_audit ia
         LEFT JOIN orders o ON o.id = ia.order_id
         WHERE ia.created_at BETWEEN ? AND ? ORDER BY ia.id DESC LIMIT 200`
      ).bind(dateStart, dateEnd).all().then(r => r.results || []).catch(() => []);

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
      const dateStart = `${date} 00:00:00`;
      const dateEnd = `${date} 23:59:59`;

      const orders = await env.DB.prepare(
        `SELECT id, customer_name, total_value, bling_pedido_id, bling_pedido_num, tipo_pagamento FROM orders WHERE created_at BETWEEN ? AND ? AND bling_pedido_id IS NOT NULL AND bling_pedido_id != '' ORDER BY id`
      ).bind(dateStart, dateEnd).all().then(r => r.results || []);

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
        } catch(e) {
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

      await env.BUCKET.delete(att.r2_key).catch(() => {});
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

      await logContractEvent(env, id, 'pdf_generated', `PDF gerado (${Math.round(pdfBytes.byteLength/1024)}KB)`, authCheck);
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
              const izResult = await sendWhatsApp(env, `55${phone}`, msg);
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
          await assinaryResendToSigner(env, contract.assinafy_doc_id, contract.assinafy_assignment_id, signer.assinafy_signer_id).catch(() => {});
        }

        try {
          const msg = `📋 *Lembrete — Contrato de Comodato*\n\nOlá ${signer.nome.split(' ')[0]}!\n\nSeu contrato (${contract.numero}) ainda aguarda sua assinatura.\n\n🔗 Clique para assinar:\n${signer.signing_url}\n\nObrigado!`;
          const izResult = await sendWhatsApp(env, `55${phone}`, msg);
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

    return err('Not found', 404);
  },

  async scheduled(event, env, ctx) {
    ctx.waitUntil(keepBlingTokenFresh(env));
    // Snapshot diário às 22h (cron: 0 1 * * * = 01:00 UTC = 22:00 BRT)
    const hour = new Date().getUTCHours();
    if (hour === 1) { // ~22h Brasília
      ctx.waitUntil(dailyAuditSnapshot(env));
    }
  },
};

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
      console.log(`[cron] Token renovado com sucesso. Novo: ${newToken.substring(0,10)}...`);
    } else {
      console.log('[cron] Token ainda válido.');
    }
  } catch(e) { console.error('[cron] Erro:', e.message); }
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
  } catch(e) { console.error('[audit] Snapshot error:', e.message); }
}
