// v2.12.2
// =============================================================
// MOSKOGAS BACKEND v2 — Cloudflare Worker (ES Module)
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
    ativo INTEGER DEFAULT 1,
    created_at INTEGER DEFAULT (unixepoch()),
    updated_at INTEGER DEFAULT (unixepoch())
  )`).run();
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS auth_sessions (
    token TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    created_at INTEGER DEFAULT (unixepoch()),
    expires_at INTEGER NOT NULL
  )`).run();
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
  const { name, items, total_value, forma_pagamento_key, forma_pagamento_id, bling_contact_id, tipo_pagamento, bling_vendedor_id } = orderData;
  const today = new Date().toISOString().slice(0, 10);

  const itensBling = (items || []).map(it => buildItemBling(it));

  const fpId = getFormaPagamentoForTipo(tipo_pagamento, forma_pagamento_key, forma_pagamento_id);
  const total = total_value || itensBling.reduce((s, i) => s + i.valor * i.quantidade, 0);

  const pedidoBody = {
    contato:  bling_contact_id ? { id: bling_contact_id } : { id: CONSUMIDOR_FINAL_ID, tipoPessoa: 'F' },
    data:     today,
    dataSaida: today,
    itens:    itensBling,
    parcelas: [{
      formaPagamento: { id: fpId },
      valor:          total,
      dataVencimento: today,
    }],
    observacoes: `Pedido MoskoGás #${orderId} - ${name}`,
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
    throw new Error(`Bling pedido ${pedidoResp.status}: ${errText.substring(0, 300)}`);
  }

  const pedidoData = await pedidoResp.json();
  const bling_pedido_id  = pedidoData.data?.id  ?? null;
  const bling_pedido_num = pedidoData.data?.numero ?? null;

  return { bling_pedido_id, bling_pedido_num };
}

// ── [REMOVIDO v2.12.0] criarPedidoEGerarNFCe — NFCe não existe na API Bling v3 ──

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
          observacoes: 'Pedido MoskoGás #' + orderId,
        };
        const resp = await blingFetch('/pedidos/vendas', { method: 'POST', body: JSON.stringify(payload) }, env);
        const txt = await resp.text();
        let parsed; try { parsed = JSON.parse(txt); } catch { parsed = txt; }
        return json({ order_id: orderId, payload_sent: payload, bling_status: resp.status, bling_response: parsed });
      } catch(e) { return json({ ok: false, error: e.message }); }
    }

    // [REMOVIDO v2.12.0] test-nfce — NFCe não existe na API Bling v3

    // ── AUTH: Login / Sessão / Logout (SEM autenticação prévia) ──

    if (method === 'POST' && path === '/api/auth/login') {
      await ensureAuthTables(env);
      const body = await request.json();
      const { login, senha } = body;
      if (!login || !senha) return err('Login e senha obrigatórios');
      const user = await env.DB.prepare('SELECT * FROM app_users WHERE login = ? AND ativo = 1').bind(login.toLowerCase().trim()).first();
      if (!user) return err('Usuário ou senha inválidos', 401);
      const valid = await verifyPassword(senha, user.senha_salt, user.senha_hash);
      if (!valid) return err('Usuário ou senha inválidos', 401);
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

    const authErr = requireApiKey(request, env);
    if (authErr) return authErr;

    // ── AUTH: Gestão de Usuários (requer admin) ─────────────────

    if (method === 'GET' && path === '/api/auth/users') {
      const authCheck = await requireAuth(request, env, ['admin']);
      if (authCheck instanceof Response) return authCheck;
      await ensureAuthTables(env);
      const rows = await env.DB.prepare('SELECT id, nome, login, role, bling_vendedor_id, bling_vendedor_nome, telefone, ativo, created_at FROM app_users ORDER BY nome').all();
      return json(rows.results || []);
    }

    if (method === 'POST' && path === '/api/auth/users') {
      const authCheck = await requireAuth(request, env, ['admin']);
      if (authCheck instanceof Response) return authCheck;
      await ensureAuthTables(env);
      const body = await request.json();
      const { id, nome, login, senha, role, bling_vendedor_id, bling_vendedor_nome, telefone, ativo } = body;
      if (!nome || !login) return err('Nome e login obrigatórios');
      if (!['admin', 'atendente', 'entregador'].includes(role || 'entregador')) return err('Role inválido');

      if (id) {
        const existing = await env.DB.prepare('SELECT * FROM app_users WHERE id = ?').bind(id).first();
        if (!existing) return err('Usuário não encontrado');
        const dup = await env.DB.prepare('SELECT id FROM app_users WHERE login = ? AND id != ?').bind(login.toLowerCase().trim(), id).first();
        if (dup) return err('Login já em uso por outro usuário');

        if (senha) {
          const salt = crypto.randomUUID();
          const hash = await hashPassword(senha, salt);
          await env.DB.prepare('UPDATE app_users SET nome=?, login=?, senha_hash=?, senha_salt=?, role=?, bling_vendedor_id=?, bling_vendedor_nome=?, telefone=?, ativo=?, updated_at=unixepoch() WHERE id=?')
            .bind(nome, login.toLowerCase().trim(), hash, salt, role||'entregador', bling_vendedor_id||null, bling_vendedor_nome||null, telefone||null, ativo !== undefined ? (ativo?1:0) : 1, id).run();
        } else {
          await env.DB.prepare('UPDATE app_users SET nome=?, login=?, role=?, bling_vendedor_id=?, bling_vendedor_nome=?, telefone=?, ativo=?, updated_at=unixepoch() WHERE id=?')
            .bind(nome, login.toLowerCase().trim(), role||'entregador', bling_vendedor_id||null, bling_vendedor_nome||null, telefone||null, ativo !== undefined ? (ativo?1:0) : 1, id).run();
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
        const result = await env.DB.prepare('INSERT INTO app_users (nome, login, senha_hash, senha_salt, role, bling_vendedor_id, bling_vendedor_nome, telefone, ativo) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)')
          .bind(nome, login.toLowerCase().trim(), hash, salt, role||'entregador', bling_vendedor_id||null, bling_vendedor_nome||null, telefone||null, ativo !== undefined ? (ativo?1:0) : 1).run();
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
      try {
        const cached = await env.DB.prepare('SELECT bling_contact_id FROM customers_cache WHERE phone_digits=?').bind(digits).first();
        if (!cached?.bling_contact_id) {
          const bResp = await blingFetch('/contatos', { method: 'POST', body: JSON.stringify({ nome: name, celular: digits, situacao: 'A', tipo: 'F', endereco: { endereco: address_line, bairro: bairro||'', municipio: 'Campo Grande', uf: 'MS', pais: 'Brasil' } }) }, env);
          if (bResp.ok) { const bData = await bResp.json(); const blingId = bData.data?.id; if (blingId) await env.DB.prepare('UPDATE customers_cache SET bling_contact_id=? WHERE phone_digits=?').bind(blingId, digits).run(); }
        }
      } catch (_) {}
      return json({ ok: true });
    }

    // ── PEDIDOS ──────────────────────────────────────────────

    if (method === 'POST' && path === '/api/order/create') {
      const body = await request.json();
      const { phone, name, address_line, bairro, complemento, referencia, items, total_value, notes, emitir_nfce, forma_pagamento_key, forma_pagamento_id, bling_contact_id, tipo_pagamento } = body;
      const digits = (phone || '').replace(/\D/g, '');

      const cols = ['forma_pagamento_id INTEGER','forma_pagamento_key TEXT','emitir_nfce INTEGER','nfce_gerada INTEGER','nfce_numero TEXT','nfce_chave TEXT','bling_pedido_id INTEGER','bling_pedido_num INTEGER','pago INTEGER DEFAULT 0','tipo_pagamento TEXT','vendedor_id INTEGER','vendedor_nome TEXT'];
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
      const criarBling = ['dinheiro', 'pix_vista', 'pix_receber', 'debito', 'credito'].includes(tipoPg);
      const pago = ['dinheiro', 'pix_vista', 'debito', 'credito'].includes(tipoPg) ? 1 : 0;

      const result = await env.DB.prepare(`
        INSERT INTO orders (phone_digits, customer_name, address_line, bairro, complemento, referencia, items_json, total_value, notes, status, sync_status, forma_pagamento_key, forma_pagamento_id, emitir_nfce, tipo_pagamento, pago, vendedor_id, vendedor_nome)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'novo', 'pending', ?, ?, ?, ?, ?, ?, ?)
      `).bind(digits||'', name||'', address_line||'', bairro||'', complemento||'', referencia||'', JSON.stringify(items||[]), total_value!=null?total_value:null, notes||null, forma_pagamento_key||null, forma_pagamento_id!=null?Number(forma_pagamento_id):null, emitir_nfce?1:0, tipoPg, pago, vendedorId, vendedorNome).run();

      const orderId = result.meta?.last_row_id;
      await env.DB.prepare('INSERT OR IGNORE INTO payments (order_id, status, method) VALUES (?, ?, ?)').bind(orderId, pago?'pago':'pendente', forma_pagamento_key||null).run();
      await logEvent(env, orderId, 'created', { name, address_line, tipo_pagamento: tipoPg, pago, vendedor: vendedorNome });

      let blingPedidoId = null;
      if (criarBling) {
        try {
          let finalBlingContactId = bling_contact_id;
          if (!finalBlingContactId && digits) {
            const cached = await env.DB.prepare('SELECT bling_contact_id FROM customers_cache WHERE phone_digits=?').bind(digits).first();
            if (cached?.bling_contact_id) finalBlingContactId = cached.bling_contact_id;
          }
          const blingResult = await criarPedidoBling(env, orderId, { name, items, total_value, forma_pagamento_key, forma_pagamento_id, bling_contact_id: finalBlingContactId, tipo_pagamento: tipoPg, bling_vendedor_id: blingVendedorId });
          blingPedidoId = blingResult.bling_pedido_id;
          await env.DB.prepare('UPDATE orders SET bling_pedido_id=?, bling_pedido_num=?, sync_status=? WHERE id=?').bind(blingPedidoId, blingResult.bling_pedido_num||null, 'synced', orderId).run();
          await logEvent(env, orderId, 'bling_created', { bling_pedido_id: blingPedidoId, vendedor_bling_id: blingVendedorId });
        } catch(e) {
          await logEvent(env, orderId, 'bling_error', { error: e.message });
          return json({ ok: true, id: orderId, bling_warning: e.message });
        }
      }
      return json({ ok: true, id: orderId, bling_pedido_id: blingPedidoId, pago, vendedor: vendedorNome });
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

    if (method === 'POST' && /^\/api\/order\/\d+\/update$/.test(path)) {
      const orderId = parseInt(path.split('/')[3]);
      const body = await request.json();
      const { customer_name, phone_digits, address_line, bairro, complemento, referencia, items, total_value, notes, tipo_pagamento, forma_pagamento_key, driver_id } = body;
      let sql = `UPDATE orders SET customer_name=?, phone_digits=?, address_line=?, bairro=?, complemento=?, referencia=?, items_json=?, total_value=?, notes=?, updated_at=unixepoch()`;
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
      sql += ` WHERE id=?`; params.push(orderId);
      await env.DB.prepare(sql).bind(...params).run();
      await logEvent(env, orderId, 'edited', { customer_name, address_line, tipo_pagamento, driver_id });
      return json({ ok: true });
    }

    if (method === 'GET' && path === '/api/orders/list') {
      const status = url.searchParams.get('status'); const driverId = url.searchParams.get('driver_id'); const q = url.searchParams.get('q');
      let sql = `SELECT o.*, d.nome AS driver_name_db, (SELECT status FROM payments WHERE order_id = o.id ORDER BY id DESC LIMIT 1) AS payment_status, (SELECT method FROM payments WHERE order_id = o.id ORDER BY id DESC LIMIT 1) AS payment_method FROM orders o LEFT JOIN app_users d ON o.driver_id = d.id WHERE 1=1`;
      const params = [];
      if (status) { sql += ` AND o.status = ?`; params.push(status); }
      if (driverId) { sql += ` AND o.driver_id = ?`; params.push(driverId); }
      if (q) { sql += ` AND (o.customer_name LIKE ? OR o.phone_digits LIKE ? OR o.address_line LIKE ?)`; params.push(`%${q}%`, `%${q}%`, `%${q}%`); }
      sql += ' ORDER BY o.created_at DESC LIMIT 200';
      const rows = await env.DB.prepare(sql).bind(...params).all();
      return json(rows.results || []);
    }

    const selectDriverMatch = path.match(/^\/api\/order\/(\d+)\/select-driver$/);
    if (method === 'POST' && selectDriverMatch) {
      const id = selectDriverMatch[1];
      const { driver_id } = await request.json();
      const driver = await env.DB.prepare('SELECT id, nome, telefone FROM app_users WHERE id=?').bind(driver_id).first();
      if (!driver) return err('driver not found');
      await env.DB.prepare(`UPDATE orders SET driver_id=?, driver_name_cache=?, driver_phone_cache=?, status='encaminhado', updated_at=unixepoch() WHERE id=?`).bind(driver_id, driver.nome, driver.telefone || '', id).run();
      await logEvent(env, id, 'driver_selected', { driver_id, driver_name: driver.nome });
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
      if (!order.driver_phone_cache) return err('Nenhum entregador selecionado');
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
      const id = deliveredMatch[1];
      await env.DB.prepare(`UPDATE orders SET status='entregue', delivered_at=unixepoch(), updated_at=unixepoch() WHERE id=?`).bind(id).run();
      await logEvent(env, id, 'delivered');
      return json({ ok: true, status: 'entregue' });
    }

    const cancelMatch = path.match(/^\/api\/order\/(\d+)\/cancel$/);
    if (method === 'POST' && cancelMatch) {
      const id = cancelMatch[1];
      await env.DB.prepare(`UPDATE orders SET status='cancelado', canceled_at=unixepoch(), updated_at=unixepoch() WHERE id=?`).bind(id).run();
      await logEvent(env, id, 'canceled');
      return json({ ok: true, status: 'cancelado' });
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
      const rows = await env.DB.prepare("SELECT id, nome, telefone, ativo FROM app_users WHERE role='entregador' AND ativo=1 ORDER BY nome").all();
      const result = (rows.results || []).map(u => ({ id: u.id, name: u.nome, phone_e164: u.telefone || '' }));
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
        WHERE o.pago = 0
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
            'SELECT bling_contact_id FROM customers_cache WHERE phone_digits=?'
          ).bind(order.phone_digits).first();

          const items = JSON.parse(order.items_json || '[]');
          let orderVendedorBlingId = null;
          if (order.vendedor_id) {
            const vendUser = await env.DB.prepare('SELECT bling_vendedor_id FROM app_users WHERE id=?').bind(order.vendedor_id).first().catch(() => null);
            if (vendUser?.bling_vendedor_id) orderVendedorBlingId = vendUser.bling_vendedor_id;
          }
          const blingResult = await criarPedidoBling(env, orderId, {
            name: order.customer_name,
            items,
            total_value: order.total_value,
            forma_pagamento_key: order.forma_pagamento_key,
            forma_pagamento_id: order.forma_pagamento_id,
            bling_contact_id: cached?.bling_contact_id || null,
            tipo_pagamento: order.tipo_pagamento,
            bling_vendedor_id: orderVendedorBlingId,
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
      await logEvent(env, orderId, 'payment_confirmed', {});
      return json({ ok: true });
    }

    if (method === 'POST' && path === '/api/pagamentos/criar-vendas-bling') {
      const body = await request.json();
      const orderIds = body.order_ids || [];
      if (orderIds.length === 0) return err('Nenhum pedido selecionado');

      const placeholders = orderIds.map(() => '?').join(',');
      const orders = await env.DB.prepare(
        `SELECT o.*, cc.bling_contact_id 
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
          grupos[key] = { cliente: o.customer_name, phone: o.phone_digits, bling_contact_id: o.bling_contact_id || null, pedidos: [], produtos: {}, total: 0 };
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

        const pedidoBody = {
          contato: grupo.bling_contact_id ? { id: grupo.bling_contact_id } : { id: CONSUMIDOR_FINAL_ID, tipoPessoa: 'F' },
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
          }

          resultados.push({ cliente: grupo.cliente, ok: true, bling_pedido_id: blingId, bling_pedido_num: blingNum, pedidos: pedidoIds, total: grupo.total, itens_count: itensBling.length });
        } catch(e) {
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

    return err('Not found', 404);
  },

  async scheduled(event, env, ctx) {
    ctx.waitUntil(keepBlingTokenFresh(env));
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
