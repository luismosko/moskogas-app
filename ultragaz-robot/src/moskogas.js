// moskogas.js — Envia pedido para API MoskoGás
import 'dotenv/config';

const API_URL  = process.env.MOSKOGAS_API_URL || 'https://api.moskogas.com.br';
const API_KEY  = process.env.MOSKOGAS_API_KEY || '';

// Busca config do Ultragaz Hub salva no painel config.html
export async function getUltragazConfig() {
  const res = await fetch(`${API_URL}/api/ultragaz/config`, {
    headers: { 'X-API-KEY': API_KEY }
  });
  if (!res.ok) throw new Error(`getUltragazConfig HTTP ${res.status}`);
  const data = await res.json();
  if (!data.configurado) throw new Error('Credenciais Ultragaz não configuradas no painel');
  return data; // { login, senha, hub_url, ativo, ... }
}

// Mapeia tipo de pagamento do Hub para o padrão MoskoGás
function mapTipoPagamento(formaPagamento = '') {
  const fp = formaPagamento.toLowerCase();
  if (fp.includes('vale gás') || fp.includes('vale gas') || fp.includes('parceria')) return 'boleto_orgao';
  if (fp.includes('dinheiro') || fp.includes('cash'))    return 'dinheiro';
  if (fp.includes('pix'))                                return 'pix_vista';
  if (fp.includes('crédito') || fp.includes('credito'))  return 'credito';
  if (fp.includes('débito') || fp.includes('debito'))    return 'debito';
  if (fp.includes('mensali'))                            return 'mensalista';
  if (fp.includes('boleto') || fp.includes('órgão') || fp.includes('orgao')) return 'boleto_orgao';
  return 'boleto_orgao'; // padrão Ultragaz é sempre boleto/parceria
}

// Parseia produto do Hub (ex: "P13", "GLP 13KG") → item padrão MoskoGás
function parseItem(produto = '', quantidade = 1, valorUnit = 0) {
  const p = produto.toUpperCase();
  let name = 'P13';
  if (p.includes('P20') || p.includes('20KG') || p.includes('20 KG')) name = 'P20';
  else if (p.includes('P45') || p.includes('45KG') || p.includes('45 KG')) name = 'P45';
  else if (p.includes('GUA') || p.includes('ÁGUA') || p.includes('20L')) name = 'Água 20L';
  else if (p.includes('P13') || p.includes('13KG') || p.includes('13 KG') || p.includes('GLP')) name = 'P13';

  return { produto: name, quantidade: parseInt(quantidade) || 1, valor_unit: parseFloat(valorUnit) || 0 };
}

// Envia pedido capturado para MoskoGás
export async function enviarPedido(orderData) {
  const {
    ultragaz_order_id,
    customer_name,
    phone_digits,
    address_line,
    bairro,
    complemento,
    referencia,
    produto,
    quantidade,
    valor_unit,
    total_value,
    forma_pagamento,
    event_type,
    raw_payload,
  } = orderData;

  const item = parseItem(produto, quantidade, valor_unit);
  const items_json = [item];
  const tipo_pagamento = mapTipoPagamento(forma_pagamento);

  const body = {
    ultragaz_order_id: String(ultragaz_order_id),
    customer_name:     customer_name || 'Cliente Ultragaz',
    phone_digits:      phone_digits || '',
    address_line:      address_line || '',
    bairro:            bairro || '',
    complemento:       complemento || '',
    referencia:        referencia || '',
    items_json,
    total_value:       parseFloat(total_value) || 0,
    tipo_pagamento,
    event_type:        event_type || 'newOrder',
    raw_payload:       raw_payload || {},
  };

  const res = await fetch(`${API_URL}/api/ultragaz/pedido`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-API-KEY': API_KEY,
    },
    body: JSON.stringify(body),
  });

  const data = await res.json().catch(() => ({}));

  if (!res.ok) {
    throw new Error(`enviarPedido HTTP ${res.status}: ${data.error || 'erro desconhecido'}`);
  }

  return data; // { ok, moskogas_order_id, duplicado }
}

// Notifica MoskoGás que um pedido do Hub foi cancelado
export async function enviarCancelamento(ultragaz_order_id) {
  const res = await fetch(`${API_URL}/api/ultragaz/cancelar`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-API-KEY': API_KEY },
    body: JSON.stringify({ ultragaz_order_id: String(ultragaz_order_id) }),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok && !data.duplicado) throw new Error(`cancelar HTTP ${res.status}: ${JSON.stringify(data)}`);
  return data;
}
