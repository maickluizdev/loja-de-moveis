const path = require('path');
const crypto = require('crypto');
const express = require('express');
const bcrypt = require('bcryptjs');
const rateLimit = require('express-rate-limit');
const { q, tx, seedAdmin } = require('./db');

const app = express();
const PROD = process.env.NODE_ENV === 'production';
const TZ = process.env.TZ_LOJA || 'America/Bahia';
const SESSAO_DIAS = 7;
const STATUS = ['Pendente', 'Pago', 'Entregue', 'Cancelado'];
const DUMMY_HASH = bcrypt.hashSync('senha-falsa', 12); // evita revelar quais e-mails existem pelo tempo de resposta

const mesAtual = () => new Date().toLocaleDateString('sv-SE', { timeZone: TZ }).slice(0, 7);
const texto = (v, max = 120) => (typeof v === 'string' ? v.trim().slice(0, max) : '');
const emailValido = (e) => e.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e);
const inteiro = (v, min = 0) => Number.isInteger(v) && v >= min;

app.disable('x-powered-by');
app.use(express.json({ limit: '100kb' }));
app.use(express.static(path.join(__dirname, 'public')));

/* ---------- Sessão ---------- */
function lerCookie(req, nome) {
  const c = (req.headers.cookie || '').split(';').map((s) => s.trim()).find((s) => s.startsWith(nome + '='));
  return c ? decodeURIComponent(c.slice(nome.length + 1)) : null;
}
const flags = () => `HttpOnly; SameSite=Lax; Path=/${PROD ? '; Secure' : ''}`;

async function usuarioDaSessao(req) {
  const token = lerCookie(req, 'sid');
  if (!token) return null;
  const { rows } = await q(`SELECT u.id, u.nome, u.email, u.role
    FROM sessoes s JOIN usuarios u ON u.id = s.usuario_id
    WHERE s.token = $1 AND s.expira_em > now()`, [token]);
  return rows[0] ? { ...rows[0], token } : null;
}
async function abrirSessao(res, usuarioId) {
  const token = crypto.randomBytes(32).toString('hex');
  await q("DELETE FROM sessoes WHERE expira_em < now()");
  await q(`INSERT INTO sessoes (token, usuario_id, expira_em) VALUES ($1, $2, now() + interval '${SESSAO_DIAS} days')`,
    [token, usuarioId]);
  res.setHeader('Set-Cookie', `sid=${token}; ${flags()}; Max-Age=${SESSAO_DIAS * 86400}`);
}
async function auth(req, res, next) {
  const u = await usuarioDaSessao(req);
  if (!u) return res.status(401).json({ erro: 'Faça login para continuar.' });
  req.user = u;
  next();
}
function admin(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ erro: 'Acesso restrito ao administrador.' });
  next();
}
const limiteLogin = rateLimit({
  windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: 'draft-7', legacyHeaders: false,
  message: { erro: 'Muitas tentativas. Aguarde 15 minutos.' },
});

/* ---------- Autenticação ---------- */
app.post('/api/cadastro', async (req, res) => {
  const nome = texto(req.body?.nome);
  const email = texto(req.body?.email, 254).toLowerCase();
  const senha = typeof req.body?.senha === 'string' ? req.body.senha : '';
  if (!nome) return res.status(400).json({ erro: 'Informe o nome.' });
  if (!emailValido(email)) return res.status(400).json({ erro: 'E-mail inválido.' });
  if (senha.length < 8) return res.status(400).json({ erro: 'A senha precisa ter ao menos 8 caracteres.' });
  try {
    const { rows } = await q(`INSERT INTO usuarios (nome, email, senha_hash, role)
      VALUES ($1, $2, $3, 'cliente') RETURNING id`, [nome, email, await bcrypt.hash(senha, 12)]);
    await abrirSessao(res, rows[0].id);
    res.status(201).json({ id: rows[0].id, nome, email, role: 'cliente' });
  } catch (e) {
    if (e.code === '23505') return res.status(409).json({ erro: 'Este e-mail já está cadastrado.' });
    throw e;
  }
});

app.post('/api/login', limiteLogin, async (req, res) => {
  const email = texto(req.body?.email, 254).toLowerCase();
  const senha = typeof req.body?.senha === 'string' ? req.body.senha : '';
  const { rows } = await q('SELECT * FROM usuarios WHERE email = $1', [email]);
  const u = rows[0];
  const ok = await bcrypt.compare(senha, u ? u.senha_hash : DUMMY_HASH);
  if (!u || !ok) return res.status(401).json({ erro: 'E-mail ou senha inválidos.' });
  await abrirSessao(res, u.id);
  res.json({ id: u.id, nome: u.nome, email: u.email, role: u.role });
});

app.post('/api/logout', async (req, res) => {
  const u = await usuarioDaSessao(req);
  if (u) await q('DELETE FROM sessoes WHERE token = $1', [u.token]);
  res.setHeader('Set-Cookie', `sid=; ${flags()}; Max-Age=0`);
  res.json({ ok: true });
});

app.get('/api/me', async (req, res) => {
  const u = await usuarioDaSessao(req);
  if (!u) return res.status(401).json({ erro: 'Não autenticado.' });
  res.json({ id: u.id, nome: u.nome, email: u.email, role: u.role });
});

/* ---------- Produtos ---------- */
const formatoProduto = (p) => ({ id: p.id, nome: p.nome, categoria: p.categoria, preco: p.preco_centavos / 100, estoque: p.estoque });
function validarProduto(b) {
  const nome = texto(b?.nome), categoria = texto(b?.categoria, 60);
  const preco = Number(b?.preco), estoque = Number(b?.estoque);
  if (!nome) return { erro: 'Informe o nome.' };
  if (!categoria) return { erro: 'Informe a categoria.' };
  if (!Number.isFinite(preco) || preco < 0) return { erro: 'Preço inválido.' };
  if (!inteiro(estoque)) return { erro: 'Estoque inválido.' };
  return { dados: [nome, categoria, Math.round(preco * 100), estoque] };
}

app.get('/api/produtos', auth, async (req, res) => {
  const { rows } = await q('SELECT * FROM produtos ORDER BY nome');
  res.json(rows.map(formatoProduto));
});
app.post('/api/produtos', auth, admin, async (req, res) => {
  const v = validarProduto(req.body);
  if (v.erro) return res.status(400).json(v);
  const { rows } = await q(`INSERT INTO produtos (nome, categoria, preco_centavos, estoque)
    VALUES ($1, $2, $3, $4) RETURNING *`, v.dados);
  res.status(201).json(formatoProduto(rows[0]));
});
app.put('/api/produtos/:id', auth, admin, async (req, res) => {
  const v = validarProduto(req.body);
  if (v.erro) return res.status(400).json(v);
  const { rows } = await q(`UPDATE produtos SET nome=$1, categoria=$2, preco_centavos=$3, estoque=$4
    WHERE id=$5 RETURNING *`, [...v.dados, Number(req.params.id)]);
  if (!rows[0]) return res.status(404).json({ erro: 'Produto não encontrado.' });
  res.json(formatoProduto(rows[0]));
});
app.delete('/api/produtos/:id', auth, admin, async (req, res) => {
  const r = await q('DELETE FROM produtos WHERE id = $1', [Number(req.params.id)]);
  if (!r.rowCount) return res.status(404).json({ erro: 'Produto não encontrado.' });
  res.json({ ok: true });
});

/* ---------- Pedidos ---------- */
app.post('/api/pedidos', auth, async (req, res) => {
  if (req.user.role !== 'cliente') return res.status(403).json({ erro: 'Somente clientes realizam compras.' });
  const itens = Array.isArray(req.body?.itens) ? req.body.itens : [];
  if (!itens.length || itens.length > 50) return res.status(400).json({ erro: 'Carrinho vazio ou inválido.' });
  for (const it of itens) {
    if (!Number.isInteger(Number(it?.produto_id)) || !inteiro(Number(it?.qtd), 1))
      return res.status(400).json({ erro: 'Item inválido no carrinho.' });
  }
  try {
    const id = await tx(async (c) => {
      let total = 0;
      const linhas = [];
      for (const it of itens) {
        // FOR UPDATE trava a linha: duas compras simultâneas não vendem o mesmo estoque
        const { rows } = await c.query('SELECT * FROM produtos WHERE id = $1 FOR UPDATE', [Number(it.produto_id)]);
        const p = rows[0];
        const qtd = Number(it.qtd);
        if (!p) throw new Error('Produto não encontrado.');
        if (p.estoque < qtd) throw new Error(`Estoque insuficiente para ${p.nome}.`);
        await c.query('UPDATE produtos SET estoque = estoque - $1 WHERE id = $2', [qtd, p.id]);
        total += p.preco_centavos * qtd; // preço sempre vem do banco, nunca do navegador
        linhas.push({ p, qtd });
      }
      const { rows } = await c.query(
        'INSERT INTO pedidos (usuario_id, total_centavos, mes) VALUES ($1, $2, $3) RETURNING id',
        [req.user.id, total, mesAtual()]);
      for (const { p, qtd } of linhas) {
        await c.query(`INSERT INTO itens_pedido (pedido_id, produto_id, nome, preco_centavos, qtd)
          VALUES ($1, $2, $3, $4, $5)`, [rows[0].id, p.id, p.nome, p.preco_centavos, qtd]);
      }
      return rows[0].id;
    });
    res.status(201).json({ id });
  } catch (e) {
    if (e.message.startsWith('Estoque') || e.message.startsWith('Produto')) return res.status(400).json({ erro: e.message });
    throw e;
  }
});

async function listarPedidos(usuarioId) {
  const filtro = usuarioId ? 'WHERE p.usuario_id = $1' : '';
  const { rows } = await q(`SELECT p.id, p.total_centavos, p.status, p.criado_em, p.mes, u.nome AS cliente,
      COALESCE(json_agg(json_build_object('nome', i.nome, 'qtd', i.qtd, 'preco_centavos', i.preco_centavos))
        FILTER (WHERE i.pedido_id IS NOT NULL), '[]') AS itens
    FROM pedidos p
    JOIN usuarios u ON u.id = p.usuario_id
    LEFT JOIN itens_pedido i ON i.pedido_id = p.id
    ${filtro}
    GROUP BY p.id, u.nome
    ORDER BY p.id DESC`, usuarioId ? [usuarioId] : []);
  return rows.map((p) => ({
    id: p.id, cliente: p.cliente, data: p.criado_em, mes: p.mes, status: p.status,
    total: p.total_centavos / 100,
    itens: p.itens.map((i) => ({ nome: i.nome, qtd: i.qtd, preco: i.preco_centavos / 100 })),
  }));
}
app.get('/api/pedidos', auth, async (req, res) => {
  res.json(await listarPedidos(req.user.role === 'admin' ? null : req.user.id));
});
app.patch('/api/pedidos/:id/status', auth, admin, async (req, res) => {
  const s = req.body?.status;
  if (!STATUS.includes(s)) return res.status(400).json({ erro: 'Status inválido.' });
  const r = await q('UPDATE pedidos SET status = $1 WHERE id = $2', [s, Number(req.params.id)]);
  if (!r.rowCount) return res.status(404).json({ erro: 'Pedido não encontrado.' });
  res.json({ ok: true });
});

/* ---------- Faturamento (admin) ---------- */
app.get('/api/faturamento', auth, admin, async (req, res) => {
  const mes = /^\d{4}-\d{2}$/.test(req.query.mes || '') ? req.query.mes : mesAtual();
  const { rows } = await q(`SELECT COUNT(*)::int AS qtd, COALESCE(SUM(total_centavos), 0)::bigint AS total
    FROM pedidos WHERE mes = $1 AND status IN ('Pago', 'Entregue')`, [mes]);
  const qtd = rows[0].qtd, total = Number(rows[0].total);
  res.json({ mes, pedidos: qtd, faturado: total / 100, ticketMedio: qtd ? total / qtd / 100 : 0 });
});

/* ---------- Erros e inicialização ---------- */
app.use((req, res) => res.status(404).json({ erro: 'Rota não encontrada.' }));
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ erro: 'Erro interno do servidor.' });
});

seedAdmin()
  .then(() => app.listen(process.env.PORT || 3000, () => console.log('Loja rodando na porta', process.env.PORT || 3000)))
  .catch((e) => { console.error('Falha ao conectar no banco:', e.message); process.exit(1); });
