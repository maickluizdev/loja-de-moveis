const { Pool } = require('pg');
const bcrypt = require('bcryptjs');

if (!process.env.DATABASE_URL) throw new Error('Defina DATABASE_URL no .env');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  // Supabase exige SSL. Para validar o certificado, use o CA do Supabase (ver README).
  ssl: { rejectUnauthorized: false },
  max: 10,
});

const q = (text, params = []) => pool.query(text, params);

// Executa várias operações em uma transação: tudo ou nada
async function tx(fn) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    throw e;
  } finally {
    client.release();
  }
}

// Cria o administrador inicial a partir do .env, se ainda não existir
async function seedAdmin() {
  const email = (process.env.ADMIN_EMAIL || '').trim().toLowerCase();
  const senha = process.env.ADMIN_SENHA || '';
  if (!email || senha.length < 8) return;
  const existe = await q('SELECT 1 FROM usuarios WHERE email = $1', [email]);
  if (existe.rowCount) return;
  await q("INSERT INTO usuarios (nome, email, senha_hash, role) VALUES ('Administrador', $1, $2, 'admin')",
    [email, await bcrypt.hash(senha, 12)]);
  console.log('Administrador inicial criado:', email);
}

module.exports = { q, tx, seedAdmin };
