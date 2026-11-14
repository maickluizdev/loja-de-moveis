-- Rode este arquivo no SQL Editor do Supabase (uma vez).
create table if not exists usuarios (
  id integer generated always as identity primary key,
  nome text not null,
  email text not null unique,
  senha_hash text not null,
  role text not null default 'cliente' check (role in ('cliente','admin')),
  criado_em timestamptz not null default now()
);
create table if not exists sessoes (
  token text primary key,
  usuario_id integer not null references usuarios(id) on delete cascade,
  expira_em timestamptz not null
);
create table if not exists produtos (
  id integer generated always as identity primary key,
  nome text not null,
  categoria text not null,
  preco_centavos integer not null check (preco_centavos >= 0),
  estoque integer not null check (estoque >= 0)
);
create table if not exists pedidos (
  id integer generated always as identity primary key,
  usuario_id integer not null references usuarios(id),
  total_centavos integer not null,
  status text not null default 'Pendente' check (status in ('Pendente','Pago','Entregue','Cancelado')),
  mes text not null,
  criado_em timestamptz not null default now()
);
create table if not exists itens_pedido (
  pedido_id integer not null references pedidos(id) on delete cascade,
  produto_id integer,
  nome text not null,
  preco_centavos integer not null,
  qtd integer not null check (qtd > 0)
);
-- Segurança: as tabelas não ficam expostas pela API pública do Supabase (chave anon).
-- O servidor acessa o banco direto pela conexão Postgres, que ignora essas regras.
alter table usuarios enable row level security;
alter table sessoes enable row level security;
alter table produtos enable row level security;
alter table pedidos enable row level security;
alter table itens_pedido enable row level security;
