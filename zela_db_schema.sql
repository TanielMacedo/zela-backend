CREATE TABLE usuarios (
  id SERIAL PRIMARY KEY,
  nome VARCHAR(100),
  email VARCHAR(100) UNIQUE,
  senha_hash TEXT,
  tipo VARCHAR(20),
  telefone VARCHAR(20)
);
-- (Demais tabelas omitidas por brevidade)
