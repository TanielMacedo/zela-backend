import express from 'express';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import pg from 'pg';
import bcrypt from 'bcrypt';
import dotenv from 'dotenv';

dotenv.config();
const app = express();
const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

app.use(cors());
app.use(express.json());

const SECRET = process.env.JWT_SECRET || 'secretkey';

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

app.get('/', (req, res) => {
  res.send('Zela API Online com PostgreSQL & JWT 🚀');
});

app.post('/register', async (req, res) => {
  const { nome, email, senha, tipo } = req.body;
  const senhaHash = await bcrypt.hash(senha, 10);
  try {
    const result = await pool.query(
      'INSERT INTO usuarios (nome, email, senha_hash, tipo) VALUES ($1, $2, $3, $4) RETURNING id, nome, email, tipo',
      [nome, email, senhaHash, tipo]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/login', async (req, res) => {
  const { email, senha } = req.body;
  try {
    const result = await pool.query('SELECT * FROM usuarios WHERE email = $1', [email]);
    const usuario = result.rows[0];
    if (!usuario || !(await bcrypt.compare(senha, usuario.senha_hash))) {
      return res.status(401).json({ error: 'Credenciais inválidas' });
    }
    const token = jwt.sign({ id: usuario.id, tipo: usuario.tipo }, SECRET, { expiresIn: '1d' });
    res.json({ token });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/estatisticas', authenticateToken, async (req, res) => {
  try {
    const [usuarios, agendamentos, pagamentos, avaliacoes] = await Promise.all([
      pool.query('SELECT COUNT(*) FROM usuarios'),
      pool.query('SELECT COUNT(*) FROM agendamentos'),
      pool.query('SELECT COUNT(*) FROM pagamentos'),
      pool.query('SELECT AVG(nota) FROM avaliacoes')
    ]);
    res.json({
      totalUsuarios: usuarios.rows[0].count,
      totalAgendamentos: agendamentos.rows[0].count,
      totalPagamentos: pagamentos.rows[0].count,
      mediaNota: parseFloat(avaliacoes.rows[0].avg || 0).toFixed(2)
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`Zela API rodando na porta ${PORT}`);
});
