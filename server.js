require('dotenv').config();
const dns = require('dns');
dns.setServers(['8.8.8.8', '8.8.4.4']);
const express   = require('express');
const bcrypt    = require('bcryptjs');
const jwt       = require('jsonwebtoken');
const cors      = require('cors');
const path      = require('path');
const mongoose  = require('mongoose');

const app        = express();
const PORT       = process.env.PORT       || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'danie-perfumaria-secret-2025';
const MONGODB_URI = process.env.MONGODB_URI;

app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ── SCHEMAS ──────────────────────────────────────────────────────────────────
const counterSchema = new mongoose.Schema({ _id: String, seq: { type: Number, default: 0 } });
const Counter = mongoose.model('Counter', counterSchema);

async function nextId(name) {
  const doc = await Counter.findByIdAndUpdate(name, { $inc: { seq: 1 } }, { returnDocument: 'after', upsert: true });
  return doc.seq;
}

const userSchema = new mongoose.Schema({
  id:        Number,
  name:      String,
  email:     String,
  password:  String,
  role:      { type: String, default: 'client' },
  createdAt: String,
  consentAt: { type: String, default: null },
  consentIp: { type: String, default: null }
});
const User = mongoose.model('User', userSchema);

const productSchema = new mongoose.Schema({
  id:    Number,
  name:  String,
  brand: { type: String, default: '' },
  type:  { type: String, default: '' },
  price: Number,
  desc:  { type: String, default: '' },
  img:   { type: String, default: '' }
});
const Product = mongoose.model('Product', productSchema);

const cookieConsentSchema = new mongoose.Schema({
  id:         Number,
  ip:         String,
  categories: mongoose.Schema.Types.Mixed,
  recordedAt: String
});
const CookieConsent = mongoose.model('CookieConsent', cookieConsentSchema);

const dataRequestSchema = new mongoose.Schema({
  type:        String,
  userEmail:   String,
  requestedAt: String,
  executedAt:  String,
  status:      String
});
const DataRequest = mongoose.model('DataRequest', dataRequestSchema);

// ── SEED: garante admin na primeira execução ──────────────────────────────────
async function seed() {
  const exists = await User.findOne({ role: 'admin' });
  if (!exists) {
    const id = await nextId('users');
    await User.create({
      id,
      name:      'Administradora',
      email:     'admin@danie.com',
      password:  await bcrypt.hash('admin123', 10),
      role:      'admin',
      createdAt: new Date().toISOString(),
      consentAt: null,
      consentIp: null
    });
    console.log('[seed] Admin criada: admin@danie.com / admin123');
  }
}

// ── MIDDLEWARES ───────────────────────────────────────────────────────────────
function authMiddleware(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer '))
    return res.status(401).json({ error: 'Token não informado.' });
  try {
    req.user = jwt.verify(header.split(' ')[1], JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Token inválido ou expirado.' });
  }
}

function adminMiddleware(req, res, next) {
  if (req.user.role !== 'admin')
    return res.status(403).json({ error: 'Acesso restrito ao administrador.' });
  next();
}

function getIp(req) {
  return (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
}

function toObj(doc) {
  const o = doc.toObject();
  delete o._id; delete o.__v;
  return o;
}

// ── AUTH ──────────────────────────────────────────────────────────────────────
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ error: 'E-mail e senha são obrigatórios.' });

  const user = await User.findOne({ email: email.toLowerCase() });
  if (!user || !(await bcrypt.compare(password, user.password)))
    return res.status(401).json({ error: 'E-mail ou senha inválidos.' });

  const token = jwt.sign(
    { id: user.id, email: user.email, name: user.name, role: user.role },
    JWT_SECRET, { expiresIn: '8h' }
  );
  res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
});

app.post('/api/auth/register', async (req, res) => {
  const { email, password, lgpdConsent } = req.body;
  if (!email || !password)
    return res.status(400).json({ error: 'E-mail e senha são obrigatórios.' });
  if (password.length < 6)
    return res.status(400).json({ error: 'Senha mínima: 6 caracteres.' });
  if (!lgpdConsent)
    return res.status(400).json({ error: 'O aceite à Política de Privacidade é obrigatório.' });

  const exists = await User.findOne({ email: email.toLowerCase() });
  if (exists) return res.status(409).json({ error: 'E-mail já cadastrado.' });

  const id = await nextId('users');
  const newUser = await User.create({
    id,
    name:      email.split('@')[0],
    email:     email.toLowerCase(),
    password:  await bcrypt.hash(password, 10),
    role:      'client',
    createdAt: new Date().toISOString(),
    consentAt: new Date().toISOString(),
    consentIp: getIp(req)
  });

  const token = jwt.sign(
    { id: newUser.id, email: newUser.email, name: newUser.name, role: newUser.role },
    JWT_SECRET, { expiresIn: '8h' }
  );
  res.status(201).json({ token, user: { id: newUser.id, name: newUser.name, email: newUser.email, role: newUser.role } });
});

app.get('/api/auth/me', authMiddleware, (req, res) => {
  res.json({ user: req.user });
});

// ── LGPD: COOKIES ────────────────────────────────────────────────────────────
app.post('/api/legal/consent/cookies', async (req, res) => {
  const { categories } = req.body;
  const id = await nextId('cookieConsents');
  const record = await CookieConsent.create({
    id,
    ip:         getIp(req),
    categories: categories || { essential: true },
    recordedAt: new Date().toISOString()
  });
  res.json({ ok: true, consentId: record.id });
});

// ── LGPD: POLÍTICAS ───────────────────────────────────────────────────────────
app.get('/api/legal/privacy-policy', (req, res) => {
  res.json({
    version: '1.0', updatedAt: '2025-06-01',
    title: 'Política de Privacidade — Daniê Casa de Perfumes',
    sections: [
      { title: '1. Quem somos', text: 'A Daniê Casa de Perfumes é uma loja especializada em fragrâncias árabes e europeias, com sede em Maringá, Paraná. Contato: +55 (44) 8868-5743.' },
      { title: '2. Quais dados coletamos', text: 'Coletamos exclusivamente: (a) endereço de e-mail, utilizado para autenticação; (b) data e hora do cadastro; (c) endereço IP no momento do cadastro, para fins de auditoria de consentimento conforme exigido pela LGPD. Não coletamos nome completo, CPF, endereço postal, telefone, ou quaisquer dados sensíveis definidos pelo art. 5º, II da Lei 13.709/2018.' },
      { title: '3. Para que usamos seus dados', text: 'Os dados são usados exclusivamente para: (a) permitir o acesso à área de cliente do site; (b) registrar o histórico de consentimento exigido pela LGPD (art. 7º, I). Não utilizamos seus dados para marketing, não os compartilhamos com terceiros e não realizamos tratamento para outras finalidades.' },
      { title: '4. Base legal do tratamento', text: 'O tratamento de dados pessoais é realizado com base no consentimento livre, informado e inequívoco do titular (art. 7º, I, LGPD), coletado no momento do cadastro.' },
      { title: '5. Por quanto tempo armazenamos', text: 'Seus dados são armazenados enquanto sua conta estiver ativa. Após a solicitação de exclusão (art. 18, VI, LGPD), os dados são removidos em até 15 dias. O registro de consentimento pode ser mantido pelo período necessário para cumprimento de obrigação legal (art. 7º, II, LGPD).' },
      { title: '6. Seus direitos como titular', text: 'Você tem direito a: (I) confirmação da existência de tratamento; (II) acesso aos dados; (III) correção de dados incompletos ou inexatos; (IV) anonimização, bloqueio ou eliminação de dados desnecessários; (V) portabilidade dos dados; (VI) eliminação dos dados tratados com seu consentimento; (VII) revogação do consentimento. Para exercer qualquer direito, use a seção "Meus Dados" na sua conta ou entre em contato pelo WhatsApp +55 (44) 8868-5743.' },
      { title: '7. Segurança', text: 'Senhas são armazenadas exclusivamente em formato hash bcrypt (irreversível). Utilizamos tokens JWT com expiração de 8 horas para autenticação. Nenhuma senha ou dado de pagamento é armazenado em texto puro.' },
      { title: '8. Contato e encarregado (DPO)', text: 'Responsável pelo tratamento de dados: Daniê Casa de Perfumes. Contato: WhatsApp +55 (44) 8868-5743. Para questões de privacidade, entre em contato diretamente pelo WhatsApp informando "Privacidade - LGPD".' }
    ]
  });
});

app.get('/api/legal/cookie-policy', (req, res) => {
  res.json({
    version: '1.0', updatedAt: '2025-06-01',
    title: 'Política de Cookies — Daniê Casa de Perfumes',
    sections: [
      { title: '1. O que são cookies', text: 'Cookies são pequenos arquivos de texto armazenados no seu navegador quando você visita um site. Eles permitem que o site reconheça sua sessão e preferências entre visitas.' },
      { title: '2. Cookies que utilizamos', text: 'Utilizamos apenas cookies estritamente necessários para o funcionamento do site: (a) Token de sessão (localStorage): armazena o token JWT de autenticação, válido por 8 horas, necessário para manter você conectado. Sem este token, o login não funciona. Este cookie não requer consentimento pois é essencial para o serviço solicitado. Não utilizamos cookies de rastreamento, analytics, publicidade ou de terceiros.' },
      { title: '3. Como gerenciar cookies', text: 'Você pode limpar o token de sessão a qualquer momento clicando em "Sair" no menu do site, ou acessando as configurações do seu navegador e limpando o armazenamento local (localStorage) para este domínio.' },
      { title: '4. Alterações nesta política', text: 'Qualquer alteração será comunicada nesta página com atualização da data de versão. Para mudanças materiais que afetem seus direitos, notificaremos via e-mail cadastrado.' }
    ]
  });
});

// ── LGPD: DIREITOS DO TITULAR ─────────────────────────────────────────────────
app.get('/api/user/data', authMiddleware, async (req, res) => {
  const user = await User.findOne({ id: req.user.id });
  if (!user) return res.status(404).json({ error: 'Usuário não encontrado.' });
  res.json({
    id: user.id, email: user.email, name: user.name, role: user.role,
    createdAt: user.createdAt || null, consentAt: user.consentAt || null,
    dataExportedAt: new Date().toISOString()
  });
});

app.delete('/api/user/account', authMiddleware, async (req, res) => {
  const user = await User.findOne({ id: req.user.id });
  if (!user) return res.status(404).json({ error: 'Usuário não encontrado.' });
  if (user.role === 'admin')
    return res.status(403).json({ error: 'A conta administradora não pode ser excluída por esta rota.' });

  await DataRequest.create({
    type: 'DELETE_ACCOUNT', userEmail: user.email,
    requestedAt: new Date().toISOString(),
    executedAt: new Date().toISOString(), status: 'COMPLETED'
  });
  await User.deleteOne({ id: req.user.id });
  res.json({ ok: true, message: 'Sua conta e dados pessoais foram removidos com sucesso.' });
});

// ── PRODUTOS ──────────────────────────────────────────────────────────────────
app.get('/api/products', async (req, res) => {
  const products = await Product.find().sort({ id: 1 });
  res.json(products.map(toObj));
});

app.post('/api/products', authMiddleware, adminMiddleware, async (req, res) => {
  const { name, brand, type, price, desc, img } = req.body;
  if (!name || !name.trim())
    return res.status(400).json({ error: 'Nome do produto é obrigatório.' });
  if (!price || isNaN(parseFloat(price)) || parseFloat(price) <= 0)
    return res.status(400).json({ error: 'Valor inválido.' });

  const id = await nextId('products');
  const product = await Product.create({
    id, name: name.trim(), brand: brand || '', type: type || '',
    price: parseFloat(price), desc: desc || '', img: img || ''
  });
  res.status(201).json(toObj(product));
});

app.put('/api/products/:id', authMiddleware, adminMiddleware, async (req, res) => {
  const id = parseInt(req.params.id);
  const { name, brand, type, price, desc, img } = req.body;
  if (!name || !name.trim())
    return res.status(400).json({ error: 'Nome do produto é obrigatório.' });
  if (!price || isNaN(parseFloat(price)) || parseFloat(price) <= 0)
    return res.status(400).json({ error: 'Valor inválido.' });

  const product = await Product.findOneAndUpdate(
    { id },
    { name: name.trim(), brand: brand || '', type: type || '', price: parseFloat(price), desc: desc || '', img: img !== undefined ? img : undefined },
    { returnDocument: 'after' }
  );
  if (!product) return res.status(404).json({ error: 'Produto não encontrado.' });
  res.json(toObj(product));
});

app.delete('/api/products/:id', authMiddleware, adminMiddleware, async (req, res) => {
  const id = parseInt(req.params.id);
  const result = await Product.deleteOne({ id });
  if (result.deletedCount === 0) return res.status(404).json({ error: 'Produto não encontrado.' });
  res.json({ ok: true });
});

// ── BOOT ──────────────────────────────────────────────────────────────────────
async function start() {
  if (!MONGODB_URI) {
    console.error('❌  MONGODB_URI não definida. Configure a variável de ambiente.');
    process.exit(1);
  }
  await mongoose.connect(MONGODB_URI, { family: 4 });
  console.log('[db] MongoDB conectado.');
  await seed();
  app.listen(PORT, () => {
    console.log(`\n✦ Daniê Casa de Perfumes — http://localhost:${PORT}`);
    console.log(`  Admin: admin@danie.com / admin123\n`);
  });
}

start().catch(err => { console.error(err); process.exit(1); });
