require("dotenv").config();
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
const path = require("path");

const { MONGODB_URI, JWT_SECRET, PORT = 3000 } = process.env;
if (!MONGODB_URI || !JWT_SECRET) {
  console.error("XƏTA: .env faylında MONGODB_URI və JWT_SECRET təyin edilməlidir (.env.example-a baxın).");
  process.exit(1);
}

// ---------- Modellər ----------
const User = mongoose.model("User", new mongoose.Schema({
  name: { type: String, required: true, trim: true, maxlength: 60 },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  passwordHash: { type: String, required: true }
}, { timestamps: true }));

const CATEGORIES = ["HTML", "CSS", "JavaScript", "Digər"];
const Post = mongoose.model("Post", new mongoose.Schema({
  title: { type: String, required: true, trim: true, maxlength: 150 },
  category: { type: String, enum: CATEGORIES, default: "Digər" },
  body: { type: String, required: true, maxlength: 20000 },
  author: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true, index: true }
}, { timestamps: true }));

const toPost = p => ({
  id: p.id, title: p.title, category: p.category, body: p.body,
  author: p.author && p.author.name ? p.author.name : "Naməlum",
  authorId: String(p.author && p.author._id ? p.author._id : p.author),
  date: p.createdAt.toISOString().slice(0, 10)
});

// ---------- Middleware ----------
const app = express();
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:"]
    }
  }
}));
app.use(cors());
app.use(express.json({ limit: "100kb" }));
app.use(express.static(path.join(__dirname, "public")));

const wrap = fn => (req, res, next) => fn(req, res, next).catch(next);
const str = v => (typeof v === "string" ? v : ""); // NoSQL injection-a qarşı: yalnız string qəbul edirik
const sign = u => jwt.sign({ id: String(u._id), name: u.name }, JWT_SECRET, { expiresIn: "7d" });
const pub = u => ({ id: String(u._id), name: u.name, email: u.email });

function auth(req, res, next) {
  const h = req.headers.authorization || "";
  const token = h.startsWith("Bearer ") ? h.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Giriş tələb olunur." });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(401).json({ error: "Sessiya bitib, yenidən daxil olun." }); }
}

// Brute-force hücumlarına qarşı: 15 dəqiqədə 30 cəhd
app.use("/api/auth", rateLimit({ windowMs: 15 * 60 * 1000, max: 30,
  message: { error: "Çox cəhd edildi. Bir az sonra yenidən yoxlayın." } }));

// ---------- Auth ----------
app.post("/api/auth/register", wrap(async (req, res) => {
  const name = str(req.body.name).trim(), email = str(req.body.email).trim().toLowerCase(), password = str(req.body.password);
  if (!name || name.length > 60 || !/^\S+@\S+\.\S+$/.test(email))
    return res.status(400).json({ error: "Ad və düzgün e-poçt daxil edin." });
  if (password.length < 6 || password.length > 72)
    return res.status(400).json({ error: "Şifrə 6–72 simvol arasında olmalıdır." });
  if (await User.exists({ email })) return res.status(409).json({ error: "Bu e-poçt artıq qeydiyyatdadır." });
  const user = await User.create({ name, email, passwordHash: await bcrypt.hash(password, 12) });
  res.status(201).json({ token: sign(user), user: pub(user) });
}));

app.post("/api/auth/login", wrap(async (req, res) => {
  const email = str(req.body.email).trim().toLowerCase(), password = str(req.body.password);
  const user = await User.findOne({ email });
  if (!user || !(await bcrypt.compare(password, user.passwordHash)))
    return res.status(401).json({ error: "E-poçt və ya şifrə yanlışdır." });
  res.json({ token: sign(user), user: pub(user) });
}));

app.get("/api/auth/me", auth, (req, res) => res.json({ user: req.user }));

// ---------- Posts ----------
app.get("/api/posts", wrap(async (req, res) => {
  const posts = await Post.find().sort({ createdAt: -1 }).limit(100).populate("author", "name");
  res.json({ posts: posts.map(toPost) });
}));

app.get("/api/posts/:id", wrap(async (req, res) => {
  if (!mongoose.isValidObjectId(req.params.id)) return res.status(404).json({ error: "Yazı tapılmadı." });
  const post = await Post.findById(req.params.id).populate("author", "name");
  if (!post) return res.status(404).json({ error: "Yazı tapılmadı." });
  res.json({ post: toPost(post) });
}));

app.post("/api/posts", auth, wrap(async (req, res) => {
  const title = str(req.body.title).trim(), body = str(req.body.body).trim();
  const category = CATEGORIES.includes(req.body.category) ? req.body.category : "Digər";
  if (title.length < 3 || title.length > 150) return res.status(400).json({ error: "Başlıq 3–150 simvol olmalıdır." });
  if (body.length < 20) return res.status(400).json({ error: "Məzmun çox qısadır (ən azı 20 simvol)." });
  const post = await Post.create({ title, category, body, author: req.user.id });
  await post.populate("author", "name");
  res.status(201).json({ post: toPost(post) });
}));

app.delete("/api/posts/:id", auth, wrap(async (req, res) => {
  if (!mongoose.isValidObjectId(req.params.id)) return res.status(404).json({ error: "Yazı tapılmadı." });
  const post = await Post.findById(req.params.id);
  if (!post) return res.status(404).json({ error: "Yazı tapılmadı." });
  if (String(post.author) !== req.user.id) return res.status(403).json({ error: "Bu yazını silmək icazəniz yoxdur." });
  await post.deleteOne();
  res.json({ ok: true });
}));

app.use("/api", (req, res) => res.status(404).json({ error: "Belə API yoxdur." }));
app.use((err, req, res, next) => {
  if (err.code === 11000) return res.status(409).json({ error: "Bu məlumat artıq mövcuddur." });
  console.error(err);
  res.status(500).json({ error: "Server xətası. Sonra yenidən cəhd edin." });
});

// ---------- Başlat ----------
mongoose.connect(MONGODB_URI, { serverSelectionTimeoutMS: 8000 })
  .then(() => { console.log("MongoDB-yə qoşuldu"); app.listen(PORT, () => console.log(`Server: http://localhost:${PORT}`)); })
  .catch(e => { console.error("MongoDB-yə qoşulmaq olmadı:", e.message); process.exit(1); });
