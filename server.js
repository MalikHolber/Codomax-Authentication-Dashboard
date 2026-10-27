const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const fs = require("fs");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET = process.env.JWT_SECRET || "dev-secret-bunu-deyisin";
const FILE = path.join(__dirname, "data.json");

// ---------- Sadə fayl bazası (data.json) ----------
const seed = {
  users: [],
  posts: [
    { id: 1, title: "HTML ilə ilk addımlar", category: "HTML", author: "Aysel", authorId: 0, date: "2026-10-02",
      body: "HTML səhifənin skeletidir. Başlıq, paraqraf, şəkil və keçid kimi elementlər məzmunun mənasını təyin edir." },
    { id: 2, title: "CSS Grid ilə adaptiv kartlar", category: "CSS", author: "Murad", authorId: 0, date: "2026-10-09",
      body: "Grid ekran enindən asılı olaraq sütun sayını avtomatik dəyişə bilər. Media query yalnız incə tənzimləmə üçün qalır." }
  ]
};
function load() {
  try { return JSON.parse(fs.readFileSync(FILE, "utf8")); }
  catch { fs.writeFileSync(FILE, JSON.stringify(seed, null, 2)); return structuredClone(seed); }
}
function save(db) { fs.writeFileSync(FILE, JSON.stringify(db, null, 2)); }

// ---------- Middleware ----------
app.use(cors());
app.use(express.json({ limit: "100kb" }));
app.use(express.static(path.join(__dirname, "public")));

function sign(u) {
  return jwt.sign({ id: u.id, name: u.name }, SECRET, { expiresIn: "7d" });
}
function auth(req, res, next) {
  const h = req.headers.authorization || "";
  const token = h.startsWith("Bearer ") ? h.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Giriş tələb olunur." });
  try { req.user = jwt.verify(token, SECRET); next(); }
  catch { res.status(401).json({ error: "Sessiya bitib, yenidən daxil olun." }); }
}

// ---------- Auth ----------
app.post("/api/auth/register", async (req, res) => {
  const { name = "", email = "", password = "" } = req.body;
  if (!name.trim() || !/^\S+@\S+\.\S+$/.test(email))
    return res.status(400).json({ error: "Ad və düzgün e-poçt daxil edin." });
  if (password.length < 6)
    return res.status(400).json({ error: "Şifrə ən azı 6 simvol olmalıdır." });
  const db = load();
  const mail = email.trim().toLowerCase();
  if (db.users.some(u => u.email === mail))
    return res.status(409).json({ error: "Bu e-poçt artıq qeydiyyatdadır." });
  const user = { id: Date.now(), name: name.trim(), email: mail, passwordHash: await bcrypt.hash(password, 10) };
  db.users.push(user); save(db);
  res.status(201).json({ token: sign(user), user: { id: user.id, name: user.name, email: user.email } });
});

app.post("/api/auth/login", async (req, res) => {
  const { email = "", password = "" } = req.body;
  const user = load().users.find(u => u.email === email.trim().toLowerCase());
  if (!user || !(await bcrypt.compare(password, user.passwordHash)))
    return res.status(401).json({ error: "E-poçt və ya şifrə yanlışdır." });
  res.json({ token: sign(user), user: { id: user.id, name: user.name, email: user.email } });
});

app.get("/api/auth/me", auth, (req, res) => res.json({ user: req.user }));

// ---------- Posts ----------
app.get("/api/posts", (req, res) => res.json({ posts: load().posts.slice().reverse() }));

app.get("/api/posts/:id", (req, res) => {
  const post = load().posts.find(p => p.id === Number(req.params.id));
  if (!post) return res.status(404).json({ error: "Yazı tapılmadı." });
  res.json({ post });
});

app.post("/api/posts", auth, (req, res) => {
  const { title = "", category = "Digər", body = "" } = req.body;
  if (title.trim().length < 3) return res.status(400).json({ error: "Başlıq ən azı 3 simvol olmalıdır." });
  if (body.trim().length < 20) return res.status(400).json({ error: "Məzmun çox qısadır (ən azı 20 simvol)." });
  const db = load();
  const post = { id: Date.now(), title: title.trim(), category, body: body.trim(),
    author: req.user.name, authorId: req.user.id, date: new Date().toISOString().slice(0, 10) };
  db.posts.push(post); save(db);
  res.status(201).json({ post });
});

app.delete("/api/posts/:id", auth, (req, res) => {
  const db = load();
  const post = db.posts.find(p => p.id === Number(req.params.id));
  if (!post) return res.status(404).json({ error: "Yazı tapılmadı." });
  if (post.authorId !== req.user.id) return res.status(403).json({ error: "Bu yazını silmək icazəniz yoxdur." });
  db.posts = db.posts.filter(p => p.id !== post.id); save(db);
  res.json({ ok: true });
});

app.use("/api", (req, res) => res.status(404).json({ error: "Belə API yoxdur." }));
app.listen(PORT, () => console.log(`Server işləyir: http://localhost:${PORT}`));
