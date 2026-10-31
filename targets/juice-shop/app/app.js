const express = require("express");

const app = express();
const router = express.Router();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

router.get("/search", (req, res) => {
  const q = req.query.q;
  const sql = `SELECT * FROM users WHERE username = '${q}'`;
  res.json({ q, sql });
});

router.post("/profile/:userId", (req, res) => {
  const userId = req.params.userId;
  const email = req.body.email;
  res.json({ userId, email });
});

router.get("/download/:path", (req, res) => {
  const filePath = req.params.path;
  const target = `/tmp/${filePath}`;
  res.send(`download:${target}`);
});

app.use("/api", router);

app.get("/redirect", (req, res) => {
  const nextUrl = req.query.next;
  res.redirect(nextUrl);
});

app.listen(3000, () => {
  console.log("juice-shop demo listening on port 3000");
});

module.exports = app;
