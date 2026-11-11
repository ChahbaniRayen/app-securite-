// Fixture VULNERABLE - doit declencher custom.js.sequelize.raw-query-user-input
const express = require('express');
const app = express();
app.use(express.json());

app.post('/login', (req, res) => {
  // TP2 : requete SQL par template literal (source -> sink)
  models.sequelize.query(
    `SELECT * FROM Users WHERE email = '${req.body.email}' AND deletedAt IS NULL`
  ).then(rows => res.json(rows));
});

app.get('/lookup', (req, res) => {
  // TP2 mini-lab : command injection
  require('child_process').exec(`nslookup ${req.query.domain}`, (e, out) => res.send(out));
});

app.get('/page', (req, res) => {
  // TP3 : XSS DOM
  document.getElementById('out').innerHTML = new URLSearchParams(location.search).get('q');
});
