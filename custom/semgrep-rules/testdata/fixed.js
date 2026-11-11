// Fixture CORRIGEE - ne doit AUCUNE alerte des regles custom
const express = require('express');
const app = express();
app.use(express.json());

app.post('/login', (req, res) => {
  models.sequelize.query(
    'SELECT * FROM Users WHERE email = :email AND deletedAt IS NULL',
    { replacements: { email: req.body.email } }   // requete preparee
  ).then(rows => res.json(rows));
});

app.get('/lookup', (req, res) => {
  const domain = req.query.domain;
  if (!/^[a-zA-Z0-9.-]+$/.test(domain)) return res.status(400).send('bad');
  require('dns').resolve(domain, (e, addrs) => res.json(addrs));  // pas de shell
});

app.get('/page', (req, res) => {
  document.getElementById('out').textContent = new URLSearchParams(location.search).get('q');
});
