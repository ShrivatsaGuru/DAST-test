const express = require('express');
const app = express();
const port = process.env.PORT || 3000;

const users = [
  { username: 'admin', password: 'password123' },
  { username: 'test', password: 'test' }
];

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Vulnerable search (Reflected XSS)
app.get('/search', (req, res) => {
  const q = req.query.q || '';
  res.send(`<h1>Results for: ${q}</h1>`);
});

// Open redirect
app.get('/redirect', (req, res) => {
  const url = req.query.url;
  if (url) {
    res.redirect(url); // Unsafe
  } else {
    res.send('No URL provided.');
  }
});

// Insecure login (no hashing, no validation, verbose error messages)
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username && u.password === password);

  if (user) {
    res.send(`Welcome, ${username}!`);
  } else {
    res.status(401).send('Invalid username or password. Hint: try admin/password123');
  }
});

// SQL Injection simulation (No parameterization)
app.get('/user', (req, res) => {
  const id = req.query.id;
  // Pretend SQL query without sanitization
  res.send(`Fetched user with ID: ${id}`);
});

// Sensitive data exposure
app.get('/config', (req, res) => {
  res.send({
    dbHost: 'localhost',
    dbUser: 'root',
    dbPassword: 'supersecret'
  });
});

// Missing security headers
app.get('/', (req, res) => {
  res.send(`
    <h1>Welcome to the vulnerable app</h1>
    <form action="/search" method="get">
      <input type="text" name="q" placeholder="Search...">
      <button type="submit">Search</button>
    </form>
    <form action="/login" method="post">
      <input type="text" name="username" placeholder="Username">
      <input type="password" name="password" placeholder="Password">
      <button type="submit">Login</button>
    </form>
    <a href="/redirect?url=https://example.com">Redirect Example</a><br>
    <a href="/config">View Config</a><br>
    <a href="/user?id=1 OR 1=1">SQLi Example</a>
  `);
});

app.listen(port, () => {
  console.log(`App listening at http://localhost:${port}`);
});
