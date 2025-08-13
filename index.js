const express = require('express');
const app = express();
const port = process.env.PORT || 3000;

app.use(express.urlencoded({ extended: true }));
app.use(express.json());


app.get('/search', (req, res) => {
  const q = req.query.q || '';
  res.send(`<h1>Results for: ${q}</h1>`);
});

app.get('/redirect', (req, res) => {
  const url = req.query.url;
  if (url) {
    res.redirect(url); // Unsafe
  } else {
    res.send('No URL provided.');
  }
});

// No security headers
app.get('/', (req, res) => {
  res.send(`
    <h1>Welcome to the vulnerable app</h1>
    <form action="/search" method="get">
      <input type="text" name="q" placeholder="Search...">
      <button type="submit">Search</button>
    </form>
    <a href="/redirect?url=https://example.com">Redirect Example</a>
  `);
});

app.listen(port, () => {
  console.log(`App listening at http://localhost:${port}`);
});
