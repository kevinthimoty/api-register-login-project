const express = require('express');
const bodyParser = require('body-parser');
const { check, validationResult } = require('express-validator');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2');

const app = express();
const port = 3000;

const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',      
  password: '',  
  database: 'api_techtest' 
});

app.use(bodyParser.json());

function authenticateToken(req, res, next) {
  const token = req.header('Authorization');
  if (!token) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  jwt.verify(token, 'your_secret_key', (err, decoded) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid token' });
    }
    req.userId = decoded.userId;
    next();
  });
}

app.post('/api/register', [
  check('name').notEmpty(),
  check('email').isEmail(),
  check('password').isLength({ min: 6 })
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(422).json({ errors: errors.array() });
  }

  const { name, email, password } = req.body;

  bcrypt.hash(password, 10, (err, hash) => {
    if (err) {
      return res.status(500).json({ error: 'Error while hashing password' });
    }

    const sql = 'INSERT INTO users (name, email, password) VALUES (?, ?, ?)';
    db.query(sql, [name, email, hash], (err, result) => {
      if (err) {
        return res.status(500).json({ error: 'Error while registering user' });
      }
      return res.status(201).json({ message: 'User registered successfully' });
    });
  });
});

app.post('/api/login', (req, res) => {
  const { email, password } = req.body;

  const sql = 'SELECT * FROM users WHERE email = ?';
  db.query(sql, [email], (err, results) => {
    if (err) {
      return res.status(500).json({ error: 'Error while logging in' });
    }

    if (results.length === 0) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }
    const user = results[0];
    bcrypt.compare(password, user.password, (err, isMatch) => {
      if (err) {
        return res.status(500).json({ error: 'Error while comparing passwords' });
      }

      if (!isMatch) {
        return res.status(401).json({ error: 'Invalid email or password' });
      }

      const token = jwt.sign({ userId: user.id }, 'your_secret_key'); 
      return res.json({ token });
    });
  });
});

app.get('/api/me', authenticateToken, (req, res) => {
  const sql = 'SELECT id, name, email FROM users WHERE id = ?';
  db.query(sql, [req.userId], (err, results) => {
    if (err) {
      return res.status(500).json({ error: 'Error while fetching user data' });
    }

    if (results.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const user = results[0];
    return res.json({
      id: user.id,
      name: user.name,
      email: user.email
    });
  });
});

app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
