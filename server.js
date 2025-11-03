require('dotenv').config();
const express = require('express');
const { Pool } = require('pg'); // ← NEW: PostgreSQL
const bcrypt = require('bcryptjs');
const session = require('express-session');
const bodyParser = require('body-parser');
const multer = require('multer');
const path = require('path');
const natural = require('natural');
const TfIdf = natural.TfIdf;
const similarity = require('cosine-similarity');

const app = express();
const port = process.env.PORT || 3000;

// === Multer: Uploads ===
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'public/uploads'),
  filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname)
});
const upload = multer({ storage });

// === Database (PostgreSQL) ===
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

pool.connect((err) => {
  if (err) {
    console.error('PostgreSQL connection error:', err.stack);
    process.exit(1);
  }
  console.log('Connected to PostgreSQL - nearby_book_store');
});

// === ADMIN AUTH MIDDLEWARE ===
const requireAdmin = (req, res, next) => {
  if (req.session.bookieId && req.session.role === 'admin') {
    return next();
  }
  res.status(403).send('Access Denied: Admins Only');
};

// === Middleware ===
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(session({
  secret: process.env.SESSION_SECRET || 'fallback_secret',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: process.env.NODE_ENV === 'production' }
}));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));

// === Auth ===
const requireLogin = (req, res, next) => {
  if (req.session.bookieId) return next();
  res.redirect('/login');
};

// === ROUTES ===

// Home
app.get('/', (req, res) => res.redirect('/login'));

// Register
app.get('/register', (req, res) => res.render('register'));

app.post('/register', async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) {
    return res.render('register', { error_msg: 'All fields required' });
  }
  const hash = await bcrypt.hash(password, 10);
  const query = 'INSERT INTO bookies (name, email, password) VALUES ($1, $2, $3) RETURNING id';
  pool.query(query, [name, email, hash], (err, result) => {
    if (err?.code === '23505') { // Unique violation
      return res.render('register', { error_msg: 'Email already exists' });
    }
    if (err) {
      console.error(err);
      return res.render('register', { error_msg: 'Server error' });
    }
    res.redirect('/login');
  });
});

// Login
app.get('/login', (req, res) => res.render('login'));

app.post('/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.render('login', { error_msg: 'Email and password required' });
  }
  pool.query('SELECT * FROM bookies WHERE email = $1', [email], async (err, result) => {
    if (err || result.rows.length === 0) {
      return res.render('login', { error_msg: 'Invalid credentials' });
    }
    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.render('login', { error_msg: 'Invalid credentials' });

    req.session.bookieId = user.id;
    req.session.bookieName = user.name;
    req.session.role = user.role || 'user';
    req.session.gender = user.gender;

    if (req.session.role === 'admin') {
      return res.redirect('/admin');
    }
    res.redirect('/dashboard');
  });
});

// Add Book
app.get('/add-book', requireLogin, (req, res) => res.render('add-book'));

app.post('/add-book', requireLogin, upload.single('cover'), (req, res) => {
  const { title, author, price, genre, description } = req.body;
  const cover_url = req.file ? `/uploads/${req.file.filename}` : null;
  const owner_id = req.session.bookieId;

  if (!title || !author || !price) {
    return res.json({ success: false, error: 'Title, author, and price required' });
  }

  const query = `
    INSERT INTO books (title, author, price, owner_id, is_available, cover_url, genre, description)
    VALUES ($1, $2, $3, $4, TRUE, $5, $6, $7)
  `;

  pool.query(query, [title, author, price, owner_id, cover_url, genre || null, description || null], (err) => {
    if (err) return res.json({ success: false, error: 'Error adding book' });
    res.json({ success: true });
  });
});

// ——— SET GENDER ———
app.post('/set-gender', requireLogin, (req, res) => {
  const { gender } = req.body;
  const userId = req.session.bookieId;

  if (!['male', 'female'].includes(gender)) {
    return res.status(400).json({ error: "Please select 'male' or 'female'" });
  }

  pool.query('UPDATE bookies SET gender = $1 WHERE id = $2', [gender, userId], (err) => {
    if (err) return res.status(500).json({ error: 'Failed to save gender' });
    req.session.gender = gender;
    res.json({ success: true });
  });
});

// === Dashboard ===
app.get('/dashboard', requireLogin, async (req, res) => {
  const bookieId = req.session.bookieId;

  const q = {
    owned: 'SELECT * FROM books WHERE owner_id = $1',
    bought: `SELECT b.*, p.purchase_date FROM purchases p JOIN books b ON p.book_id = b.id WHERE p.buyer_id = $1`,
    available: `SELECT b.*, bk.name AS owner_name FROM books b JOIN bookies bk ON b.owner_id = bk.id WHERE b.is_available = TRUE AND b.owner_id != $1`
  };

  try {
    const [ownedRes, boughtRes, availableRes] = await Promise.all([
      pool.query(q.owned, [bookieId]),
      pool.query(q.bought, [bookieId]),
      pool.query(q.available, [bookieId])
    ]);

    const owned = ownedRes.rows;
    const bought = boughtRes.rows;
    const available = availableRes.rows;

    // === AI RECOMMENDATIONS ===
    let recommendations = [];
    if (bought.length > 0) {
      const tfidf = new TfIdf();
      const allDocs = [...bought, ...available];

      allDocs.forEach(book => {
        const text = `${book.title} ${book.author} ${book.genre || ''} ${book.description || ''}`.toLowerCase();
        tfidf.addDocument(text);
      });

      const getVector = (index) => {
        const vec = [];
        tfidf.tfidfs('', (i, measure) => {
          if (i === index) vec.push(measure);
        });
        return vec;
      };

      const userVectors = bought.map((_, i) => getVector(i));
      const avgUserVector = userVectors[0].map((_, col) =>
        userVectors.reduce((sum, vec) => sum + (vec[col] || 0), 0) / userVectors.length
      );

      recommendations = available
        .map((book, idx) => {
          const bookVector = getVector(bought.length + idx);
          const score = similarity(avgUserVector, bookVector);
          return { ...book, score };
        })
        .filter(r => r.score > 0.12)
        .sort((a, b) => b.score - a.score)
        .slice(0, 6);
    }

    res.render('dashboard', {
      bookieName: req.session.bookieName,
      owned,
      bought,
      available,
      recommendations,
      gender: req.session.gender
    });
  } catch (err) {
    console.error(err);
    res.status(500).send('Database error');
  }
});

// ——— BUY BOOK ———
app.post('/buy-book', requireLogin, (req, res) => {
  const { bookId } = req.body;
  const buyerId = req.session.bookieId;

  pool.query('SELECT * FROM books WHERE id = $1 AND is_available = TRUE AND owner_id != $2', [bookId, buyerId], async (err, result) => {
    if (err || result.rows.length === 0) return res.json({ success: false, error: 'Book not available' });

    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query('UPDATE books SET is_available = FALSE WHERE id = $1', [bookId]);
      await client.query('INSERT INTO purchases (book_id, buyer_id, purchase_date) VALUES ($1, $2, NOW())', [bookId, buyerId]);
      await client.query('COMMIT');
      res.json({ success: true });
    } catch (e) {
      await client.query('ROLLBACK');
      res.json({ success: false, error: 'Transaction failed' });
    } finally {
      client.release();
    }
  });
});

// === Recommendations Page ===
app.get('/recommendations', requireLogin, async (req, res) => {
  const bookieId = req.session.bookieId;

  try {
    const userRes = await pool.query(`
      SELECT b.id, b.title, b.author, b.genre, b.description 
      FROM purchases p 
      JOIN books b ON p.book_id = b.id 
      WHERE p.buyer_id = $1
    `, [bookieId]);

    const allRes = await pool.query(`
      SELECT b.id, b.title, b.author, b.genre, b.description, b.price, b.cover_url, bk.name AS owner_name
      FROM books b 
      JOIN bookies bk ON b.owner_id = bk.id 
      WHERE b.is_available = TRUE AND b.owner_id != $1
    `, [bookieId]);

    const userBooks = userRes.rows;
    const allBooks = allRes.rows;

    if (userBooks.length === 0) {
      return res.render('recommendations', { recommendations: [], message: 'Buy a book to get recommendations!' });
    }

    const tfidf = new TfIdf();
    [...userBooks, ...allBooks].forEach(book => {
      const text = `${book.title} ${book.author} ${book.genre || ''} ${book.description || ''}`.toLowerCase();
      tfidf.addDocument(text);
    });

    const getVector = (index) => {
      const vec = [];
      tfidf.tfidfs('', (i, measure) => {
        if (i === index) vec.push(measure);
      });
      return vec;
    };

    const userVectors = userBooks.map((_, i) => getVector(i));
    const avgUserVector = userVectors[0].map((_, col) =>
      userVectors.reduce((sum, vec) => sum + (vec[col] || 0), 0) / userVectors.length
    );

    const recommendations = allBooks
      .map((book, idx) => {
        const bookVector = getVector(userBooks.length + idx);
        const score = similarity(avgUserVector, bookVector);
        return { ...book, score };
      })
      .filter(r => r.score > 0.1)
      .sort((a, b) => b.score - a.score)
      .slice(0, 6);

    res.render('recommendations', { recommendations });
  } catch (err) {
    console.error(err);
    res.status(500).send('Error loading recommendations');
  }
});

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

// === ADMIN ROUTES ===
app.get('/admin', requireAdmin, (req, res) => {
  pool.query('SELECT id, name, email, role FROM bookies ORDER BY id', (err, result) => {
    if (err) throw err;
    res.render('admin/dashboard', { users: result.rows });
  });
});

app.get('/admin/books', requireAdmin, (req, res) => {
  pool.query(`
    SELECT b.*, k.name AS owner_name 
    FROM books b 
    JOIN bookies k ON b.owner_id = k.id 
    ORDER BY b.id DESC
  `, (err, result) => {
    if (err) throw err;
    res.render('admin/books', { books: result.rows });
  });
});

app.post('/admin/books/delete/:id', requireAdmin, (req, res) => {
  const bookId = req.params.id;
  pool.query('DELETE FROM books WHERE id = $1', [bookId], (err) => {
    if (err) return res.redirect('/admin/books?error=Failed to delete');
    res.redirect('/admin/books?success=Book deleted');
  });
});

app.get('/admin/books/edit/:id', requireAdmin, (req, res) => {
  const bookId = req.params.id;
  pool.query('SELECT * FROM books WHERE id = $1', [bookId], (err, result) => {
    if (err || result.rows.length === 0) return res.redirect('/admin/books');
    res.render('admin/edit-book', { book: result.rows[0] });
  });
});

app.post('/admin/books/edit/:id', requireAdmin, upload.single('cover'), (req, res) => {
  const bookId = req.params.id;
  const { title, author, price, genre, description, is_available } = req.body;
  const cover_url = req.file ? `/uploads/${req.file.filename}` : req.body.current_cover;

  const sql = `
    UPDATE books 
    SET title=$1, author=$2, price=$3, genre=$4, description=$5, is_available=$6, cover_url=$7
    WHERE id=$8
  `;
  pool.query(sql, [title, author, price, genre || null, description || null, !!is_available, cover_url, bookId], (err) => {
    if (err) return res.redirect('/admin/books?error=Update failed');
    res.redirect('/admin/books?success=Book updated');
  });
});

// Start
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});