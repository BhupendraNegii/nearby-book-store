require('dotenv').config();
const express = require('express');
const mysql = require('mysql2');
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

// === Database ===
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME
});

db.connect(err => {
  if (err) {
    console.error('MySQL connection error:', err);
    process.exit(1);
  }
  console.log('Connected to MySQL - nearby_book_store');
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
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false }
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
  db.query('INSERT INTO bookies (name, email, password) VALUES (?, ?, ?)', [name, email, hash], (err) => {
    if (err?.code === 'ER_DUP_ENTRY') {
      return res.render('register', { error_msg: 'Email already exists' });
    }
    if (err) return res.render('register', { error_msg: 'Server error' });
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
  db.query('SELECT * FROM bookies WHERE email = ?', [email], async (err, results) => {
    if (err || !results.length) {
      return res.render('login', { error_msg: 'Invalid credentials' });
    }
    const user = results[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.render('login', { error_msg: 'Invalid credentials' });

    // Save session data
    req.session.bookieId = user.id;
    req.session.bookieName = user.name;
    req.session.role = user.role;
    req.session.gender = user.gender; // ← Save gender

    if (user.role === 'admin') {
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
    return res.render('add-book', { error_msg: 'Title, author, and price required' });
  }

  db.query(
    `INSERT INTO books (title, author, price, owner_id, is_available, cover_url, genre, description)
     VALUES (?, ?, ?, ?, TRUE, ?, ?, ?)`,
    [title, author, price, owner_id, cover_url, genre || null, description || null],
    (err) => {
      if (err) return res.json({ success: false, error: 'Error adding book' });
      res.json({ success: true }); // ← AJAX response
    }
  );
});

// ——— SET GENDER (Only male/female) ———
app.post('/set-gender', requireLogin, (req, res) => {
  const { gender } = req.body;
  const userId = req.session.bookieId;

  if (!['male', 'female'].includes(gender)) {
    return res.status(400).json({ error: "Please select 'male' or 'female'" });
  }

  db.query('UPDATE bookies SET gender = ? WHERE id = ?', [gender, userId], (err) => {
    if (err) {
      console.error('Set gender error:', err);
      return res.status(500).json({ error: 'Failed to save gender' });
    }
    req.session.gender = gender;
    res.json({ success: true });
  });
});

// === Dashboard (With Gender & AI) ===
app.get('/dashboard', requireLogin, (req, res) => {
  const bookieId = req.session.bookieId;
  const gender = req.session.gender; // ← Pass to view

  const q = {
    owned: 'SELECT * FROM books WHERE owner_id = ?',
    bought: `SELECT b.*, p.purchase_date FROM purchases p JOIN books b ON p.book_id = b.id WHERE p.buyer_id = ?`,
    available: `SELECT b.*, bk.name AS owner_name FROM books b JOIN bookies bk ON b.owner_id = bk.id WHERE b.is_available = TRUE AND b.owner_id != ?`
  };

  db.query(q.owned, [bookieId], (err, owned) => {
    if (err) throw err;

    db.query(q.bought, [bookieId], (err, bought) => {
      if (err) throw err;

      db.query(q.available, [bookieId], (err, available) => {
        if (err) throw err;

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

        // Render with gender
        res.render('dashboard', {
          bookieName: req.session.bookieName,
          owned,
          bought,
          available,
          recommendations,
          gender // ← Pass gender to EJS
        });
      });
    });
  });
});

// ——— BUY BOOK ———
app.post('/buy-book', requireLogin, (req, res) => {
  const { bookId } = req.body;
  const buyerId = req.session.bookieId;

  db.query('SELECT * FROM books WHERE id = ? AND is_available = TRUE AND owner_id != ?', [bookId, buyerId], (err, books) => {
    if (err || books.length === 0) return res.json({ success: false, error: 'Book not available' });

    const book = books[0];
    db.query('START TRANSACTION', err => {
      if (err) return res.json({ success: false, error: 'Transaction error' });

      db.query('UPDATE books SET is_available = FALSE WHERE id = ?', [bookId], err => {
        if (err) { db.query('ROLLBACK'); return res.json({ success: false, error: 'Update failed' }); }

        db.query('INSERT INTO purchases (book_id, buyer_id, purchase_date) VALUES (?, ?, NOW())',
          [bookId, buyerId], err => {
            if (err) { db.query('ROLLBACK'); return res.json({ success: false, error: 'Purchase failed' }); }
            db.query('COMMIT', () => res.json({ success: true }));
          });
      });
    });
  });
});

// === ML: Recommendations Page ===
app.get('/recommendations', requireLogin, (req, res) => {
  const bookieId = req.session.bookieId;

  db.query(`
    SELECT b.id, b.title, b.author, b.genre, b.description 
    FROM purchases p 
    JOIN books b ON p.book_id = b.id 
    WHERE p.buyer_id = ?
  `, [bookieId], (err, userBooks) => {
    if (err) throw err;

    db.query(`
      SELECT b.id, b.title, b.author, b.genre, b.description, b.price, b.cover_url, bk.name AS owner_name
      FROM books b 
      JOIN bookies bk ON b.owner_id = bk.id 
      WHERE b.is_available = TRUE AND b.owner_id != ?
    `, [bookieId], (err, allBooks) => {
      if (err) throw err;

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
    });
  });
});

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

// === ADMIN DASHBOARD ===
app.get('/admin', requireAdmin, (req, res) => {
  db.query('SELECT id, name, email, role FROM bookies ORDER BY id', (err, users) => {
    if (err) throw err;
    res.render('admin/dashboard', { users });
  });
});

app.get('/admin/books', requireAdmin, (req, res) => {
  db.query(`
    SELECT b.*, k.name AS owner_name 
    FROM books b 
    JOIN bookies k ON b.owner_id = k.id 
    ORDER BY b.id DESC
  `, (err, books) => {
    if (err) throw err;
    res.render('admin/books', { books });
  });
});

app.post('/admin/books/delete/:id', requireAdmin, (req, res) => {
  const bookId = req.params.id;
  db.query('DELETE FROM books WHERE id = ?', [bookId], (err) => {
    if (err) {
      console.error(err);
      return res.redirect('/admin/books?error=Failed to delete');
    }
    res.redirect('/admin/books?success=Book deleted');
  });
});

app.get('/admin/books/edit/:id', requireAdmin, (req, res) => {
  const bookId = req.params.id;
  db.query('SELECT * FROM books WHERE id = ?', [bookId], (err, results) => {
    if (err || results.length === 0) return res.redirect('/admin/books');
    res.render('admin/edit-book', { book: results[0] });
  });
});

app.post('/admin/books/edit/:id', requireAdmin, upload.single('cover'), (req, res) => {
  const bookId = req.params.id;
  const { title, author, price, genre, description, is_available } = req.body;
  const cover_url = req.file ? `/uploads/${req.file.filename}` : req.body.current_cover;

  const sql = `
    UPDATE books 
    SET title=?, author=?, price=?, genre=?, description=?, is_available=?, cover_url=?
    WHERE id=?
  `;
  db.query(sql, [title, author, price, genre || null, description || null, is_available ? 1 : 0, cover_url, bookId], (err) => {
    if (err) {
      console.error(err);
      return res.redirect('/admin/books?error=Update failed');
    }
    res.redirect('/admin/books?success=Book updated');
  });
});

// Start
app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});