// run this once in a Node REPL or a tiny script
const bcrypt = require('bcryptjs');
bcrypt.hash('admin123', 10, (e, h) => console.log(h));