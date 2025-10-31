const con = require("./db");
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const argon2 = require('@node-rs/argon2');

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(
    session({
        secret: 'room-booking-secret',
        resave: false,
        saveUninitialized: false,
    }),
);
//-------------------------- starting server ------------------------
const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Server is running at http://localhost:${PORT}`);
});


//-------------------------- password generator ------------------------
app.get('/api/password/:raw', (req, res) => {
   const raw = req.params.raw;
   const hash = argon2.hashSync(raw);
   res.send(hash);
});
//-------------------------- login ------------------------
app.post("/login", (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).send("Username and password required");
    const sql = "SELECT user_id, username, password, role FROM users WHERE username = ?";
    con.query(sql, [username], (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).send("Internal Server Error");
        }
        if (results.length === 0) {
            return res.status(401).send("Username doesn't exist");
        }
        const user = results[0];
        // compare passwords using argon2id
        const same = argon2.verifySync(results[0].password, password);
        if(same) {
            return res.json({"uid": results[0].id, "username": username, "role": results[0].role});
        }
        return res.status(401).send("Wrong password");
    });
});


//------------------register---------------------
app.post('/register', async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password) {
    return res.status(400).send("All fields are required");
  }
  try {
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    const sql = "INSERT INTO users (username, password, role) VALUES (?, ?, 'student')";
    con.query(sql, [username, hashedPassword], (err, result) => {
      if (err) {
        console.error(err);
        return res.status(500).send("Database error: " + err.message);
      }
      res.status(200).send("User registered successfully");
    });
  } catch (e) {
    res.status(500).send("Server error: " + e);
  }
});


