const con = require("./db");
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');

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

const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Server is running at http://localhost:${PORT}`);
});

//hash password for testing
app.get("/password/:password", function (req, res) {
    const password = req.params.password;
    bcrypt.hash(password, 10, function (err, hash) {
        if (err) {
            console.error(err);
            return res.status(500).send("Password hashing error");
        }
        res.status(200).send(hash);
    });
})

//---------------------Login-----------------------//
// app.post("/login", function (req, res) {
//     const username = req.body.username;
//     const password = req.body.password;

//     const sql = `SELECT user_id, username, password, role FROM users WHERE username = ?`;

//     con.query(sql, [username], function (err, result) {
//         if (err) {
//             console.err(err);
//             return res.status(500).send("Internal Server Error");
//         }
//         if (result.length === 0) {
//             return res.status(401).send("Username doesn't exist");
//         }

//         bcrypt.compare(password, result[0].password, function (err, isMatch) {
//             if (err) {
//                 return res.status(500).send("Authentication Server Error");
//             }

//             if (isMatch) {
//                 const user = result[0];
//                 //check user role exist 
//                 const userRoleStr = user.role;
//                 if (!userRoleStr) {
//                     return res.status(403).send("Forbidden: Unknown Role");
//                 }
//                 return res.status(200).json({ role: userRoleStr });
//             }else{
//                 return res.status(400).send("Wrong Password")
//             }
//         });
//     })
// })



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
        bcrypt.compare(password, user.password, (err, isMatch) => {
            if (err) return res.status(500).send("Authentication Server Error");
            if (!isMatch) return res.status(401).send("Wrong Password");
            if (!user.role) return res.status(403).send("Forbidden: Unknown Role");
            res.status(200).json({ role: user.role });
        });
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
