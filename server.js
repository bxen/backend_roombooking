
// ===== Import modules =====
const express = require("express");
const session = require("express-session");
const bcrypt = require("bcrypt");
const argon2 = require("@node-rs/argon2");
const con = require("./db");

const app = express();


app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(
  session({
    secret: "room-booking-secret",
    resave: false,
    saveUninitialized: false,
  })
);


function isAuthenticated(req, res, next) {
  if (req.session && req.session.userId) return next();
  return res.status(401).send("Unauthorized");
}


function isStudent(req, res, next) {
  if (req.session && req.session.role === "student") return next();
  return res.status(403).send("Forbidden: Students only");
}

// ===== Server Start =====
const PORT = 3000;
app.listen(PORT, () =>
  console.log(`Server running at http://localhost:${PORT}`)
);

// ===== Test Password =====
app.get("/api/password/:raw", (req, res) => {
  const raw = req.params.raw;
  const hash = argon2.hashSync(raw);
  res.send(hash);
});

// ===== Login =====
app.post("/login", (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).send("Username & password required");

  const sql =
    "SELECT user_id, username, password, role FROM users WHERE username = ?";

  con.query(sql, [username], (err, results) => {
    if (err) return res.status(500).send("DB error");

    if (results.length === 0)
      return res.status(401).send("Username does not exist");

    const user = results[0];
    const same = argon2.verifySync(user.password, password);

    if (!same) return res.status(401).send("Wrong password");

    req.session.userId = user.user_id;
    req.session.role = user.role;

    return res.json({
      uid: user.user_id,
      username: user.username,
      role: user.role,
    });
  });
});

// ===== Register =====
app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).send("All fields required");

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const sql =
      "INSERT INTO users (username, password, role) VALUES (?, ?, 'student')";

    con.query(sql, [username,hashedPassword], (err) => {
      if (err) return res.status(500).send("DB error: " + err.message);
      res.send("User registered ");
    });
  } catch (e) {
    res.status(500).send("Server error");
  }
});

// ===== Get Rooms =====
app.get("/api/rooms", /* isAuthenticated, */ (req, res) => {
  const sql =
    "SELECT room_id, room_name FROM rooms WHERE status='free'";

  con.query(sql, (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).send("DB error");
    }
    res.json(results);
  });
});

// ===== Room Detail + Timeslots =====

app.get("/api/rooms/:id", /* isAuthenticated, */ (req, res) => {
  const roomId = req.params.id;
  const date = req.query.date;
  if (!date)
    return res.status(400).send("?date=YYYY-MM-DD required");

  // (แก้ไข Query ให้ตรงกับ DB)
  const sql = `
    SELECT 
      ts.slot_id, 
      ts.start_time, 
      ts.end_time,
      COALESCE(b.status, 'free') AS status
    FROM 
      time_slots ts
    LEFT JOIN 
      bookings b ON ts.slot_id = b.slot_id 
                   AND b.room_id = ? 
                   AND b.booking_date = ?
    ORDER BY 
      ts.start_time;
  `;

  con.query(sql, [roomId, date], (err, timeSlots) => {
    if (err) {
      console.error(err);
      return res.status(500).send("DB error: " + err.message);
    }
    
    con.query(
      "SELECT room_id, room_name FROM rooms WHERE room_id=?",
      [roomId],
      (err, roomInfo) => {
        if (err) {
          console.error(err);
          return res.status(500).send("DB error");
        }
        if (roomInfo.length === 0)
          return res.status(404).send("Room not found");

        res.json({
          ...roomInfo[0],
          time_slots: timeSlots,
        });
      }
    );
  });
});


// ===== Book Room =====
app.post("/api/bookings", isStudent, (req, res) => {
  // (DB ใช้ 'purpose')
  const { room_id, slot_id, date, purpose } = req.body;
  const userId = req.session.userId;

  if (!room_id || !slot_id || !date || !purpose)
    return res.status(400).send("Missing fields");

  // (DB use 'pending')
  const sql = `
    INSERT INTO bookings (room_id, user_id, slot_id, booking_date, purpose, status)
    VALUES (?,?,?,?,?,'pending') 
  `;

  con.query(sql, [room_id, userId, slot_id, date, purpose], (err, result) => {
    if (err) {
      console.error(err);
      if (err.code === "ER_DUP_ENTRY")
        return res.status(409).send("Slot already booked");
      return res.status(500).send("DB error");
    }
    res.status(201).json({
      message: "Booking created",
      booking_id: result.insertId,
    });
  });
});

// ===== Booking History =====
app.get("/api/bookings/my", isStudent, (req, res) => {
  const userId = req.session.userId;

  // (SQL ตรงกับ DB)
  const sql = `
    SELECT b.booking_id, b.booking_date, b.status, b.purpose,
           r.room_name AS room_name, ts.start_time, ts.end_time
    FROM bookings b
    JOIN rooms r ON b.room_id=r.room_id
    JOIN time_slots ts ON b.slot_id=ts.slot_id
    WHERE b.user_id=? 
    ORDER BY b.booking_date DESC, ts.start_time DESC;
  `;

  con.query(sql, [userId], (err, results) => {
    if (err) {
      console.error(err);
      return res.status(500).send("DB error");
    }
    res.json(results);
  });
});

// ===== Cancel Booking =====
app.delete("/api/bookings/:id", isStudent, (req, res) => {
  const bookingId = req.params.id;
  const userId = req.session.userId;

  // (DB ของคุณใช้ 'pending')
  const sql =
    "DELETE FROM bookings WHERE booking_id=? AND user_id=? AND status='pending'";

  con.query(sql, [bookingId, userId], (err, result) => {
    if (err) {
      console.error(err);
      return res.status(500).send("DB error");
    }
    if (result.affectedRows === 0)
      return res.status(404).send("Not found or cannot cancel");
    res.send("Booking canceled");
  });
});

