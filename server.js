// ===== Core modules =====
const express = require("express");
const session = require("express-session");
const cors = require("cors");
const bcrypt = require("bcrypt");
const con = require("./db");
const cron = require("node-cron");

// ===== App & middlewares =====
const app = express();

app.use(
  cors({
    origin: true, // ใส่ origin ของ frontend ถ้าอยากล็อกให้ชัด
    credentials: true,
  })
);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use((req, res, next) => {
  res.set("Cache-Control", "no-store");
  next();
});

app.use(
  session({
    secret: "room-booking-secret",
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, sameSite: "lax" },
  })
);

// ===== Helpers (Auth) =====
function isAuthenticated(req, res, next) {
  if (req.session && req.session.userId) return next();
  return res.status(401).send("Unauthorized");
}
function isStudent(req, res, next) {
  if (req.session?.role === "student") return next();
  return res.status(403).send("Forbidden: Students only");
}
function isStaff(req, res, next) {
  if (req.session?.role === "staff") return next();
  return res.status(403).send("Forbidden: Staff only");
}
function isLecturer(req, res, next) {
  if (req.session?.role === "lecturer") return next();
  return res.status(403).send("Forbidden: Lecturers only");
}
function requireDateParam(req, res, next) {
  const d = req.query.date;
  if (!d) return res.status(400).send("?date=YYYY-MM-DD required");
  if (!/^\d{4}-\d{2}-\d{2}$/.test(d)) {
    return res.status(400).send("date format must be YYYY-MM-DD");
  }
  next();
}

// ===== Utilities =====
function todayYMD() {
  const now = new Date();
  const mm = String(now.getMonth() + 1).padStart(2, "0");
  const dd = String(now.getDate()).padStart(2, "0");
  return `${now.getFullYear()}-${mm}-${dd}`;
}

// ตอนนี้ให้ดึง user แค่จาก session เท่านั้น (ไม่อ่านจาก body/query แล้ว)
function getUserIdFromSessionOr(req) {
  return req.session && req.session.userId ? req.session.userId : null;
}

function mapBookingToSlotStatus(dbStatus) {
  if (!dbStatus) return "free";
  if (dbStatus === "pending") return "pending";
  if (dbStatus === "approved" || dbStatus === "reserved") return "reserved";
  if (dbStatus === "rejected" || dbStatus === "cancelled") return "free";
  return "free";
}

// ===== Auto Reject (Cron) =====
function autoRejectExpiredBookings() {
  const sql = `
    UPDATE bookings
    SET status='rejected', rejection_reason='Booking expired'
    WHERE status='pending'
      AND booking_date < CURDATE()
  `;
  con.query(sql, (err, result) => {
    if (err) {
      console.error("Auto-reject failed:", err);
    } else {
      console.log(`Auto-rejected ${result.affectedRows} expired bookings.`);
    }
  });
}

// 1️⃣ รันทันทีตอน start server
autoRejectExpiredBookings();

// 2️⃣ ตั้ง cron รันทุกวันตอนเที่ยงคืน (Asia/Bangkok)
cron.schedule("0 0 * * *", autoRejectExpiredBookings, {
  timezone: "Asia/Bangkok",
});

// ===== Server Start =====
const PORT = 3000;
app.listen(PORT, "0.0.0.0", () => console.log(`Server on 0.0.0.0:${PORT}`));

// ===== Health =====
app.get("/", (_req, res) => res.send("Room Booking API OK"));

// ===== Auth =====
app.post("/login", (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).send("Username & password required");

  const sql =
    "SELECT user_id, username, password, role FROM users WHERE username = ?";

  con.query(sql, [username], async (err, results) => {
    if (err) return res.status(500).send("DB error");
    if (results.length === 0)
      return res.status(401).send("Username does not exist");

    const user = results[0];

    try {
      const ok = await bcrypt.compare(password, user.password);
      if (!ok) return res.status(401).send("Wrong password");

      // set session
      req.session.userId = user.user_id;
      req.session.role = user.role;

      return res.json({
        uid: user.user_id,
        username: user.username,
        role: user.role,
      });
    } catch (e) {
      return res.status(500).send("Server error");
    }
  });
});

// Register (สมัครเป็น student โดยค่าเริ่มต้น)
app.post("/register", async (req, res) => {
  const { username, password, email } = req.body;
  if (!username || !password || !email) {
    return res.status(400).json({ error: "username, password, email required" });
  }
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const sql = `
      INSERT INTO users (name, username, email, password, role)
      VALUES (?, ?, ?, ?, 'student')
    `;
    con.query(sql, [username, username, email, hashedPassword], (err) => {
      if (err) {
        if (err.code === "ER_DUP_ENTRY") {
          const field = (err.message || "").includes("uniq_email")
            ? "email"
            : "username";
          return res.status(409).json({ error: `${field} already exists` });
        }
        return res.status(500).json({ error: "DB error", detail: err.message });
      }
      res.json({ message: "User registered" });
    });
  } catch (e) {
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/logout", isAuthenticated, (req, res) => {
  req.session.destroy(() => res.send("Logged out"));
});

// =======================
//   SESSION PROTECTION
// =======================

// ทุก /api/* ต้อง login ก่อน
app.use("/api", isAuthenticated);

// /api/student/* ต้องเป็น role student
app.use("/api/student", isStudent);

// /api/staff/* ต้องเป็น role staff
app.use("/api/staff", isStaff);

// /api/lecturer/* ต้องเป็น role lecturer
app.use("/api/lecturer", isLecturer);

// ===== Public / Student-facing (แต่ตอนนี้ต้องมี session แล้วเพราะ prefix /api) =====

// เฉพาะห้อง status='free'
app.get("/api/rooms/free-only", (_req, res) => {
  const sql = "SELECT room_id, room_name, status FROM rooms WHERE status='free'";
  con.query(sql, (err, results) => {
    if (err) return res.status(500).send("DB error");
    res.json(results);
  });
});

// ดูห้อง + timeslot สำหรับวันที่ระบุ
app.get("/api/rooms/:id", requireDateParam, (req, res) => {
  const roomId = req.params.id;
  const date = req.query.date;

  const sql = `
    SELECT 
      ts.slot_id,
      ts.start_time,
      ts.end_time,
      COALESCE(b.status, 'free') AS status
    FROM time_slots ts
    LEFT JOIN bookings b 
      ON ts.slot_id = b.slot_id
     AND b.room_id = ?
     AND b.booking_date = ?
    ORDER BY ts.start_time;
  `;

  con.query(sql, [roomId, date], (err, timeSlots) => {
    if (err) return res.status(500).send("DB error: " + err.message);

    con.query(
      "SELECT room_id, room_name, status, image_url FROM rooms WHERE room_id=?",
      [roomId],
      (err2, roomInfo) => {
        if (err2) return res.status(500).send("DB error");
        if (roomInfo.length === 0) return res.status(404).send("Room not found");
        res.json({ ...roomInfo[0], time_slots: timeSlots });
      }
    );
  });
});

// Student: จองห้อง (pending) — ผูกกับ session เท่านั้น
app.post("/api/bookings", isStudent, (req, res) => {
  const { room_id, slot_id, date, purpose } = req.body;
  const userId = req.session.userId; // only session
  if (!userId) return res.status(401).send("Unauthorized");

  if (!room_id || !slot_id || !date || !purpose)
    return res.status(400).send("Missing fields");

  const sql = `
    INSERT INTO bookings (room_id, user_id, slot_id, booking_date, purpose, status)
    VALUES (?,?,?,?,?,'pending')
  `;

  con.query(sql, [room_id, userId, slot_id, date, purpose], (err, result) => {
    if (err) {
      if (err.code === "ER_DUP_ENTRY")
        return res.status(409).send("Slot already booked");
      return res.status(500).send("DB error");
    }
    res
      .status(201)
      .json({ message: "Booking created", booking_id: result.insertId });
  });
});

// Student: ประวัติของฉัน / pending
app.get("/api/student/bookings", (req, res) => {
  const userId = getUserIdFromSessionOr(req);
  if (!userId) return res.status(401).json({ error: "Unauthorized" });
  const scope = (req.query.scope || "pending").toLowerCase();

  const baseSql = `
    SELECT b.booking_id, b.booking_date, b.status, b.purpose, b.rejection_reason,
           r.room_name, r.image_url,
           ts.start_time, ts.end_time,
           u.username AS borrower,
           ua.username AS approver
    FROM bookings b
    JOIN rooms r ON b.room_id = r.room_id
    JOIN time_slots ts ON b.slot_id = ts.slot_id
    JOIN users u ON b.user_id = u.user_id
    LEFT JOIN users ua ON b.approver_id = ua.user_id
    WHERE b.user_id = ?
  `;

  const pendingSql =
    baseSql +
    ` AND b.status = 'pending'
      ORDER BY b.booking_date ASC, ts.start_time ASC`;

  // ไม่เอา cancelled เข้า history
  const historySql =
    baseSql +
    ` AND b.status IN ('approved','reserved','rejected')
      ORDER BY b.booking_date DESC, ts.start_time DESC`;

  const sql = scope === "history" ? historySql : pendingSql;

  con.query(sql, [userId], (err, results) => {
    if (err) return res.status(500).send("DB error: " + err.message);
    res.json(results);
  });
});

// Student: ยกเลิก (เฉพาะ pending) — ลบ record ออกจริง
app.post("/api/bookings/:id/cancel", (req, res) => {
  const bookingId = req.params.id;
  const userId = getUserIdFromSessionOr(req);
  if (!userId) return res.status(401).json({ error: "Unauthorized" });

  const sql = `
    DELETE FROM bookings
     WHERE booking_id = ?
       AND user_id = ?
       AND status = 'pending'
  `;
  con.query(sql, [bookingId, userId], (err, r) => {
    if (err) return res.status(500).json({ error: "DB error", detail: err.message });
    if (r.affectedRows === 0)
      return res.status(404).json({ error: "Not found or cannot cancel" });
    res.json({ message: "Booking cancelled" });
  });
});

// ===== Student bundle endpoints =====
app.get("/api/student/rooms/today", (req, res) => {
  const userId = getUserIdFromSessionOr(req);
  const theDate = todayYMD();

  const roomsSql = `SELECT room_id, room_name, status AS room_status, image_url FROM rooms ORDER BY room_id ASC`;
  con.query(roomsSql, (err, roomRows) => {
    if (err) return res.status(500).send("DB error: " + err.message);

    const tsSql = `
      SELECT r.room_id, ts.slot_id, ts.start_time, ts.end_time, b.status AS booking_status
      FROM rooms r
      CROSS JOIN time_slots ts
      LEFT JOIN bookings b
        ON b.room_id = r.room_id
       AND b.slot_id = ts.slot_id
       AND b.booking_date = ?
    `;
    con.query(tsSql, [theDate], (err2, tsRows) => {
      if (err2) return res.status(500).send("DB error: " + err2.message);

      const bookedSql = `
        SELECT 1
        FROM bookings
        WHERE user_id = ?
          AND booking_date = ?
          AND status IN ('pending','approved','reserved')
        LIMIT 1
      `;

      const toDisp = (s) => {
        if (!s) return "free";
        s = s.toLowerCase();
        if (s === "pending") return "pending";
        if (s === "approved" || s === "reserved") return "reserved";
        return "free";
      };

      const doMerge = (userAlreadyBooked) => {
        const grouped = new Map();
        for (const r of roomRows)
          grouped.set(r.room_id, { ...r, time_slots: [] });

        for (const row of tsRows) {
          const g = grouped.get(row.room_id);
          if (!g) continue;
          const slotStatus =
            g.room_status === "disabled" ? "disabled" : toDisp(row.booking_status);
          g.time_slots.push({
            slot_id: row.slot_id,
            start: row.start_time,
            end: row.end_time,
            start_time: row.start_time,
            end_time: row.end_time,
            status: slotStatus,
          });
        }

        const out = Array.from(grouped.values()).map((r) => ({
          room_id: r.room_id,
          room_name: r.room_name,
          room_status: r.room_status,
          image_url: r.image_url || null,
          user_already_booked_today: !!userAlreadyBooked,
          time_slots: r.time_slots.sort((a, b) =>
            a.start_time.localeCompare(b.start_time)
          ),
        }));
        res.json(out);
      };

      if (!userId) return doMerge(false);
      con.query(bookedSql, [userId, theDate], (err3, br) => {
        if (err3) return res.status(500).send("DB error: " + err3.message);
        doMerge(br.length > 0);
      });
    });
  });
});

// ===== Staff =====
app.get("/api/staff/rooms", (_req, res) => {
  const sql = "SELECT room_id, room_name, status FROM rooms ORDER BY room_id ASC";
  con.query(sql, (err, rows) => {
    if (err) return res.status(500).send("DB error");
    res.json(rows);
  });
});

app.post("/api/staff/rooms", (req, res) => {
  const { room_name, image_url } = req.body;
  if (!room_name) return res.status(400).json({ error: "room_name required" });
  const sql =
    "INSERT INTO rooms (room_name, status, image_url) VALUES (?, 'free', ?)";
  con.query(sql, [room_name, image_url || null], (err, result) => {
    if (err) {
      if (err.code === "ER_DUP_ENTRY")
        return res.status(409).json({ error: "Room name already exists" });
      return res
        .status(500)
        .json({ error: "DB error", detail: err.message });
    }
    res.status(201).json({ message: "Room created", room_id: result.insertId });
  });
});

app.put("/api/staff/rooms/:id", (req, res) => {
  const id = req.params.id;
  const { room_name, status } = req.body;
  if (!room_name && !status) return res.status(400).send("Nothing to update");

  const sql =
    "UPDATE rooms SET room_name=COALESCE(?, room_name), status=COALESCE(?, status) WHERE room_id=?";
  con.query(sql, [room_name || null, status || null, id], (err, r) => {
    if (err) return res.status(500).send("DB error");
    if (r.affectedRows === 0) return res.status(404).send("Room not found");
    res.send("Room updated");
  });
});

// Disable room (ถ้าไม่มี booking active)
app.patch("/api/staff/rooms/:id/disable", (req, res) => {
  const id = req.params.id;
  const today = todayYMD();

  const checkSql = `
    SELECT COUNT(*) AS active_count
    FROM bookings
    WHERE room_id = ?
      AND status IN ('pending', 'approved', 'reserved')
      AND booking_date >= ?
  `;

  con.query(checkSql, [id, today], (errCheck, results) => {
    if (errCheck) {
      return res.status(500).json({ error: "DB check error", detail: errCheck.message });
    }

    const activeCount = results[0].active_count;

    if (activeCount > 0) {
      return res.status(409).json({
        error: "Cannot disable room",
        message: "This room has active or pending bookings.",
      });
    }

    con.query(
      "UPDATE rooms SET status='disabled' WHERE room_id=?",
      [id],
      (errUpdate, r) => {
        if (errUpdate) {
          return res.status(500).json({ error: "DB update error", detail: errUpdate.message });
        }
        if (r.affectedRows === 0) {
          return res.status(404).json({ error: "Room not found" });
        }
        res.json({ message: "Room disabled" });
      }
    );
  });
});

// ===== Lecturer: อนุมัติ/ปฏิเสธ =====
app.get("/api/lecturer/requests", (_req, res) => {
  const sql = `
    SELECT b.booking_id, b.booking_date, b.purpose, b.status,
           r.room_name, ts.start_time, ts.end_time, u.username AS borrower
    FROM bookings b
    JOIN users u ON b.user_id = u.user_id
    JOIN rooms r ON b.room_id = r.room_id
    JOIN time_slots ts ON b.slot_id = ts.slot_id
    WHERE b.status = 'pending'
    ORDER BY b.booking_date ASC, ts.start_time ASC;
  `;
  con.query(sql, (err, rows) => {
    if (err) return res.status(500).send("DB error");
    res.json(rows);
  });
});

app.post("/api/lecturer/requests/:id/approve", (req, res) => {
  const id = req.params.id;
  const approverId = getUserIdFromSessionOr(req);
  if (!approverId) return res.status(401).json({ error: "Unauthorized" });

  const sql = `
    UPDATE bookings 
       SET status='approved', approver_id=? 
     WHERE booking_id=? AND status='pending'
  `;
  con.query(sql, [approverId, id], (err, r) => {
    if (err) return res.status(500).json({ error: "DB error" });
    if (r.affectedRows === 0)
      return res.status(404).json({ error: "Not found or already processed" });
    res.json({ message: "Approved" });
  });
});

app.post("/api/lecturer/requests/:id/reject", (req, res) => {
  const id = req.params.id;
  const { reason } = req.body;
  const approverId = getUserIdFromSessionOr(req);
  if (!approverId) return res.status(401).json({ error: "Unauthorized" });

  const sql = `
    UPDATE bookings
       SET status='rejected',
           approver_id=?,
           rejection_reason = ?
     WHERE booking_id=? AND status='pending'
  `;
  con.query(sql, [approverId, reason || null, id], (err, r) => {
    if (err) return res.status(500).json({ error: "DB error" });
    if (r.affectedRows === 0)
      return res.status(404).json({ error: "Not found or already processed" });
    res.json({ message: "Rejected" });
  });
});

// Lecturer history — เห็นเฉพาะของตัวเอง
app.get("/api/lecturer/history", (req, res) => {
  const uid = getUserIdFromSessionOr(req);
  if (!uid) return res.status(401).json({ error: "Unauthorized" });

  const sql = `
    SELECT 
      b.booking_id,
      b.booking_date,
      b.purpose,
      b.status,
      r.room_name,
      ts.start_time,
      ts.end_time,
      u.username  AS borrower,
      ua.username AS approved_by
    FROM bookings b
    JOIN users u   ON b.user_id    = u.user_id
    JOIN rooms r   ON b.room_id    = r.room_id
    JOIN time_slots ts ON b.slot_id = ts.slot_id
    LEFT JOIN users ua ON b.approver_id = ua.user_id
    WHERE b.status IN ('approved','rejected') 
      AND b.approver_id IS NOT NULL
      AND b.approver_id = ?
    ORDER BY b.booking_date DESC, ts.start_time DESC
  `;
  con.query(sql, [uid], (err, rows) => {
    if (err) return res.status(500).json({ error: "DB error" });
    res.json(rows);
  });
});

// Lecturer summary
app.get("/api/lecturer/summary", (_req, res) => {
  const today = new Date();
  const y = today.getFullYear();
  const m = String(today.getMonth() + 1).padStart(2, "0");
  const d = String(today.getDate()).padStart(2, "0");
  const theDate = `${y}-${m}-${d}`;

  const sql = `
    SELECT 
      CASE
        WHEN r.status = 'disabled' THEN 'disabled'
        ELSE COALESCE(b.status, 'free')
      END AS slot_status,
      COUNT(*) AS c
    FROM rooms r
    CROSS JOIN time_slots ts
    LEFT JOIN bookings b
      ON b.room_id = r.room_id
      AND b.slot_id = ts.slot_id
      AND b.booking_date = ?
    GROUP BY slot_status
  `;

  con.query(sql, [theDate], (err, rows) => {
    if (err) return res.status(500).json({ error: "DB error" });

    const sum = {
      free: 0,
      pending: 0,
      reserved: 0,
      approved: 0,
      disabled: 0,
    };

    rows.forEach((r) => {
      sum[r.slot_status] = r.c;
    });

    res.json({
      available: sum.free,
      pending: sum.pending,
      booked: (sum.approved || 0) + (sum.reserved || 0),
      disabled: sum.disabled,
    });
  });
});

// ===== Unified Room APIs (Staff/Shared) =====
app.get("/api/rooms", (req, res) => {
  const date = req.query.date;
  if (!date) {
    const sql =
      "SELECT room_id, room_name, status, image_url FROM rooms WHERE status='free'";
    return con.query(sql, (err, results) => {
      if (err) return res.status(500).json({ error: "DB error" });
      res.json(results);
    });
  }

  const roomsSql = `SELECT room_id, room_name, status, image_url FROM rooms ORDER BY room_id ASC`;
  con.query(roomsSql, (err, roomRows) => {
    if (err)
      return res
        .status(500)
        .json({ error: "DB error", detail: err.message });

    const tsSql = `
      SELECT r.room_id, ts.slot_id, ts.start_time, ts.end_time, b.status AS booking_status
      FROM rooms r
      CROSS JOIN time_slots ts
      LEFT JOIN bookings b
        ON b.room_id = r.room_id
       AND b.slot_id = ts.slot_id
       AND b.booking_date = ?
    `;
    con.query(tsSql, [date], (err2, tsRows) => {
      if (err2)
        return res
          .status(500)
          .json({ error: "DB error", detail: err2.message });

      const grouped = new Map();
      for (const r of roomRows) {
        grouped.set(r.room_id, { ...r, timeslots: [] });
      }
      const mapBookingToSlotStatusLocal = (s) => {
        if (!s) return "free";
        if (s === "pending") return "pending";
        if (s === "approved" || s === "reserved") return "reserved";
        if (s === "rejected" || s === "cancelled") return "free";
        return "free";
      };
      for (const row of tsRows) {
        const g = grouped.get(row.room_id);
        if (!g) continue;
        const fromBooking = mapBookingToSlotStatusLocal(row.booking_status);
        const finalStatus = g.status === "disabled" ? "disabled" : fromBooking;
        g.timeslots.push({
          slot_id: row.slot_id,
          start_time: row.start_time,
          end_time: row.end_time,
          status: finalStatus,
        });
      }
      res.json(Array.from(grouped.values()));
    });
  });
});

app.post("/api/rooms", (req, res) => {
  const { room_name, status, image_url } = req.body || {};
  if (!room_name) return res.status(400).send("room_name required");
  const st = status === "disabled" ? "disabled" : "free";
  const sql = `INSERT INTO rooms (room_name, status, image_url) VALUES (?, ?, ?)`;
  con.query(sql, [room_name, st, image_url || null], (err, result) => {
    if (err) {
      if (err.code === "ER_DUP_ENTRY")
        return res.status(409).send("Room name already exists");
      return res.status(500).send("DB error: " + err.message);
    }
    res.status(201).json({ message: "Room created", room_id: result.insertId });
  });
});

// ใช้ enable/edit room (ทั่วไป)
app.patch("/api/staff/rooms/:id", (req, res) => {
  const id = req.params.id;
  const { room_name, status, image_url } = req.body;
  if (!room_name && !status && typeof image_url === "undefined") {
    return res.status(400).json({ error: "Nothing to update" });
  }
  const sql = `
    UPDATE rooms
    SET room_name = COALESCE(?, room_name),
        status    = COALESCE(?, status),
        image_url = COALESCE(?, image_url)
    WHERE room_id=?
  `;
  con.query(
    sql,
    [room_name || null, status || null, image_url || null, id],
    (err, r) => {
      if (err) {
        if (err.code === "ER_DUP_ENTRY") {
          return res.status(409).json({ error: "Room name already exists" });
        }
        return res.status(500).json({ error: "DB error", detail: err.message });
      }
      if (r.affectedRows === 0)
        return res.status(404).json({ error: "Room not found" });
      res.json({ message: "Room updated" });
    }
  );
});

// Staff Dashboard Summary
app.get("/api/staff/summary", (_req, res) => {
  const today = new Date();
  const y = today.getFullYear();
  const m = String(today.getMonth() + 1).padStart(2, "0");
  const d = String(today.getDate()).padStart(2, "0");
  const theDate = `${y}-${m}-${d}`;

  const sql = `
    SELECT 
      CASE
        WHEN r.status = 'disabled' THEN 'disabled'
        ELSE COALESCE(b.status, 'free')
      END AS slot_status,
      COUNT(*) AS c
    FROM rooms r
    CROSS JOIN time_slots ts
    LEFT JOIN bookings b
      ON b.room_id = r.room_id
      AND b.slot_id = ts.slot_id
      AND b.booking_date = ?
    GROUP BY slot_status
  `;

  con.query(sql, [theDate], (err, rows) => {
    if (err) return res.status(500).json({ error: "DB error" });

    const sum = {
      free: 0,
      pending: 0,
      approved: 0,
      reserved: 0,
      disabled: 0,
    };

    rows.forEach((r) => {
      sum[r.slot_status] = r.c;
    });

    res.json({
      available: sum.free,
      pending: sum.pending,
      booked: (sum.approved || 0) + (sum.reserved || 0),
      disabled: sum.disabled,
    });
  });
});

// Staff history
app.get("/api/staff/history", (_req, res) => {
  const sql = `
    SELECT b.booking_id, b.booking_date, b.status, b.purpose, b.rejection_reason AS reason,
           r.room_name,
           ts.start_time, ts.end_time,
           u.username  AS borrower,
           ua.username AS approved_by
    FROM bookings b
    JOIN rooms r ON b.room_id=r.room_id
    JOIN time_slots ts ON b.slot_id=ts.slot_id
    JOIN users u ON b.user_id=u.user_id
    LEFT JOIN users ua ON b.approver_id=ua.user_id
    WHERE b.status IN ('approved','rejected','reserved','cancelled')
    ORDER BY b.booking_date DESC, ts.start_time DESC
  `;
  con.query(sql, (err, rows) => {
    if (err) return res.status(500).json({ error: "DB error" });
    res.json(rows);
  });
});

module.exports = app;
