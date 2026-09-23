// import-csv.js (ヘッダー読み込み不具合修正版)
const fs = require('fs');
const csv = require('csv-parser');
const Database = require('better-sqlite3');
const db = new Database('exam.db');

// テーブルの再作成
db.exec(`
  DROP TABLE IF EXISTS questions;
  CREATE TABLE questions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    category TEXT,
    question_text TEXT,
    option1 TEXT, option2 TEXT, option3 TEXT, option4 TEXT,
    correct_option INTEGER,
    difficulty REAL
  );
`);

const insert = db.prepare(`
  INSERT INTO questions (category, question_text, option1, option2, option3, option4, correct_option, difficulty)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?)
`);

const results = [];

// questions.csv を読み込む (オプション指定を正しい書き方に修正)
fs.createReadStream('questions.csv')
  .pipe(csv({
    headers: ['category', 'question_text', 'option1', 'option2', 'option3', 'option4', 'correct_option', 'difficulty'],
    skipLines: 0
  }))
  .on('data', (data) => results.push(data))
  .on('end', () => {
    const insertMany = db.transaction((rows) => {
      for (const row of rows) {
        insert.run(
          row.category,
          row.question_text,
          row.option1,
          row.option2,
          row.option3,
          row.option4,
          parseInt(row.correct_option, 10),
          parseFloat(row.difficulty)
        );
      }
    });

    insertMany(results);
    console.log(`CSVから ${results.length} 件の問題を分野付きでデータベースに取り込みました！`);
  });