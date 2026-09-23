// init-db.js (100問自動作成版)
const Database = require('better-sqlite3');
const db = new Database('exam.db');

// テーブルの初期化
db.exec(`
  DROP TABLE IF EXISTS questions;
  DROP TABLE IF EXISTS results;

  CREATE TABLE questions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    question_text TEXT,
    option1 TEXT, option2 TEXT, option3 TEXT, option4 TEXT,
    correct_option INTEGER,
    difficulty REAL
  );

  CREATE TABLE results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    score INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
`);

const insert = db.prepare(`
  INSERT INTO questions (question_text, option1, option2, option3, option4, correct_option, difficulty)
  VALUES (?, ?, ?, ?, ?, ?, ?)
`);

// 100問のサンプルデータを生成 (難易度 -2.5 から +2.5 まで段階的に設定)
const insertMany = db.transaction(() => {
  for (let i = 1; i <= 100; i++) {
    // -2.5 (簡単) ～ +2.45 (難しい) に難易度を分散
    const diff = Number((-2.5 + (i - 1) * 0.05).toFixed(2));
    const correct = (i % 4) + 1; // 正解を 1~4 に分散
    
    insert.run(
      `第 ${i} 問：IT・情報処理に関するサンプル問題です。(想定難易度: ${diff})`,
      `選択肢 1（ダミー解答）`,
      `選択肢 2（ダミー解答）`,
      `選択肢 3（ダミー解答）`,
      `選択肢 4（ダミー解答）`,
      correct,
      diff
    );
  }
});

insertMany();
console.log("100問のテストデータをデータベースに登録しました！");