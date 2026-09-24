require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const path = require('path');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.set('trust proxy', 1); // Render環境でのレート制限（express-rate-limit）用設定

// --- 構造化ロガー ---
const logger = {
  info: (msg, meta = {}) => console.log(JSON.stringify({ time: new Date().toISOString(), level: 'INFO', msg, ...meta })),
  warn: (msg, meta = {}) => console.warn(JSON.stringify({ time: new Date().toISOString(), level: 'WARN', msg, ...meta })),
  error: (msg, meta = {}) => console.error(JSON.stringify({ time: new Date().toISOString(), level: 'ERROR', msg, ...meta }))
};

// --- 環境変数・設定チェック ---
const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'development';

let JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  if (NODE_ENV === 'production') {
    logger.error("エラー: 本番環境(production)では JWT_SECRET の設定が必須です。");
    process.exit(1);
  } else {
    JWT_SECRET = 'it_exam_dev_jwt_secret_key_2026';
    logger.warn("注意: JWT_SECRET 未設定のため開発用デフォルト値を使用します。");
  }
}

// Supabase Connection String (DATABASE_URL)
const DATABASE_URL = process.env.DATABASE_URL;
if (!DATABASE_URL && NODE_ENV === 'production') {
  logger.error("エラー: 本番環境では DATABASE_URL の設定が必須です。");
  process.exit(1);
}

// PostgreSQL 接続プール設定
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// --- プロセス例外ハンドリング ---
process.on('uncaughtException', (err) => {
  logger.error('未捕捉の例外が発生したため終了します', { error: err.message, stack: err.stack });
  process.exit(1);
});

process.on('unhandledRejection', (reason) => {
  logger.error('未処理のPromise拒否が発生しました', { reason: String(reason) });
});

// --- ミドルウェア設定 ---
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '10kb' }));
app.use(express.static(path.join(__dirname, 'public')));

// --- レートリミット設定 ---
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  message: { error: "リクエスト数が多すぎます。しばらく時間を置いてから再試行してください。" }
});
app.use('/api/', globalLimiter);

const strictLimiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 10,
  message: { error: "短時間の操作回数が多すぎます。1分ほどおいて再試行してください。" }
});

// --- JWT認証ミドルウェア ---
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: "認証が必要です。ログインしてください。" });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: "トークンが無効または期限切れです。" });
    }
    req.user = user;
    next();
  });
}

// ==================== 認証 API ====================

// ユーザー新規登録
app.post('/api/register', strictLimiter, async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || typeof username !== 'string' || !/^[a-zA-Z0-9_-]{3,20}$/.test(username.trim())) {
      return res.status(400).json({ error: "ユーザー名は3〜20文字の半角英数字、ハイフン、アンダースコアで入力してください。" });
    }
    if (!password || typeof password !== 'string' || password.length < 6 || password.length > 50) {
      return res.status(400).json({ error: "パスワードは6文字以上50文字以下で入力してください。" });
    }

    const trimmedUsername = username.trim();
    const existingUser = await pool.query("SELECT id FROM users WHERE username = $1", [trimmedUsername]);
    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: "そのユーザー名は既に使用されています。" });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    await pool.query("INSERT INTO users (username, password_hash) VALUES ($1, $2)", [trimmedUsername, passwordHash]);

    const token = jwt.sign({ username: trimmedUsername }, JWT_SECRET, { expiresIn: '7d' });
    logger.info("ユーザーが新規登録されました", { username: trimmedUsername });

    res.json({ message: "登録成功", token, username: trimmedUsername });
  } catch (err) {
    logger.error("新規登録エラー", { error: err.message });
    res.status(500).json({ error: "ユーザー登録処理に失敗しました。" });
  }
});

// ログイン
app.post('/api/login', strictLimiter, async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: "ユーザー名とパスワードを入力してください。" });
    }

    const userRes = await pool.query("SELECT * FROM users WHERE username = $1", [String(username).trim()]);
    if (userRes.rows.length === 0) {
      return res.status(401).json({ error: "ユーザー名またはパスワードが正しくありません。" });
    }

    const user = userRes.rows[0];
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) {
      return res.status(401).json({ error: "ユーザー名またはパスワードが正しくありません。" });
    }

    const token = jwt.sign({ username: user.username }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ message: "ログイン成功", token, username: user.username });
  } catch (err) {
    logger.error("ログインエラー", { error: err.message });
    res.status(500).json({ error: "ログイン処理に失敗しました。" });
  }
});

// 認証チェック
app.get('/api/me', authenticateToken, (req, res) => {
  res.json({ username: req.user.username });
});

// ==================== 試験 API ====================

// カテゴリ一覧取得
app.get('/api/categories', async (req, res) => {
  try {
    const result = await pool.query("SELECT DISTINCT category FROM questions WHERE category IS NOT NULL AND category != ''");
    res.json(result.rows.map(c => c.category));
  } catch (err) {
    logger.error("カテゴリ取得エラー", { error: err.message });
    res.status(500).json({ error: "カテゴリの取得に失敗しました。" });
  }
});

// 問題取得（出題時は正解・解説を含めない）
app.get('/api/questions', async (req, res) => {
  try {
    const { category, limit } = req.query;
    let count = parseInt(limit, 10) || 10;
    if (isNaN(count) || count < 1) count = 10;
    if (count > 100) count = 100;

    let questions = [];

    if ((!category || category === 'all') && count === 100) {
      const targets = [
        { key: 'ストラテジ', limit: 30 },
        { key: 'マネジメント', limit: 20 },
        { key: 'テクノロジ', limit: 50 }
      ];

      for (const target of targets) {
        const qList = await pool.query(`
          SELECT id, category, question_text, option1, option2, option3, option4, image_url 
          FROM questions WHERE category LIKE $1 ORDER BY RANDOM() LIMIT $2
        `, [`%${target.key}%`, target.limit]);
        questions.push(...qList.rows);
      }

      const currentFetchedIds = questions.map(q => q.id);
      if (currentFetchedIds.length < 100) {
        let fallbackSql = `SELECT id, category, question_text, option1, option2, option3, option4, image_url FROM questions`;
        const params = [];

        if (currentFetchedIds.length > 0) {
          fallbackSql += ` WHERE id NOT IN (${currentFetchedIds.map((_, i) => `$${i + 1}`).join(',')})`;
          params.push(...currentFetchedIds);
        }
        fallbackSql += ` ORDER BY RANDOM() LIMIT $${params.length + 1}`;
        params.push(100 - currentFetchedIds.length);

        const extraQuestions = await pool.query(fallbackSql, params);
        questions.push(...extraQuestions.rows);
      }

      questions.sort(() => Math.random() - 0.5);

    } else if (!category || category === 'all') {
      const result = await pool.query(`
        SELECT id, category, question_text, option1, option2, option3, option4, image_url 
        FROM questions ORDER BY RANDOM() LIMIT $1
      `, [count]);
      questions = result.rows;
    } else {
      const result = await pool.query(`
        SELECT id, category, question_text, option1, option2, option3, option4, image_url 
        FROM questions WHERE category = $1 ORDER BY RANDOM() LIMIT $2
      `, [String(category).substring(0, 50), count]);
      questions = result.rows;
    }

    res.json(questions);
  } catch (err) {
    logger.error("問題取得エラー", { error: err.message });
    res.status(500).json({ error: "問題データの取得に失敗しました。" });
  }
});

// 解答送信 & 採点（採点結果と同時に正解・問題詳細・解説データも返却）
app.post('/api/submit', strictLimiter, authenticateToken, async (req, res) => {
  const client = await pool.connect();
  try {
    const { questionIds, answers, category } = req.body;
    const authUserId = req.user.username;

    if (!Array.isArray(questionIds) || questionIds.length === 0 || questionIds.length > 100) {
      return res.status(400).json({ error: "問題ID配列が無効、または規定数(100問)を超えています。" });
    }

    const validQuestionIds = questionIds.map(id => Number(id)).filter(id => !isNaN(id) && id > 0);
    if (validQuestionIds.length !== questionIds.length) {
      return res.status(400).json({ error: "不正な問題IDが含まれています。" });
    }

    const userAnswers = (typeof answers === 'object' && answers !== null) ? answers : {};

    const placeholders = validQuestionIds.map((_, i) => `$${i + 1}`).join(',');
    // 復習用に正解・問題文・各選択肢・解説（存在する場合）を取得
    const allQuestionsRes = await client.query(`
      SELECT id, question_text, option1, option2, option3, option4, correct_option, difficulty, answer_count, correct_count, image_url, explanation
      FROM questions WHERE id IN (${placeholders})
    `, validQuestionIds);
    const allQuestions = allQuestionsRes.rows;

    // トランザクション開始
    await client.query('BEGIN');

    const responses = [];
    const questionParams = [];
    let correctCount = 0;
    const details = [];

    for (const q of allQuestions) {
      const userAnswer = userAnswers[q.id];
      const isCorrect = (userAnswer !== undefined && Number(userAnswer) === Number(q.correct_option)) ? 1 : 0;
      if (isCorrect) correctCount++;

      responses.push(isCorrect);
      questionParams.push({ difficulty: q.difficulty || 0.0, discrimination: 1.0 });

      const currentAnswerCount = (q.answer_count || 0) + 1;
      const currentCorrectCount = (q.correct_count || 0) + isCorrect;

      if (currentAnswerCount > 50) {
        const p = (currentCorrectCount + 1) / (currentAnswerCount + 2);
        let newDifficulty = -Math.log(p / (1 - p)) / 1.7;
        newDifficulty = Math.max(-3.0, Math.min(3.0, newDifficulty));

        await client.query(
          `UPDATE questions SET answer_count = $1, correct_count = $2, difficulty = $3 WHERE id = $4`,
          [currentAnswerCount, currentCorrectCount, newDifficulty, q.id]
        );
      } else {
        await client.query(
          `UPDATE questions SET answer_count = $1, correct_count = $2 WHERE id = $3`,
          [currentAnswerCount, currentCorrectCount, q.id]
        );
      }

      // クライアントの画面表示用の詳細データ作成
      details.push({
        id: q.id,
        questionText: q.question_text,
        option1: q.option1,
        option2: q.option2,
        option3: q.option3,
        option4: q.option4,
        imageUrl: q.image_url || null,
        explanation: q.explanation || '',
        userAnswer: userAnswer !== undefined ? Number(userAnswer) : null,
        correctOption: Number(q.correct_option),
        isCorrect: isCorrect === 1
      });
    }

    const totalCount = allQuestions.length;
    const maxScore = 1000;
    let finalScore = 0;

    if (correctCount > 0) {
      const irtResult = calculateIRTScore(responses, questionParams);
      finalScore = irtResult.score;
    }

    const categoryName = (!category || category === 'all') ? '全分野' : String(category).substring(0, 50);

    await client.query(
      `INSERT INTO results (user_id, score, max_score, category, correct_count, total_count) VALUES ($1, $2, $3, $4, $5, $6)`,
      [authUserId, finalScore, maxScore, categoryName, correctCount, totalCount]
    );

    await client.query('COMMIT');

    logger.info("試験提出完了", { user: authUserId, score: finalScore });

    // details (問題回答・解説詳細リスト) をレスポンスに含める
    res.json({ 
      score: finalScore, 
      maxScore, 
      correctCount, 
      totalCount, 
      details 
    });

  } catch (err) {
    await client.query('ROLLBACK');
    logger.error("採点処理エラー", { error: err.message });
    res.status(500).json({ error: "採点処理中にエラーが発生しました。" });
  } finally {
    client.release();
  }
});

// 成績履歴取得
app.get('/api/history', authenticateToken, async (req, res) => {
  try {
    const authUserId = req.user.username;

    const history = await pool.query(`
      SELECT 
        id, user_id, score, max_score, category, correct_count, total_count, 
        to_char(created_at, 'YYYY/MM/DD HH24:MI') as date
      FROM results WHERE user_id = $1 ORDER BY id ASC
    `, [authUserId]);

    res.json(history.rows);
  } catch (err) {
    logger.error("履歴取得エラー", { error: err.message });
    res.status(500).json({ error: "成績履歴の取得に失敗しました。" });
  }
});

// IRT採点ロジック (EAP法)
function calculateIRTScore(responses, questions) {
  const numNodes = 81;
  const nodes = [];
  const posteriors = [];

  for (let i = 0; i < numNodes; i++) {
    const theta = -4.0 + i * 0.1;
    nodes.push(theta);
    posteriors.push(Math.exp(-0.5 * theta * theta));
  }

  let sumPosterior = posteriors.reduce((a, b) => a + b, 0);
  for (let i = 0; i < numNodes; i++) posteriors[i] /= sumPosterior;

  for (let i = 0; i < responses.length; i++) {
    const x = responses[i];
    const b = questions[i].difficulty;
    const a = questions[i].discrimination || 1.0;

    for (let j = 0; j < numNodes; j++) {
      const theta = nodes[j];
      const p = 1 / (1 + Math.exp(-1.7 * a * (theta - b)));
      const likelihood = (x === 1) ? p : (1 - p);
      posteriors[j] *= likelihood;
    }
  }

  sumPosterior = posteriors.reduce((a, b) => a + b, 0);
  if (sumPosterior === 0) return { theta: 0, score: 200 };

  let thetaEAP = 0;
  for (let j = 0; j < numNodes; j++) {
    posteriors[j] /= sumPosterior;
    thetaEAP += nodes[j] * posteriors[j];
  }

  let rawScore = Math.round(600 + thetaEAP * 150);
  let scaledScore = Math.max(100, Math.min(1000, rawScore));

  return { theta: Number(thetaEAP.toFixed(3)), score: scaledScore };
}

// 共通エラーハンドリング
app.use((err, req, res, next) => {
  logger.error('Unhandled API Error', { error: err.message, stack: err.stack });
  res.status(500).json({ error: "内部サーバーエラーが発生しました。" });
});

// --- サーバー起動 ---
const server = app.listen(PORT, () => {
  logger.info(`サーバーが正常起動しました`, { port: PORT, env: NODE_ENV });
});

// --- グレースフルシャットダウン ---
function shutdown(signal) {
  logger.info(`${signal} シグナルを受信しました。サーバーを正常停止します...`);
  server.close(async () => {
    logger.info('HTTP サーバーを停止しました。');
    try {
      await pool.end();
      logger.info('PostgreSQL 接続プールをクローズしました。');
    } catch (e) {
      logger.error('DBクローズ時にエラーが発生しました', { error: e.message });
    }
    process.exit(0);
  });
}

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));