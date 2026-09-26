require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const path = require('path');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.set('trust proxy', 1);

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

const DATABASE_URL = process.env.DATABASE_URL;
if (!DATABASE_URL && NODE_ENV === 'production') {
  logger.error("エラー: 本番環境では DATABASE_URL の設定が必須です。");
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// --- DB スキーマの自動チェック・初期化 ---
async function initDb() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS user_answers (
        user_id VARCHAR(50) NOT NULL,
        question_id INT NOT NULL,
        is_correct INT DEFAULT 0,
        answered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (user_id, question_id)
      );

      ALTER TABLE user_answers ADD COLUMN IF NOT EXISTS is_correct INT DEFAULT 0;
      ALTER TABLE user_answers ADD COLUMN IF NOT EXISTS answered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;
    `);
    logger.info("DBスキーマ初期化完了");
  } catch (err) {
    logger.error("DB初期化失敗のため停止します", { error: err.message });
    process.exit(1);
  }
}

// --- プロセス例外ハンドリング ---
process.on('uncaughtException', (err) => {
  logger.error('未捕捉の例外が発生したため終了します', { error: err.message, stack: err.stack });
  process.exit(1);
});

process.on('unhandledRejection', (reason) => {
  logger.error('未処理のPromise拒否が発生しました', { reason: String(reason) });
});

// --- CORS設定 ---
const allowedOrigins = [
  process.env.FRONTEND_URL,
  'http://localhost:3000'
].filter(Boolean);

app.use(cors({
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('CORSポリシーにより制限されています。許可されていないオリジンからのアクセスです。'));
    }
  },
  credentials: true
}));

// --- セキュリティ・基本ミドルウェア設定 ---
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

function getOptionalUsername(req) {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return null;
    const decoded = jwt.verify(token, JWT_SECRET);
    return decoded ? decoded.username : null;
  } catch (e) {
    return null;
  }
}

// ==================== 認証 API ====================

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

app.get('/api/me', authenticateToken, (req, res) => {
  res.json({ username: req.user.username });
});

// ==================== 従来試験 API ====================

let categoryCache = null;
let categoryCacheTime = 0;

app.get('/api/categories', async (req, res) => {
  try {
    const now = Date.now();
    if (categoryCache && (now - categoryCacheTime < 5 * 60 * 1000)) {
      return res.json(categoryCache);
    }

    const result = await pool.query("SELECT DISTINCT category FROM questions WHERE category IS NOT NULL AND category != ''");
    categoryCache = result.rows.map(c => c.category);
    categoryCacheTime = now;

    res.json(categoryCache);
  } catch (err) {
    logger.error("カテゴリ取得エラー", { error: err.message });
    res.status(500).json({ error: "カテゴリの取得に失敗しました。" });
  }
});

app.get('/api/questions', async (req, res) => {
  try {
    const { category, limit, mode } = req.query;
    let count = parseInt(limit, 10) || 10;
    if (isNaN(count) || count < 1) count = 10;
    if (count > 100) count = 100;

    const username = getOptionalUsername(req) || 'GUEST';

    let orderClause = "";
    if (mode === 'weakness') {
      orderClause = `
        ORDER BY 
          CASE WHEN ua.is_correct = 0 THEN 0 ELSE 1 END,
          ua.answered_at ASC NULLS FIRST,
          RANDOM()
      `;
    } else {
      orderClause = `
        ORDER BY 
          CASE WHEN ua.question_id IS NULL THEN 0 ELSE 1 END,
          ua.answered_at ASC NULLS FIRST,
          RANDOM()
      `;
    }

    let questions = [];

    if ((!category || category === 'all') && count === 100) {
      const targets = [
        { key: 'ストラテジ', limit: 30 },
        { key: 'マネジメント', limit: 20 },
        { key: 'テクノロジ', limit: 50 }
      ];

      for (const target of targets) {
        const sql = `
          SELECT q.id, q.category, q.question_text, q.option1, q.option2, q.option3, q.option4, q.image_url 
          FROM questions q
          LEFT JOIN user_answers ua ON q.id = ua.question_id AND ua.user_id = $1
          WHERE q.category LIKE $2
          ${orderClause}
          LIMIT $3
        `;
        const qList = await pool.query(sql, [username, `%${target.key}%`, target.limit]);
        questions.push(...qList.rows);
      }

      const currentFetchedIds = questions.map(q => q.id);
      if (currentFetchedIds.length < 100) {
        let fallbackSql = `
          SELECT q.id, q.category, q.question_text, q.option1, q.option2, q.option3, q.option4, q.image_url 
          FROM questions q
          LEFT JOIN user_answers ua ON q.id = ua.question_id AND ua.user_id = $1
        `;
        const params = [username];

        if (currentFetchedIds.length > 0) {
          fallbackSql += ` WHERE q.id NOT IN (${currentFetchedIds.map((_, i) => `$${i + 2}`).join(',')})`;
          params.push(...currentFetchedIds);
        }
        fallbackSql += ` ${orderClause} LIMIT $${params.length + 1}`;
        params.push(100 - currentFetchedIds.length);

        const extraQuestions = await pool.query(fallbackSql, params);
        questions.push(...extraQuestions.rows);
      }

      questions.sort(() => Math.random() - 0.5);

    } else if (!category || category === 'all') {
      const sql = `
        SELECT q.id, q.category, q.question_text, q.option1, q.option2, q.option3, q.option4, q.image_url 
        FROM questions q
        LEFT JOIN user_answers ua ON q.id = ua.question_id AND ua.user_id = $1
        ${orderClause}
        LIMIT $2
      `;
      const result = await pool.query(sql, [username, count]);
      questions = result.rows;
    } else {
      const sql = `
        SELECT q.id, q.category, q.question_text, q.option1, q.option2, q.option3, q.option4, q.image_url 
        FROM questions q
        LEFT JOIN user_answers ua ON q.id = ua.question_id AND ua.user_id = $1
        WHERE q.category = $2
        ${orderClause}
        LIMIT $3
      `;
      const result = await pool.query(sql, [username, String(category).substring(0, 50), count]);
      questions = result.rows;
    }

    res.json(questions);
  } catch (err) {
    logger.error("問題取得エラー", { error: err.message });
    res.status(500).json({ error: "問題データの取得に失敗しました。" });
  }
});

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

    const userAnswersMap = (typeof answers === 'object' && answers !== null) ? answers : {};

    const placeholders = validQuestionIds.map((_, i) => `$${i + 1}`).join(',');
    const allQuestionsRes = await client.query(`
      SELECT id, question_text, option1, option2, option3, option4, correct_option, difficulty, answer_count, correct_count, image_url, explanation
      FROM questions WHERE id IN (${placeholders})
    `, validQuestionIds);
    const allQuestions = allQuestionsRes.rows;

    await client.query('BEGIN');

    const userAnswersPlaceholders = validQuestionIds.map((_, i) => `$${i + 2}`).join(',');
    const answeredRes = await client.query(`
      SELECT question_id FROM user_answers 
      WHERE user_id = $1 AND question_id IN (${userAnswersPlaceholders})
    `, [authUserId, ...validQuestionIds]);
    const answeredSet = new Set(answeredRes.rows.map(r => r.question_id));

    const responses = [];
    const questionParams = [];
    let correctCount = 0;
    const details = [];

    const updateQuestions = [];
    const upsertUserAnswers = [];

    for (const q of allQuestions) {
      const userAnswer = userAnswersMap[q.id];
      const isCorrect = (userAnswer !== undefined && Number(userAnswer) === Number(q.correct_option)) ? 1 : 0;
      if (isCorrect) correctCount++;

      responses.push(isCorrect);
      questionParams.push({ difficulty: q.difficulty || 0.0, discrimination: 1.0 });

      const isFirstTime = !answeredSet.has(q.id);

      // 全解答のカウントと難易度更新
      const currentAnswerCount = (q.answer_count || 0) + 1;
      const currentCorrectCount = (q.correct_count || 0) + isCorrect;
      let newDifficulty = q.difficulty || 0.0;

      if (currentAnswerCount > 5) {
        const p = (currentCorrectCount + 1) / (currentAnswerCount + 2);
        const pAdjusted = Math.max(0.01, (p - 0.25) / (1 - 0.25));
        const calculatedDifficulty = -Math.log(pAdjusted / (1 - pAdjusted)) / 1.7;

        // 初回は alpha = 0.1、復習は alpha = 0.02
        const alpha = isFirstTime ? 0.1 : 0.02;
        const oldDifficulty = q.difficulty || 0.0;
        newDifficulty = (1 - alpha) * oldDifficulty + alpha * calculatedDifficulty;
        newDifficulty = Math.max(-3.0, Math.min(3.0, newDifficulty));
      }

      updateQuestions.push({
        id: q.id,
        answer_count: currentAnswerCount,
        correct_count: currentCorrectCount,
        difficulty: newDifficulty
      });

      upsertUserAnswers.push({
        question_id: q.id,
        is_correct: isCorrect
      });

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

    if (updateQuestions.length > 0) {
      const qIds = updateQuestions.map(u => u.id);
      const qAC = updateQuestions.map(u => u.answer_count);
      const qCC = updateQuestions.map(u => u.correct_count);
      const qDiff = updateQuestions.map(u => u.difficulty);

      await client.query(`
        UPDATE questions AS q
        SET 
          answer_count = u.ac,
          correct_count = u.cc,
          difficulty = u.diff
        FROM unnest($1::int[], $2::int[], $3::int[], $4::float[]) AS u(id, ac, cc, diff)
        WHERE q.id = u.id
      `, [qIds, qAC, qCC, qDiff]);
    }

    if (upsertUserAnswers.length > 0) {
      const uUsers = upsertUserAnswers.map(() => authUserId);
      const uQIds = upsertUserAnswers.map(u => u.question_id);
      const uCorrects = upsertUserAnswers.map(u => u.is_correct);

      await client.query(`
        INSERT INTO user_answers (user_id, question_id, is_correct, answered_at)
        SELECT u, q, c, CURRENT_TIMESTAMP FROM unnest($1::varchar[], $2::int[], $3::int[]) AS t(u, q, c)
        ON CONFLICT (user_id, question_id) 
        DO UPDATE SET is_correct = EXCLUDED.is_correct, answered_at = CURRENT_TIMESTAMP
      `, [uUsers, uQIds, uCorrects]);
    }

    const totalCount = allQuestions.length;
    const maxScore = 1000;

    const irtResult = calculateIRTScore(responses, questionParams);
    const finalScore = (correctCount === 0) ? 0 : irtResult.score;

    const categoryName = (!category || category === 'all') ? '全分野' : String(category).substring(0, 50);

    await client.query(
      `INSERT INTO results (user_id, score, max_score, category, correct_count, total_count) VALUES ($1, $2, $3, $4, $5, $6)`,
      [authUserId, finalScore, maxScore, categoryName, correctCount, totalCount]
    );

    await client.query('COMMIT');

    logger.info("試験提出完了", { user: authUserId, score: finalScore });

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

// ==================== ★ CAT（適応型テスト）専用 API ====================

app.post('/api/cat/start', strictLimiter, async (req, res) => {
  try {
    const { category } = req.body;
    let targetCatPattern = '%';

    if (category && category !== 'all') {
      targetCatPattern = `%${category}%`;
    } else {
      targetCatPattern = '%ストラテジ%';
    }

    const sql = `
      SELECT id, category, question_text, option1, option2, option3, option4, image_url, difficulty
      FROM questions
      WHERE category LIKE $1
      ORDER BY ABS(COALESCE(difficulty, 0.0) - 0.0) ASC, RANDOM()
      LIMIT 1
    `;
    const result = await pool.query(sql, [targetCatPattern]);

    if (result.rows.length === 0) {
      return res.status(444).json({ error: "出題可能な問題が見つかりませんでした。" });
    }

    res.json({
      step: 1,
      totalSteps: 20,
      question: result.rows[0],
      history: []
    });
  } catch (err) {
    logger.error("CAT開始エラー", { error: err.message });
    res.status(500).json({ error: "CATテストの開始に失敗しました。" });
  }
});

app.post('/api/cat/answer', authenticateToken, async (req, res) => {
  const client = await pool.connect();
  try {
    const { questionId, userAnswer, history, category } = req.body;
    const authUserId = req.user.username;

    if (!questionId || userAnswer === undefined || !Array.isArray(history)) {
      return res.status(400).json({ error: "リクエストパラメータが不正です。" });
    }

    const qRes = await client.query(`
      SELECT id, question_text, option1, option2, option3, option4, correct_option, difficulty, answer_count, correct_count, explanation
      FROM questions WHERE id = $1
    `, [Number(questionId)]);

    if (qRes.rows.length === 0) {
      return res.status(404).json({ error: "問題が見つかりません。" });
    }

    const currentQ = qRes.rows[0];
    const isCorrect = (Number(userAnswer) === Number(currentQ.correct_option)) ? 1 : 0;

    await client.query('BEGIN');

    const answeredCheck = await client.query(`
      SELECT question_id FROM user_answers WHERE user_id = $1 AND question_id = $2
    `, [authUserId, currentQ.id]);

    const isFirstTime = (answeredCheck.rows.length === 0);

    // 全解答でのカウントアップ
    const currentAnswerCount = (currentQ.answer_count || 0) + 1;
    const currentCorrectCount = (currentQ.correct_count || 0) + isCorrect;
    let newDifficulty = currentQ.difficulty || 0.0;

    if (currentAnswerCount > 5) {
      const p = (currentCorrectCount + 1) / (currentAnswerCount + 2);
      const pAdjusted = Math.max(0.01, (p - 0.25) / (1 - 0.25));
      const calculatedDifficulty = -Math.log(pAdjusted / (1 - pAdjusted)) / 1.7;

      // 初回なら alpha = 0.1、復習なら alpha = 0.02
      const alpha = isFirstTime ? 0.1 : 0.02;
      const oldDifficulty = currentQ.difficulty || 0.0;
      newDifficulty = (1 - alpha) * oldDifficulty + alpha * calculatedDifficulty;
      newDifficulty = Math.max(-3.0, Math.min(3.0, newDifficulty));
    }

    await client.query(`
      UPDATE questions SET answer_count = $1, correct_count = $2, difficulty = $3 WHERE id = $4
    `, [currentAnswerCount, currentCorrectCount, newDifficulty, currentQ.id]);

    await client.query(`
      INSERT INTO user_answers (user_id, question_id, is_correct, answered_at)
      VALUES ($1, $2, $3, CURRENT_TIMESTAMP)
      ON CONFLICT (user_id, question_id) 
      DO UPDATE SET is_correct = EXCLUDED.is_correct, answered_at = CURRENT_TIMESTAMP
    `, [authUserId, currentQ.id, isCorrect]);

    await client.query('COMMIT');

    const updatedHistory = [
      ...history,
      {
        questionId: currentQ.id,
        isCorrect: isCorrect,
        difficulty: currentQ.difficulty || 0.0,
        discrimination: 1.0,
        userAnswer: Number(userAnswer),
        correctOption: Number(currentQ.correct_option),
        explanation: currentQ.explanation || ''
      }
    ];

    const responses = updatedHistory.map(h => h.isCorrect);
    const questionParams = updatedHistory.map(h => ({ difficulty: h.difficulty, discrimination: 1.0 }));
    const irtResult = calculateIRTScore(responses, questionParams);
    const currentTheta = irtResult.theta;

    const totalSteps = 20;

    if (updatedHistory.length >= totalSteps) {
      const correctCount = updatedHistory.filter(h => h.isCorrect === 1).length;
      const finalScore = (correctCount === 0) ? 0 : irtResult.score;
      const categoryName = (!category || category === 'all') ? 'CATスピードテスト' : `CAT:${String(category).substring(0, 45)}`;

      await pool.query(
        `INSERT INTO results (user_id, score, max_score, category, correct_count, total_count) VALUES ($1, $2, $3, $4, $5, $6)`,
        [authUserId, finalScore, 1000, categoryName, correctCount, totalSteps]
      );

      return res.json({
        isFinished: true,
        score: finalScore,
        maxScore: 1000,
        correctCount: correctCount,
        totalCount: totalSteps,
        currentTheta: currentTheta,
        lastAnswerCorrect: isCorrect === 1,
        explanation: currentQ.explanation || '',
        correctOption: Number(currentQ.correct_option),
        history: updatedHistory
      });
    }

    let targetCatPattern = '%';
    if (category && category !== 'all') {
      targetCatPattern = `%${category}%`;
    } else {
      const nextStepIndex = updatedHistory.length;
      if (nextStepIndex < 6) {
        targetCatPattern = '%ストラテジ%';
      } else if (nextStepIndex < 10) {
        targetCatPattern = '%マネジメント%';
      } else {
        targetCatPattern = '%テクノロジ%';
      }
    }

    const excludeIds = updatedHistory.map(h => h.questionId);

    const excludePlaceholders = excludeIds.map((_, i) => `$${i + 2}`).join(',');
    const thetaParamIndex = `$${excludeIds.length + 2}`;

    const nextQRes = await pool.query(`
      SELECT id, category, question_text, option1, option2, option3, option4, image_url, difficulty
      FROM questions
      WHERE id NOT IN (${excludePlaceholders})
        AND category LIKE $1
      ORDER BY ABS(COALESCE(difficulty, 0.0) - ${thetaParamIndex}) ASC, RANDOM()
      LIMIT 1
    `, [targetCatPattern, ...excludeIds, currentTheta]);

    let nextQuestion = nextQRes.rows[0];

    if (!nextQuestion) {
      const fallbackExcludePlaceholders = excludeIds.map((_, i) => `$${i + 1}`).join(',');
      const fallbackThetaParamIndex = `$${excludeIds.length + 1}`;

      const fallbackRes = await pool.query(`
        SELECT id, category, question_text, option1, option2, option3, option4, image_url, difficulty
        FROM questions
        WHERE id NOT IN (${fallbackExcludePlaceholders})
        ORDER BY ABS(COALESCE(difficulty, 0.0) - ${fallbackThetaParamIndex}) ASC, RANDOM()
        LIMIT 1
      `, [...excludeIds, currentTheta]);
      nextQuestion = fallbackRes.rows[0];
    }

    res.json({
      isFinished: false,
      step: updatedHistory.length + 1,
      totalSteps: totalSteps,
      currentTheta: currentTheta,
      lastAnswerCorrect: isCorrect === 1,
      explanation: currentQ.explanation || '',
      correctOption: Number(currentQ.correct_option),
      question: nextQuestion,
      history: updatedHistory
    });

  } catch (err) {
    await client.query('ROLLBACK');
    logger.error("CAT解答処理エラー", { error: err.message });
    res.status(500).json({ error: "CAT解答処理に失敗しました。" });
  } finally {
    client.release();
  }
});

// ==================== 分析・履歴 API ====================

app.get('/api/analytics', authenticateToken, async (req, res) => {
  try {
    const authUserId = req.user.username;

    const categoryStats = await pool.query(`
      SELECT 
        COALESCE(q.category, '全般') as category,
        COUNT(ua.question_id)::int as total_answered,
        SUM(CASE WHEN ua.is_correct = 1 THEN 1 ELSE 0 END)::int as correct_count,
        ROUND(
          (SUM(CASE WHEN ua.is_correct = 1 THEN 1 ELSE 0 END)::numeric / NULLIF(COUNT(ua.question_id), 0)) * 100, 1
        )::float as accuracy
      FROM user_answers ua
      JOIN questions q ON ua.question_id = q.id
      WHERE ua.user_id = $1
      GROUP BY q.category
      ORDER BY accuracy ASC
    `, [authUserId]);

    const overallStats = await pool.query(`
      SELECT 
        COUNT(ua.question_id)::int as total_answered,
        SUM(CASE WHEN ua.is_correct = 1 THEN 1 ELSE 0 END)::int as total_correct
      FROM user_answers ua
      WHERE ua.user_id = $1
    `, [authUserId]);

    const totalAns = overallStats.rows[0]?.total_answered || 0;
    const totalCorr = overallStats.rows[0]?.total_correct || 0;
    const overallAccuracy = totalAns > 0 ? Number(((totalCorr / totalAns) * 100).toFixed(1)) : 0;

    const qualifiedWeak = categoryStats.rows.find(c => c.total_answered >= 5);
    const weakest = qualifiedWeak || (categoryStats.rows.length > 0 ? categoryStats.rows[0] : null);

    res.json({
      overall: {
        totalAnswered: totalAns,
        totalCorrect: totalCorr,
        accuracy: overallAccuracy
      },
      categories: categoryStats.rows,
      weakestCategory: weakest ? weakest.category : null,
      weakestAccuracy: weakest ? weakest.accuracy : 0
    });
  } catch (err) {
    logger.error("弱点分析取得エラー", { error: err.message });
    res.status(500).json({ error: "弱点分析データの取得に失敗しました。" });
  }
});

app.get('/api/history', authenticateToken, async (req, res) => {
  try {
    const authUserId = req.user.username;

    const history = await pool.query(`
      SELECT 
        id, user_id, score, max_score, category, correct_count, total_count, 
        to_char(created_at, 'YYYY/MM/DD HH24:MI') as date
      FROM results WHERE user_id = $1 ORDER BY id DESC
    `, [authUserId]);

    res.json(history.rows);
  } catch (err) {
    logger.error("履歴取得エラー", { error: err.message });
    res.status(500).json({ error: "成績履歴の取得に失敗しました。" });
  }
});

// IRT採点ロジック
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

  const c = 0.25;
  for (let i = 0; i < responses.length; i++) {
    const x = responses[i];
    const b = questions[i].difficulty;
    const a = questions[i].discrimination || 1.0;

    for (let j = 0; j < numNodes; j++) {
      const theta = nodes[j];
      const p = c + (1 - c) / (1 + Math.exp(-1.7 * a * (theta - b)));
      const likelihood = (x === 1) ? p : (1 - p);
      posteriors[j] *= likelihood;
    }
  }

  sumPosterior = posteriors.reduce((a, b) => a + b, 0);
  if (sumPosterior === 0) return { theta: -3.0, score: 100 };

  let thetaEAP = 0;
  for (let j = 0; j < numNodes; j++) {
    posteriors[j] /= sumPosterior;
    thetaEAP += nodes[j] * posteriors[j];
  }

  let rawScore = Math.round(600 + thetaEAP * 150);
  let scaledScore = Math.max(100, Math.min(1000, rawScore));

  return { theta: Number(thetaEAP.toFixed(3)), score: scaledScore };
}

app.use((err, req, res, next) => {
  logger.error('Unhandled API Error', { error: err.message, stack: err.stack });
  res.status(500).json({ error: "内部サーバーエラーが発生しました。" });
});

async function startServer() {
  await initDb();

  const server = app.listen(PORT, () => {
    logger.info(`サーバーが正常起動しました`, { port: PORT, env: NODE_ENV });
  });

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
}

startServer();