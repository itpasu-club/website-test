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

// ============================================================
// ロガー
// ============================================================

const logger = {
  info: (msg, meta = {}) => {
    console.log(JSON.stringify({
      time: new Date().toISOString(),
      level: 'INFO',
      msg,
      ...meta
    }));
  },

  warn: (msg, meta = {}) => {
    console.warn(JSON.stringify({
      time: new Date().toISOString(),
      level: 'WARN',
      msg,
      ...meta
    }));
  },

  error: (msg, meta = {}) => {
    console.error(JSON.stringify({
      time: new Date().toISOString(),
      level: 'ERROR',
      msg,
      ...meta
    }));
  }
};

// ============================================================
// 環境変数
// ============================================================

const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'development';

let JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
  if (NODE_ENV === 'production') {
    logger.error(
      "エラー: 本番環境(production)では JWT_SECRET の設定が必須です。"
    );
    process.exit(1);
  } else {
    JWT_SECRET = 'it_exam_dev_jwt_secret_key_2026';

    logger.warn(
      "注意: JWT_SECRET 未設定のため開発用デフォルト値を使用します。"
    );
  }
}

const DATABASE_URL = process.env.DATABASE_URL;

if (!DATABASE_URL && NODE_ENV === 'production') {
  logger.error(
    "エラー: 本番環境では DATABASE_URL の設定が必須です。"
  );
  process.exit(1);
}

// ============================================================
// PostgreSQL接続プール
// ============================================================

const pool = new Pool({
  connectionString: DATABASE_URL,

  ssl: NODE_ENV === 'production'
    ? { rejectUnauthorized: false }
    : false,

  // 接続数を増やしすぎない
  max: 10,

  // 長時間アイドル状態の接続を解放
  idleTimeoutMillis: 30000,

  // 接続待機が長すぎる場合に失敗させる
  connectionTimeoutMillis: 5000
});

pool.on('error', (err) => {
  logger.error('PostgreSQLアイドル接続エラー', {
    error: err.message
  });
});

// ============================================================
// DBクエリ計測
// ============================================================

async function timedQuery(executor, sql, params = [], label = 'DB') {
  const startedAt = Date.now();

  try {
    const result = await executor.query(sql, params);

    const elapsedMs = Date.now() - startedAt;

    // 200ms以上なら警告ログ
    if (elapsedMs >= 200) {
      logger.warn('遅いDBクエリを検出', {
        label,
        elapsedMs
      });
    }

    return result;
  } catch (err) {
    logger.error('DBクエリエラー', {
      label,
      error: err.message,
      elapsedMs: Date.now() - startedAt
    });

    throw err;
  }
}

// ============================================================
// DBスキーマ初期化
// ============================================================

async function initDb() {
  const schemaSql = [
    'CREATE TABLE IF NOT EXISTS users (',
    '  id SERIAL PRIMARY KEY,',
    '  username VARCHAR(50) UNIQUE NOT NULL,',
    '  password_hash VARCHAR(255) NOT NULL,',
    '  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP',
    ');',

    'CREATE TABLE IF NOT EXISTS user_answers (',
    '  user_id VARCHAR(50) NOT NULL,',
    '  question_id INT NOT NULL,',
    '  is_correct INT DEFAULT 0,',
    '  answered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,',
    '  PRIMARY KEY (user_id, question_id)',
    ');',

    'CREATE TABLE IF NOT EXISTS results (',
    '  id SERIAL PRIMARY KEY,',
    '  user_id VARCHAR(50) NOT NULL,',
    '  score INT NOT NULL,',
    '  max_score INT NOT NULL,',
    '  category VARCHAR(100),',
    '  correct_count INT NOT NULL,',
    '  total_count INT NOT NULL,',
    '  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP',
    ');',

    'ALTER TABLE user_answers ADD COLUMN IF NOT EXISTS is_correct INT DEFAULT 0;',
    'ALTER TABLE user_answers ADD COLUMN IF NOT EXISTS answered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;',

    'CREATE INDEX IF NOT EXISTS idx_results_user_id_id',
    'ON results (user_id, id DESC);'
  ].join('\n');

  try {
    await timedQuery(
      pool,
      schemaSql,
      [],
      'initDb'
    );

    logger.info('DBスキーマ初期化完了');

  } catch (err) {
    logger.error(
      'DB初期化失敗のため停止します',
      {
        error: err.message
      }
    );

    process.exit(1);
  }
}

// ============================================================
// プロセス例外
// ============================================================

process.on('uncaughtException', (err) => {
  logger.error(
    '未捕捉の例外が発生したため終了します',
    {
      error: err.message,
      stack: err.stack
    }
  );

  process.exit(1);
});

process.on('unhandledRejection', (reason) => {
  logger.error(
    '未処理のPromise拒否が発生しました',
    {
      reason: String(reason)
    }
  );
});

// ============================================================
// CORS
// ============================================================

const allowedOrigins = [
  process.env.FRONTEND_URL,
  'http://localhost:3000'
].filter(Boolean);

app.use(
  cors({
    origin: function (origin, callback) {
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(
          new Error(
            'CORSポリシーにより制限されています。'
          )
        );
      }
    },

    credentials: true
  })
);

// ============================================================
// 基本ミドルウェア
// ============================================================

app.use(
  helmet({
    contentSecurityPolicy: false
  })
);

app.use(
  express.json({
    limit: '10kb'
  })
);

app.use(
  express.static(
    path.join(__dirname, 'public')
  )
);

// ============================================================
// レートリミット
// ============================================================

const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,

  message: {
    error:
      "リクエスト数が多すぎます。しばらく時間を置いてから再試行してください。"
  }
});

app.use('/api/', globalLimiter);

const strictLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,

  message: {
    error:
      "短時間の操作回数が多すぎます。1分ほどおいて再試行してください。"
  }
});

// ============================================================
// JWT認証
// ============================================================

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];

  const token =
    authHeader &&
    authHeader.startsWith('Bearer ')
      ? authHeader.substring(7)
      : null;

  if (!token) {
    return res.status(401).json({
      error: "認証が必要です。ログインしてください。"
    });
  }

  jwt.verify(
    token,
    JWT_SECRET,
    (err, user) => {
      if (err) {
        return res.status(403).json({
          error:
            "トークンが無効または期限切れです。"
        });
      }

      req.user = user;
      next();
    }
  );
}

function getOptionalUsername(req) {
  try {
    const authHeader =
      req.headers['authorization'];

    const token =
      authHeader &&
      authHeader.startsWith('Bearer ')
        ? authHeader.substring(7)
        : null;

    if (!token) {
      return null;
    }

    const decoded = jwt.verify(
      token,
      JWT_SECRET
    );

    return decoded?.username || null;

  } catch (err) {
    return null;
  }
}

// ============================================================
// 問題キャッシュ
//
// 問題文・選択肢・正解・難易度などは基本的に頻繁には変化しない。
// そのためDBから毎回SELECTせず、Node.jsメモリに保持する。
// ============================================================

let questionCache = [];
const questionCacheMap = new Map();

const QUESTION_CACHE_REFRESH_MS =
  5 * 60 * 1000;

async function refreshQuestionCache() {
  const result = await timedQuery(
    pool,
    `
      SELECT
        id,
        category,
        question_text,
        option1,
        option2,
        option3,
        option4,
        correct_option,
        difficulty,
        answer_count,
        correct_count,
        image_url,
        explanation
      FROM questions
      ORDER BY id ASC
    `,
    [],
    'refreshQuestionCache'
  );

  const newCache = result.rows.map((row) => ({
    id: Number(row.id),

    category:
      row.category || '全般',

    question_text:
      row.question_text || '',

    option1:
      row.option1 || '',

    option2:
      row.option2 || '',

    option3:
      row.option3 || '',

    option4:
      row.option4 || '',

    correct_option:
      Number(row.correct_option),

    difficulty:
      Number(row.difficulty ?? 0),

    answer_count:
      Number(row.answer_count ?? 0),

    correct_count:
      Number(row.correct_count ?? 0),

    image_url:
      row.image_url || null,

    explanation:
      row.explanation || ''
  }));

  questionCache = newCache;

  questionCacheMap.clear();

  for (const question of newCache) {
    questionCacheMap.set(
      question.id,
      question
    );
  }

  logger.info(
    "問題キャッシュ更新完了",
    {
      count: questionCache.length
    }
  );
}

function getQuestionById(id) {
  return questionCacheMap.get(Number(id)) || null;
}

function updateQuestionCache(question) {
  const cached = questionCacheMap.get(
    Number(question.id)
  );

  if (!cached) {
    return;
  }

  cached.difficulty =
    Number(question.difficulty ?? cached.difficulty);

  cached.answer_count =
    Number(question.answer_count ?? cached.answer_count);

  cached.correct_count =
    Number(question.correct_count ?? cached.correct_count);
}

// ============================================================
// ユーザー解答履歴キャッシュ
//
// user_answersはユーザーごとに取得する。
// 同じユーザーがCATを20問実施する場合などに、
// 毎回SELECTする必要をなくす。
// ============================================================

const userProgressCache = new Map();

const USER_PROGRESS_CACHE_TTL_MS =
  5 * 60 * 1000;

async function getUserProgress(username) {
  if (!username) {
    return new Map();
  }

  const cached =
    userProgressCache.get(username);

  if (
    cached &&
    Date.now() - cached.loadedAt <
      USER_PROGRESS_CACHE_TTL_MS
  ) {
    return cached.answers;
  }

  const result = await timedQuery(
    pool,
    `
      SELECT
        question_id,
        is_correct,
        answered_at
      FROM user_answers
      WHERE user_id = $1
    `,
    [username],
    'getUserProgress'
  );

  const answers = new Map();

  for (const row of result.rows) {
    answers.set(
      Number(row.question_id),
      {
        isCorrect:
          Number(row.is_correct) === 1,

        answeredAt:
          row.answered_at
      }
    );
  }

  userProgressCache.set(
    username,
    {
      loadedAt: Date.now(),
      answers
    }
  );

  return answers;
}

function updateUserProgressCache(
  username,
  questionId,
  isCorrect,
  answeredAt = new Date().toISOString()
) {
  if (!username) {
    return;
  }

  let cached =
    userProgressCache.get(username);

  if (!cached) {
    cached = {
      loadedAt: Date.now(),
      answers: new Map()
    };

    userProgressCache.set(
      username,
      cached
    );
  }

  cached.answers.set(
    Number(questionId),
    {
      isCorrect:
        Number(isCorrect) === 1,

      answeredAt
    }
  );

  cached.loadedAt = Date.now();
}

// ============================================================
// 問題選択用ヘルパー
// ============================================================

function getMajorCategory(category) {
  const value = String(category || '');

  if (value.includes('ストラテジ')) {
    return 'ストラテジ';
  }

  if (value.includes('マネジメント')) {
    return 'マネジメント';
  }

  if (value.includes('テクノロジ')) {
    return 'テクノロジ';
  }

  return 'その他';
}

function getAnsweredTimestamp(answer) {
  if (!answer?.answeredAt) {
    return 0;
  }

  const time =
    new Date(answer.answeredAt).getTime();

  return Number.isFinite(time)
    ? time
    : 0;
}

function shuffleArray(array) {
  const copy = [...array];

  for (
    let i = copy.length - 1;
    i > 0;
    i--
  ) {
    const j =
      Math.floor(
        Math.random() * (i + 1)
      );

    [copy[i], copy[j]] =
      [copy[j], copy[i]];
  }

  return copy;
}

// 通常・弱点モードの優先順位
function sortPracticeQuestions(
  candidates,
  progress,
  mode
) {
  return candidates
    .map((question) => ({
      question,
      answer:
        progress.get(question.id) || null,

      random:
        Math.random()
    }))
    .sort((a, b) => {
      const aAnswer = a.answer;
      const bAnswer = b.answer;

      let aRank;
      let bRank;

      if (mode === 'weakness') {
        // 不正解
        aRank =
          aAnswer && !aAnswer.isCorrect
            ? 0
            : 1;

        bRank =
          bAnswer && !bAnswer.isCorrect
            ? 0
            : 1;
      } else {
        // 未回答
        aRank =
          !aAnswer
            ? 0
            : 1;

        bRank =
          !bAnswer
            ? 0
            : 1;
      }

      if (aRank !== bRank) {
        return aRank - bRank;
      }

      const aTime =
        getAnsweredTimestamp(aAnswer);

      const bTime =
        getAnsweredTimestamp(bAnswer);

      if (aTime !== bTime) {
        return aTime - bTime;
      }

      return a.random - b.random;
    })
    .map(item => item.question);
}

// 通常問題取得
function selectPracticeQuestions(
  candidates,
  count,
  mode,
  progress
) {
  const sorted =
    sortPracticeQuestions(
      candidates,
      progress,
      mode
    );

  return sorted.slice(
    0,
    count
  );
}

// 全分野100問
function selectFullExamQuestions(
  candidates,
  mode,
  progress
) {
  const targets = [
    {
      major: 'ストラテジ',
      count: 30
    },
    {
      major: 'マネジメント',
      count: 20
    },
    {
      major: 'テクノロジ',
      count: 50
    }
  ];

  const selected = [];
  const usedIds = new Set();

  for (const target of targets) {
    const group =
      candidates.filter(
        q =>
          getMajorCategory(q.category) ===
          target.major
      );

    const sorted =
      sortPracticeQuestions(
        group,
        progress,
        mode
      );

    for (
      const question of sorted
    ) {
      if (
        selected.length >=
        100
      ) {
        break;
      }

      if (
        usedIds.has(question.id)
      ) {
        continue;
      }

      if (
        selected.filter(
          q =>
            getMajorCategory(q.category) ===
            target.major
        ).length >=
        target.count
      ) {
        break;
      }

      selected.push(
        question
      );

      usedIds.add(
        question.id
      );
    }
  }

  // 問題数不足時のフォールバック
  if (selected.length < 100) {
    const remaining =
      candidates.filter(
        q => !usedIds.has(q.id)
      );

    const sortedRemaining =
      sortPracticeQuestions(
        remaining,
        progress,
        mode
      );

    for (
      const question of sortedRemaining
    ) {
      if (
        selected.length >= 100
      ) {
        break;
      }

      selected.push(
        question
      );

      usedIds.add(
        question.id
      );
    }
  }

  return shuffleArray(
    selected
  );
}

// ============================================================
// CAT問題選択
// ============================================================

function selectAdaptiveQuestion(
  candidates,
  usedIds,
  theta
) {
  const available =
    candidates.filter(
      q => !usedIds.has(q.id)
    );

  if (
    available.length === 0
  ) {
    return null;
  }

  let bestDistance =
    Infinity;

  let bestQuestions = [];

  for (
    const question of available
  ) {
    const difficulty =
      Number(
        question.difficulty ?? 0
      );

    const distance =
      Math.abs(
        difficulty - theta
      );

    if (
      distance <
      bestDistance
    ) {
      bestDistance =
        distance;

      bestQuestions = [
        question
      ];
    } else if (
      distance ===
      bestDistance
    ) {
      bestQuestions.push(
        question
      );
    }
  }

  if (
    bestQuestions.length === 0
  ) {
    return available[0];
  }

  return bestQuestions[
    Math.floor(
      Math.random() *
      bestQuestions.length
    )
  ];
}

// ============================================================
// 認証API
// ============================================================

app.post(
  '/api/register',
  strictLimiter,
  async (req, res) => {
    try {
      const {
        username,
        password
      } = req.body;

      if (
        !username ||
        typeof username !==
          'string' ||
        !/^[a-zA-Z0-9_-]{3,20}$/.test(
          username.trim()
        )
      ) {
        return res.status(400).json({
          error:
            "ユーザー名は3〜20文字の半角英数字、ハイフン、アンダースコアで入力してください。"
        });
      }

      if (
        !password ||
        typeof password !==
          'string' ||
        password.length < 6 ||
        password.length > 50
      ) {
        return res.status(400).json({
          error:
            "パスワードは6文字以上50文字以下で入力してください。"
        });
      }

      const trimmedUsername =
        username.trim();

      const existingUser =
        await timedQuery(
          pool,
          `
            SELECT id
            FROM users
            WHERE username = $1
          `,
          [trimmedUsername],
          'register.checkUser'
        );

      if (
        existingUser.rows.length > 0
      ) {
        return res.status(400).json({
          error:
            "そのユーザー名は既に使用されています。"
        });
      }

      const passwordHash =
        await bcrypt.hash(
          password,
          10
        );

      await timedQuery(
        pool,
        `
          INSERT INTO users
            (username, password_hash)
          VALUES
            ($1, $2)
        `,
        [
          trimmedUsername,
          passwordHash
        ],
        'register.insertUser'
      );

      const token =
        jwt.sign(
          {
            username:
              trimmedUsername
          },
          JWT_SECRET,
          {
            expiresIn: '7d'
          }
        );

      userProgressCache.set(
        trimmedUsername,
        {
          loadedAt: Date.now(),
          answers: new Map()
        }
      );

      logger.info(
        "ユーザーが新規登録されました",
        {
          username:
            trimmedUsername
        }
      );

      res.json({
        message: "登録成功",
        token,
        username:
          trimmedUsername
      });

    } catch (err) {
      logger.error(
        "新規登録エラー",
        {
          error: err.message
        }
      );

      res.status(500).json({
        error:
          "ユーザー登録処理に失敗しました。"
      });
    }
  }
);

app.post(
  '/api/login',
  strictLimiter,
  async (req, res) => {
    try {
      const {
        username,
        password
      } = req.body;

      if (
        !username ||
        !password
      ) {
        return res.status(400).json({
          error:
            "ユーザー名とパスワードを入力してください。"
        });
      }

      const userRes =
        await timedQuery(
          pool,
          `
            SELECT
              id,
              username,
              password_hash
            FROM users
            WHERE username = $1
          `,
          [
            String(username).trim()
          ],
          'login.getUser'
        );

      if (
        userRes.rows.length ===
        0
      ) {
        return res.status(401).json({
          error:
            "ユーザー名またはパスワードが正しくありません。"
        });
      }

      const user =
        userRes.rows[0];

      const match =
        await bcrypt.compare(
          password,
          user.password_hash
        );

      if (!match) {
        return res.status(401).json({
          error:
            "ユーザー名またはパスワードが正しくありません。"
        });
      }

      const token =
        jwt.sign(
          {
            username:
              user.username
          },
          JWT_SECRET,
          {
            expiresIn: '7d'
          }
        );

      res.json({
        message:
          "ログイン成功",
        token,
        username:
          user.username
      });

    } catch (err) {
      logger.error(
        "ログインエラー",
        {
          error: err.message
        }
      );

      res.status(500).json({
        error:
          "ログイン処理に失敗しました。"
      });
    }
  }
);

app.get(
  '/api/me',
  authenticateToken,
  (req, res) => {
    res.json({
      username:
        req.user.username
    });
  }
);

// ============================================================
// カテゴリAPI
//
// 問題カテゴリはキャッシュから返すためDBアクセスなし。
// ============================================================

app.get(
  '/api/categories',
  (req, res) => {
    try {
      const categories =
        [
          ...new Set(
            questionCache
              .map(q => q.category)
              .filter(Boolean)
          )
        ];

      res.json(
        categories
      );

    } catch (err) {
      logger.error(
        "カテゴリ取得エラー",
        {
          error: err.message
        }
      );

      res.status(500).json({
        error:
          "カテゴリの取得に失敗しました。"
      });
    }
  }
);

// ============================================================
// 問題取得API
//
// 従来:
//   DBでLEFT JOIN
//   ORDER BY
//   RANDOM()
//   などを毎回実行
//
// 改善後:
//   user_answersだけ必要時に取得
//   問題選択はNode.jsメモリ上
// ============================================================

app.get(
  '/api/questions',
  async (req, res) => {
    try {
      const {
        category,
        limit,
        mode
      } = req.query;

      let count =
        parseInt(
          limit,
          10
        ) || 10;

      if (
        Number.isNaN(count) ||
        count < 1
      ) {
        count = 10;
      }

      if (
        count > 100
      ) {
        count = 100;
      }

      const username =
        getOptionalUsername(req);

      const progress =
        username
          ? await getUserProgress(
              username
            )
          : new Map();

      let candidates;

      if (
        !category ||
        category === 'all'
      ) {
        candidates =
          questionCache;
      } else {
        candidates =
          questionCache.filter(
            q =>
              q.category ===
              String(category)
                .substring(
                  0,
                  50
                )
          );
      }

      if (
        candidates.length ===
        0
      ) {
        return res.json([]);
      }

      let questions;

      if (
        (!category ||
          category === 'all') &&
        count === 100
      ) {
        questions =
          selectFullExamQuestions(
            candidates,
            mode,
            progress
          );
      } else {
        questions =
          selectPracticeQuestions(
            candidates,
            count,
            mode,
            progress
          );
      }

      // クライアントへ返す内容を制限
      const responseQuestions =
        questions.map(
          q => ({
            id: q.id,
            category:
              q.category,
            question_text:
              q.question_text,
            option1:
              q.option1,
            option2:
              q.option2,
            option3:
              q.option3,
            option4:
              q.option4,
            image_url:
              q.image_url
          })
        );

      res.json(
        responseQuestions
      );

    } catch (err) {
      logger.error(
        "問題取得エラー",
        {
          error: err.message
        }
      );

      res.status(500).json({
        error:
          "問題データの取得に失敗しました。"
      });
    }
  }
);

// ============================================================
// 問題統計更新SQL
//
// DB側で answer_count / correct_count を加算することで、
// 同時アクセス時の「値を読んでから+1して書く」競合を防止。
// ============================================================

const UPDATE_QUESTION_STATS_SQL = `
  WITH input AS (
    SELECT *
    FROM unnest(
      $1::int[],
      $2::int[],
      $3::int[]
    ) AS t(
      id,
      is_correct,
      is_first_time
    )
  ),

  calculated AS (
    SELECT
      q.id,

      COALESCE(
        q.answer_count,
        0
      ) + 1
        AS new_answer_count,

      COALESCE(
        q.correct_count,
        0
      ) + input.is_correct
        AS new_correct_count,

      COALESCE(
        q.difficulty,
        0.0
      ) AS old_difficulty,

      input.is_first_time,

      CASE
        WHEN
          COALESCE(q.answer_count, 0) + 1 > 5
        THEN
          GREATEST(
            0.01,
            (
              (
                (
                  (
                    COALESCE(q.correct_count, 0)
                    + input.is_correct
                    + 1
                  )::numeric
                  /
                  (
                    COALESCE(q.answer_count, 0)
                    + 1
                    + 2
                  )
                )
                - 0.25
              )
              /
              0.75
            )
          )
        ELSE
          NULL
      END AS p_adjusted

    FROM questions q

    JOIN input
      ON q.id = input.id
  ),

  scored AS (
    SELECT
      calculated.*,

      CASE
        WHEN
          calculated.p_adjusted IS NOT NULL
        THEN
          -LN(
            calculated.p_adjusted
            /
            (
              1 -
              calculated.p_adjusted
            )
          ) / 1.7
        ELSE
          calculated.old_difficulty
      END AS calculated_difficulty

    FROM calculated
  ),

  final_values AS (
    SELECT
      scored.*,

      CASE
        WHEN
          scored.new_answer_count > 5
        THEN
          GREATEST(
            -3.0,
            LEAST(
              3.0,

              (
                1 -
                CASE
                  WHEN scored.is_first_time = 1
                  THEN 0.1
                  ELSE 0.02
                END
              )
              * scored.old_difficulty

              +

              CASE
                WHEN scored.is_first_time = 1
                THEN 0.1
                ELSE 0.02
              END
              * scored.calculated_difficulty
            )
          )

        ELSE
          scored.old_difficulty
      END AS new_difficulty

    FROM scored
  )

  UPDATE questions AS q

  SET
    answer_count =
      final_values.new_answer_count,

    correct_count =
      final_values.new_correct_count,

    difficulty =
      final_values.new_difficulty

  FROM final_values

  WHERE
    q.id =
      final_values.id

  RETURNING
    q.id,
    q.answer_count,
    q.correct_count,
    q.difficulty;
`;

// ============================================================
// user_answers一括UPSERT
// ============================================================

const UPSERT_USER_ANSWERS_SQL = `
  INSERT INTO user_answers (
    user_id,
    question_id,
    is_correct,
    answered_at
  )

  SELECT
    u,
    q,
    c,
    CURRENT_TIMESTAMP

  FROM unnest(
    $1::varchar[],
    $2::int[],
    $3::int[]
  ) AS t(
    u,
    q,
    c
  )

  ON CONFLICT (
    user_id,
    question_id
  )

  DO UPDATE SET
    is_correct =
      EXCLUDED.is_correct,

    answered_at =
      CURRENT_TIMESTAMP
`;

// ============================================================
// 通常試験提出
//
// DB SELECTを廃止し、問題・履歴はキャッシュから取得。
// DBアクセスは基本的に:
//   BEGIN
//   UPDATE questions
//   UPSERT user_answers
//   INSERT results
//   COMMIT
// ============================================================

app.post(
  '/api/submit',
  strictLimiter,
  authenticateToken,
  async (req, res) => {

    let client = null;

    try {
      const {
        questionIds,
        answers,
        category
      } = req.body;

      const authUserId =
        req.user.username;

      if (
        !Array.isArray(
          questionIds
        ) ||
        questionIds.length === 0 ||
        questionIds.length > 100
      ) {
        return res.status(400).json({
          error:
            "問題ID配列が無効、または規定数(100問)を超えています。"
        });
      }

      const validQuestionIds =
        questionIds.map(
          id => Number(id)
        );

      if (
        validQuestionIds.some(
          id =>
            !Number.isInteger(id) ||
            id <= 0
        )
      ) {
        return res.status(400).json({
          error:
            "不正な問題IDが含まれています。"
        });
      }

      // 重複ID禁止
      const uniqueIds =
        new Set(
          validQuestionIds
        );

      if (
        uniqueIds.size !==
        validQuestionIds.length
      ) {
        return res.status(400).json({
          error:
            "同じ問題IDが重複しています。"
        });
      }

      const userAnswersMap =
        (
          typeof answers ===
            'object' &&
          answers !== null
        )
          ? answers
          : {};

      const progress =
        await getUserProgress(
          authUserId
        );

      const questions =
        validQuestionIds.map(
          id =>
            getQuestionById(id)
        );

      if (
        questions.some(
          q => !q
        )
      ) {
        return res.status(400).json({
          error:
            "存在しない問題IDが含まれています。"
        });
      }

      const responses = [];

      const qIds = [];
      const qCorrects = [];
      const qFirstTimes = [];

      const uUsers = [];
      const uQIds = [];
      const uCorrects = [];

      let correctCount = 0;

      const details = [];

      for (
        const q of questions
      ) {
        const userAnswer =
          userAnswersMap[
            q.id
          ];

        const isCorrect =
          (
            userAnswer !==
              undefined &&
            Number(userAnswer) ===
              Number(q.correct_option)
          )
            ? 1
            : 0;

        if (isCorrect === 1) {
          correctCount++;
        }

        responses.push(
          isCorrect
        );

        const isFirstTime =
          !progress.has(
            q.id
          );

        qIds.push(q.id);
        qCorrects.push(
          isCorrect
        );
        qFirstTimes.push(
          isFirstTime ? 1 : 0
        );

        uUsers.push(
          authUserId
        );
        uQIds.push(
          q.id
        );
        uCorrects.push(
          isCorrect
        );

        details.push({
          id: q.id,

          questionText:
            q.question_text,

          option1:
            q.option1,

          option2:
            q.option2,

          option3:
            q.option3,

          option4:
            q.option4,

          imageUrl:
            q.image_url || null,

          explanation:
            q.explanation || '',

          userAnswer:
            userAnswer !==
              undefined
              ? Number(userAnswer)
              : null,

          correctOption:
            Number(
              q.correct_option
            ),

          isCorrect:
            isCorrect === 1
        });
      }

      const questionParams =
        questions.map(
          q => ({
            difficulty:
              Number(
                q.difficulty ?? 0
              ),

            discrimination:
              1.0
          })
        );

      client =
        await pool.connect();

      await timedQuery(
        client,
        'BEGIN',
        [],
        'submit.BEGIN'
      );

      const updatedQuestions =
        await timedQuery(
          client,
          UPDATE_QUESTION_STATS_SQL,
          [
            qIds,
            qCorrects,
            qFirstTimes
          ],
          'submit.updateQuestions'
        );

      await timedQuery(
        client,
        UPSERT_USER_ANSWERS_SQL,
        [
          uUsers,
          uQIds,
          uCorrects
        ],
        'submit.upsertUserAnswers'
      );

      const totalCount =
        questions.length;

      const irtResult =
        calculateIRTScore(
          responses,
          questionParams
        );

      const finalScore =
        correctCount === 0
          ? 0
          : irtResult.score;

      const categoryName =
        (
          !category ||
          category === 'all'
        )
          ? '全分野'
          : String(category)
              .substring(0, 50);

      await timedQuery(
        client,
        `
          INSERT INTO results (
            user_id,
            score,
            max_score,
            category,
            correct_count,
            total_count
          )

          VALUES (
            $1,
            $2,
            $3,
            $4,
            $5,
            $6
          )
        `,
        [
          authUserId,
          finalScore,
          1000,
          categoryName,
          correctCount,
          totalCount
        ],
        'submit.insertResult'
      );

      await timedQuery(
        client,
        'COMMIT',
        [],
        'submit.COMMIT'
      );

      // DB更新成功後にキャッシュを更新
      for (
        const row of
          updatedQuestions.rows
      ) {
        updateQuestionCache(
          row
        );
      }

      const now =
        new Date().toISOString();

      for (
        let i = 0;
        i < qIds.length;
        i++
      ) {
        updateUserProgressCache(
          authUserId,
          qIds[i],
          qCorrects[i],
          now
        );
      }

      logger.info(
        "試験提出完了",
        {
          user:
            authUserId,
          score:
            finalScore,
          correctCount,
          totalCount
        }
      );

      res.json({
        score:
          finalScore,

        maxScore:
          1000,

        correctCount,

        totalCount,

        details
      });

    } catch (err) {

      if (client) {
        try {
          await client.query(
            'ROLLBACK'
          );
        } catch (
          rollbackErr
        ) {
          logger.error(
            "ROLLBACK失敗",
            {
              error:
                rollbackErr.message
            }
          );
        }
      }

      logger.error(
        "採点処理エラー",
        {
          error:
            err.message
        }
      );

      res.status(500).json({
        error:
          "採点処理中にエラーが発生しました。"
      });

    } finally {

      if (client) {
        client.release();
      }
    }
  }
);

// ============================================================
// CAT開始
//
// DBアクセスなし。
// 問題キャッシュから初期theta=0付近を選択。
// ============================================================

app.post(
  '/api/cat/start',
  strictLimiter,
  async (req, res) => {
    try {
      const {
        category
      } = req.body;

      let candidates;

      if (
        category &&
        category !== 'all'
      ) {
        candidates =
          questionCache.filter(
            q =>
              q.category.includes(
                String(category)
              )
          );
      } else {
        candidates =
          questionCache.filter(
            q =>
              getMajorCategory(
                q.category
              ) ===
              'ストラテジ'
          );
      }

      if (
        candidates.length === 0
      ) {
        return res.status(404).json({
          error:
            "出題可能な問題が見つかりませんでした。"
        });
      }

      const question =
        selectAdaptiveQuestion(
          candidates,
          new Set(),
          0.0
        );

      if (!question) {
        return res.status(404).json({
          error:
            "出題可能な問題が見つかりませんでした。"
        });
      }

      res.json({
        step: 1,
        totalSteps: 20,

        question: {
          id:
            question.id,

          category:
            question.category,

          question_text:
            question.question_text,

          option1:
            question.option1,

          option2:
            question.option2,

          option3:
            question.option3,

          option4:
            question.option4,

          image_url:
            question.image_url,

          difficulty:
            question.difficulty
        },

        history: []
      });

    } catch (err) {

      logger.error(
        "CAT開始エラー",
        {
          error:
            err.message
        }
      );

      res.status(500).json({
        error:
          "CATテストの開始に失敗しました。"
      });
    }
  }
);

// ============================================================
// CAT回答
//
// 改善点:
//   ・現在問題のSELECT → キャッシュ
//   ・answeredCheck → ユーザー進捗キャッシュ
//   ・次問題SELECT → キャッシュ
//
// DBへ行くのは主に書き込みだけ。
// ============================================================

app.post(
  '/api/cat/answer',
  authenticateToken,
  async (req, res) => {

    let client = null;

    try {
      const {
        questionId,
        userAnswer,
        history,
        category
      } = req.body;

      const authUserId =
        req.user.username;

      if (
        !questionId ||
        userAnswer ===
          undefined ||
        !Array.isArray(history)
      ) {
        return res.status(400).json({
          error:
            "リクエストパラメータが不正です。"
        });
      }

      // historyが巨大になるのを防止
      if (
        history.length >=
        20
      ) {
        return res.status(400).json({
          error:
            "CAT履歴が不正です。"
        });
      }

      const currentQ =
        getQuestionById(
          Number(questionId)
        );

      if (!currentQ) {
        return res.status(404).json({
          error:
            "問題が見つかりません。"
        });
      }

      const isCorrect =
        (
          Number(userAnswer) ===
          Number(
            currentQ.correct_option
          )
        )
          ? 1
          : 0;

      const progress =
        await getUserProgress(
          authUserId
        );

      const isFirstTime =
        !progress.has(
          currentQ.id
        );

      // この時点のdifficultyをIRT用に保持
      const originalDifficulty =
        Number(
          currentQ.difficulty ?? 0
        );

      // DBに書き込む対象
      const qIds = [
        currentQ.id
      ];

      const qCorrects = [
        isCorrect
      ];

      const qFirstTimes = [
        isFirstTime ? 1 : 0
      ];

      const uUsers = [
        authUserId
      ];

      const uQIds = [
        currentQ.id
      ];

      const uCorrects = [
        isCorrect
      ];

      client =
        await pool.connect();

      await timedQuery(
        client,
        'BEGIN',
        [],
        'cat.BEGIN'
      );

      const updatedQuestions =
        await timedQuery(
          client,
          UPDATE_QUESTION_STATS_SQL,
          [
            qIds,
            qCorrects,
            qFirstTimes
          ],
          'cat.updateQuestion'
        );

      await timedQuery(
        client,
        UPSERT_USER_ANSWERS_SQL,
        [
          uUsers,
          uQIds,
          uCorrects
        ],
        'cat.upsertUserAnswer'
      );

      // 現在の問題を履歴へ追加
      const updatedHistory = [
        ...history,
        {
          questionId:
            currentQ.id,

          isCorrect,

          difficulty:
            originalDifficulty,

          discrimination:
            1.0,

          userAnswer:
            Number(
              userAnswer
            ),

          correctOption:
            Number(
              currentQ.correct_option
            ),

          explanation:
            currentQ.explanation ||
            ''
        }
      ];

      const responses =
        updatedHistory.map(
          h => h.isCorrect
        );

      const questionParams =
        updatedHistory.map(
          h => ({
            difficulty:
              Number(
                h.difficulty ?? 0
              ),

            discrimination:
              Number(
                h.discrimination || 1
              )
          })
        );

      const irtResult =
        calculateIRTScore(
          responses,
          questionParams
        );

      const currentTheta =
        irtResult.theta;

      const totalSteps = 20;

      // ======================================================
      // CAT終了
      // ======================================================

      if (
        updatedHistory.length >=
        totalSteps
      ) {
        const correctCount =
          updatedHistory.filter(
            h =>
              h.isCorrect === 1
          ).length;

        const finalScore =
          correctCount === 0
            ? 0
            : irtResult.score;

        const categoryName =
          (
            !category ||
            category === 'all'
          )
            ? 'CATスピードテスト'
            : `CAT:${String(category).substring(
                0,
                45
              )}`;

        await timedQuery(
          client,
          `
            INSERT INTO results (
              user_id,
              score,
              max_score,
              category,
              correct_count,
              total_count
            )

            VALUES (
              $1,
              $2,
              $3,
              $4,
              $5,
              $6
            )
          `,
          [
            authUserId,
            finalScore,
            1000,
            categoryName,
            correctCount,
            totalSteps
          ],
          'cat.insertResult'
        );

        await timedQuery(
          client,
          'COMMIT',
          [],
          'cat.COMMIT'
        );

        // キャッシュ更新
        for (
          const row of
            updatedQuestions.rows
        ) {
          updateQuestionCache(
            row
          );
        }

        updateUserProgressCache(
          authUserId,
          currentQ.id,
          isCorrect
        );

        return res.json({
          isFinished:
            true,

          score:
            finalScore,

          maxScore:
            1000,

          correctCount,

          totalCount:
            totalSteps,

          currentTheta,

          lastAnswerCorrect:
            isCorrect === 1,

          explanation:
            currentQ.explanation ||
            '',

          correctOption:
            Number(
              currentQ.correct_option
            ),

          history:
            updatedHistory
        });
      }

      // ======================================================
      // 次問題選択
      // ======================================================

      let targetMajor =
        null;

      if (
        category &&
        category !== 'all'
      ) {
        targetMajor = null;
      } else {
        const nextStep =
          updatedHistory.length;

        if (
          nextStep < 6
        ) {
          targetMajor =
            'ストラテジ';
        } else if (
          nextStep < 10
        ) {
          targetMajor =
            'マネジメント';
        } else {
          targetMajor =
            'テクノロジ';
        }
      }

      let candidates;

      if (
        category &&
        category !== 'all'
      ) {
        candidates =
          questionCache.filter(
            q =>
              q.category.includes(
                String(category)
              )
          );
      } else {
        candidates =
          questionCache.filter(
            q =>
              getMajorCategory(
                q.category
              ) ===
              targetMajor
          );
      }

      const usedIds =
        new Set(
          updatedHistory.map(
            h =>
              Number(
                h.questionId
              )
          )
        );

      let nextQuestion =
        selectAdaptiveQuestion(
          candidates,
          usedIds,
          currentTheta
        );

      // カテゴリ内に残りがない場合は全カテゴリから取得
      if (!nextQuestion) {
        nextQuestion =
          selectAdaptiveQuestion(
            questionCache,
            usedIds,
            currentTheta
          );
      }

      if (!nextQuestion) {
        return res.status(500).json({
          error:
            "次の問題を取得できませんでした。"
        });
      }

      await timedQuery(
        client,
        'COMMIT',
        [],
        'cat.COMMIT'
      );

      // DB更新成功後にキャッシュ更新
      for (
        const row of
          updatedQuestions.rows
      ) {
        updateQuestionCache(
          row
        );
      }

      updateUserProgressCache(
        authUserId,
        currentQ.id,
        isCorrect
      );

      res.json({
        isFinished:
          false,

        step:
          updatedHistory.length +
          1,

        totalSteps,

        currentTheta,

        lastAnswerCorrect:
          isCorrect === 1,

        explanation:
          currentQ.explanation ||
          '',

        correctOption:
          Number(
            currentQ.correct_option
          ),

        question: {
          id:
            nextQuestion.id,

          category:
            nextQuestion.category,

          question_text:
            nextQuestion.question_text,

          option1:
            nextQuestion.option1,

          option2:
            nextQuestion.option2,

          option3:
            nextQuestion.option3,

          option4:
            nextQuestion.option4,

          image_url:
            nextQuestion.image_url,

          difficulty:
            nextQuestion.difficulty
        },

        history:
          updatedHistory
      });

    } catch (err) {

      if (client) {
        try {
          await client.query(
            'ROLLBACK'
          );
        } catch (
          rollbackErr
        ) {
          logger.error(
            "CAT ROLLBACK失敗",
            {
              error:
                rollbackErr.message
            }
          );
        }
      }

      logger.error(
        "CAT解答処理エラー",
        {
          error:
            err.message
        }
      );

      res.status(500).json({
        error:
          "CAT解答処理に失敗しました。"
      });

    } finally {

      if (client) {
        client.release();
      }
    }
  }
);

// ============================================================
// 分析API
//
// user_progress_cacheを利用するため、
// キャッシュが存在すればDBアクセスなし。
// 初回だけuser_answersをSELECT。
// ============================================================

app.get(
  '/api/analytics',
  authenticateToken,
  async (req, res) => {
    try {
      const authUserId =
        req.user.username;

      const progress =
        await getUserProgress(
          authUserId
        );

      const categoryMap =
        new Map();

      let totalAnswered = 0;
      let totalCorrect = 0;

      for (
        const [
          questionId,
          answer
        ] of progress.entries()
      ) {
        const question =
          getQuestionById(
            questionId
          );

        if (!question) {
          continue;
        }

        const category =
          question.category ||
          '全般';

        if (
          !categoryMap.has(
            category
          )
        ) {
          categoryMap.set(
            category,
            {
              category,
              total_answered: 0,
              correct_count: 0
            }
          );
        }

        const stat =
          categoryMap.get(
            category
          );

        stat.total_answered++;

        if (
          answer.isCorrect
        ) {
          stat.correct_count++;
        }

        totalAnswered++;

        if (
          answer.isCorrect
        ) {
          totalCorrect++;
        }
      }

      const categories =
        [...categoryMap.values()]
          .map(stat => ({
            category:
              stat.category,

            total_answered:
              stat.total_answered,

            correct_count:
              stat.correct_count,

            accuracy:
              stat.total_answered >
              0
                ? Number(
                    (
                      (
                        stat.correct_count /
                        stat.total_answered
                      ) *
                      100
                    ).toFixed(1)
                  )
                : 0
          }))
          .sort(
            (a, b) =>
              a.accuracy -
              b.accuracy
          );

      const overallAccuracy =
        totalAnswered > 0
          ? Number(
              (
                (
                  totalCorrect /
                  totalAnswered
                ) *
                100
              ).toFixed(1)
            )
          : 0;

      const qualifiedWeak =
        categories.find(
          c =>
            c.total_answered >=
            5
        );

      const weakest =
        qualifiedWeak ||
        (
          categories.length > 0
            ? categories[0]
            : null
        );

      res.json({
        overall: {
          totalAnswered,
          totalCorrect,
          accuracy:
            overallAccuracy
        },

        categories,

        weakestCategory:
          weakest
            ? weakest.category
            : null,

        weakestAccuracy:
          weakest
            ? weakest.accuracy
            : 0
      });

    } catch (err) {

      logger.error(
        "弱点分析取得エラー",
        {
          error:
            err.message
        }
      );

      res.status(500).json({
        error:
          "弱点分析データの取得に失敗しました。"
      });
    }
  }
);

// ============================================================
// 履歴API
// ============================================================

app.get(
  '/api/history',
  authenticateToken,
  async (req, res) => {
    try {
      const authUserId =
        req.user.username;

      const history =
        await timedQuery(
          pool,
          `
            SELECT
              id,
              user_id,
              score,
              max_score,
              category,
              correct_count,
              total_count,
              to_char(
                created_at,
                'YYYY/MM/DD HH24:MI'
              ) AS date
            FROM results
            WHERE user_id = $1
            ORDER BY id DESC
          `,
          [authUserId],
          'history'
        );

      res.json(
        history.rows
      );

    } catch (err) {

      logger.error(
        "履歴取得エラー",
        {
          error:
            err.message
        }
      );

      res.status(500).json({
        error:
          "成績履歴の取得に失敗しました。"
      });
    }
  }
);

// ============================================================
// IRT採点
// ============================================================

function calculateIRTScore(
  responses,
  questions
) {
  const numNodes = 81;

  const nodes = [];
  const posteriors = [];

  for (
    let i = 0;
    i < numNodes;
    i++
  ) {
    const theta =
      -4.0 +
      i * 0.1;

    nodes.push(theta);

    posteriors.push(
      Math.exp(
        -0.5 *
        theta *
        theta
      )
    );
  }

  let sumPosterior =
    posteriors.reduce(
      (a, b) =>
        a + b,
      0
    );

  for (
    let i = 0;
    i < numNodes;
    i++
  ) {
    posteriors[i] /=
      sumPosterior;
  }

  const c = 0.25;

  for (
    let i = 0;
    i < responses.length;
    i++
  ) {
    const x =
      responses[i];

    const b =
      Number(
        questions[i].difficulty ??
        0
      );

    const a =
      Number(
        questions[i].discrimination ||
        1.0
      );

    for (
      let j = 0;
      j < numNodes;
      j++
    ) {
      const theta =
        nodes[j];

      const p =
        c +
        (1 - c) /
          (
            1 +
            Math.exp(
              -1.7 *
              a *
              (theta - b)
            )
          );

      const likelihood =
        x === 1
          ? p
          : 1 - p;

      posteriors[j] *=
        likelihood;
    }
  }

  sumPosterior =
    posteriors.reduce(
      (a, b) =>
        a + b,
      0
    );

  if (
    sumPosterior === 0 ||
    !Number.isFinite(
      sumPosterior
    )
  ) {
    return {
      theta:
        -3.0,

      score:
        100
    };
  }

  let thetaEAP = 0;

  for (
    let j = 0;
    j < numNodes;
    j++
  ) {
    posteriors[j] /=
      sumPosterior;

    thetaEAP +=
      nodes[j] *
      posteriors[j];
  }

  const rawScore =
    Math.round(
      600 +
      thetaEAP *
      150
    );

  const scaledScore =
    Math.max(
      100,
      Math.min(
        1000,
        rawScore
      )
    );

  return {
    theta:
      Number(
        thetaEAP.toFixed(3)
      ),

    score:
      scaledScore
  };
}

// ============================================================
// エラーハンドラ
// ============================================================

app.use(
  (
    err,
    req,
    res,
    next
  ) => {
    logger.error(
      'Unhandled API Error',
      {
        error:
          err.message,

        stack:
          err.stack
      }
    );

    res.status(500).json({
      error:
        "内部サーバーエラーが発生しました。"
    });
  }
);

// ============================================================
// サーバー起動
// ============================================================

async function startServer() {
  // DB初期化
  await initDb();

  // 起動時に問題を一度だけ取得
  await refreshQuestionCache();

  // 定期的に問題キャッシュを更新
  const refreshTimer =
    setInterval(
      () => {
        refreshQuestionCache()
          .catch(err => {
            logger.error(
              "定期問題キャッシュ更新失敗",
              {
                error:
                  err.message
              }
            );
          });
      },
      QUESTION_CACHE_REFRESH_MS
    );

  if (
    typeof refreshTimer.unref ===
    'function'
  ) {
    refreshTimer.unref();
  }

  const server =
    app.listen(
      PORT,
      () => {
        logger.info(
          "サーバーが正常起動しました",
          {
            port:
              PORT,

            env:
              NODE_ENV,

            questionCount:
              questionCache.length
          }
        );
      }
    );

  // ==========================================================
  // Graceful Shutdown
  // ==========================================================

  function shutdown(signal) {
    logger.info(
      `${signal} シグナルを受信しました。サーバーを正常停止します...`
    );

    clearInterval(
      refreshTimer
    );

    server.close(
      async () => {
        logger.info(
          "HTTPサーバーを停止しました。"
        );

        try {
          await pool.end();

          logger.info(
            "PostgreSQL接続プールをクローズしました。"
          );

        } catch (err) {
          logger.error(
            "DBクローズ時にエラーが発生しました",
            {
              error:
                err.message
            }
          );
        }

        process.exit(0);
      }
    );
  }

  process.on(
    'SIGINT',
    () =>
      shutdown(
        'SIGINT'
      )
  );

  process.on(
    'SIGTERM',
    () =>
      shutdown(
        'SIGTERM'
      )
  );
}

// ============================================================
// 起動
// ============================================================

startServer().catch(
  err => {
    logger.error(
      "サーバー起動失敗",
      {
        error:
          err.message,

        stack:
          err.stack
      }
    );

    process.exit(1);
  }
);
