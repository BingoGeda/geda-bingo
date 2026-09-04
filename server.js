const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const path = require("path");
const { Pool } = require("pg");
const WebSocket = require("ws");
require("dotenv").config();

const app = express();

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname)));

const PORT = process.env.PORT || 10000;

const BOT_TOKEN = process.env.BOT_TOKEN || "";
const OWNER_TELEGRAM_ID = String(
  process.env.OWNER_TELEGRAM_ID || ""
);

/* =========================================================
   GAME SETTINGS
========================================================= */

const MAX_PLAYERS = 50;
const DEFAULT_ENTRY_FEE = 50;
const DEFAULT_PRIZE = 400;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL
    ? { rejectUnauthorized: false }
    : false
});

let wss;

const clients = new Map();

let autoCallTimer = null;
let autoCallBusy = false;

/* =========================================================
   BASIC
========================================================= */

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

app.get("/api/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");

    res.json({
      success: true,
      status: "healthy",
      database: "connected",
      websocket: !!wss
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      error: "Database connection failed"
    });
  }
});

/* =========================================================
   DATABASE
========================================================= */

async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGINT PRIMARY KEY,
      first_name TEXT DEFAULT '',
      last_name TEXT DEFAULT '',
      username TEXT DEFAULT '',
      role TEXT NOT NULL DEFAULT 'player',
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS game_types (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      entry_fee NUMERIC(12,2) NOT NULL,
      max_players INTEGER NOT NULL DEFAULT 50,
      prize_amount NUMERIC(12,2) NOT NULL DEFAULT 0,
      description TEXT DEFAULT '',
      active BOOLEAN DEFAULT TRUE,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS games (
      id BIGSERIAL PRIMARY KEY,
      game_type_id INTEGER REFERENCES game_types(id),
      status TEXT NOT NULL DEFAULT 'waiting',
      called_numbers INTEGER[] NOT NULL DEFAULT '{}',
      auto_call BOOLEAN NOT NULL DEFAULT FALSE,
      current_number INTEGER,
      winner_user_id BIGINT REFERENCES users(id),
      created_at TIMESTAMPTZ DEFAULT NOW(),
      started_at TIMESTAMPTZ,
      ended_at TIMESTAMPTZ
    );

    CREATE TABLE IF NOT EXISTS players (
      id BIGSERIAL PRIMARY KEY,
      game_id BIGINT REFERENCES games(id) ON DELETE CASCADE,
      user_id BIGINT REFERENCES users(id),
      card INTEGER[][] NOT NULL,
      payment_status TEXT NOT NULL DEFAULT 'pending',
      joined_at TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE(game_id, user_id)
    );

    CREATE TABLE IF NOT EXISTS payments (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT REFERENCES users(id),
      game_id BIGINT REFERENCES games(id),
      tx_ref TEXT UNIQUE NOT NULL,
      amount NUMERIC(12,2) NOT NULL,
      currency TEXT NOT NULL DEFAULT 'ETB',
      provider TEXT NOT NULL DEFAULT 'telebirr',
      status TEXT NOT NULL DEFAULT 'pending',
      provider_reference TEXT,
      raw_response JSONB,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      paid_at TIMESTAMPTZ
    );
  `);

  /* -------------------------------------------------------
     Create default game type if it does not exist
  ------------------------------------------------------- */

  const existingType = await pool.query(
    `
    SELECT id
    FROM game_types
    WHERE name = 'Bingo Geda 50'
    LIMIT 1
    `
  );

  if (existingType.rows.length === 0) {
    await pool.query(
      `
      INSERT INTO game_types
      (name, entry_fee, max_players, prize_amount, description)
      VALUES ($1,$2,$3,$4,$5)
      `,
      [
        "Bingo Geda 50",
        DEFAULT_ENTRY_FEE,
        MAX_PLAYERS,
        DEFAULT_PRIZE,
        "Standard Bingo game"
      ]
    );
  } else {
    /* -----------------------------------------------------
       Important:
       Existing database already had max_players = 10.
       Update it to 50.
       
       Prize remains unchanged.
    ----------------------------------------------------- */

    await pool.query(
      `
      UPDATE game_types
      SET
        max_players = $1,
        entry_fee = $2
      WHERE name = 'Bingo Geda 50'
      `,
      [
        MAX_PLAYERS,
        DEFAULT_ENTRY_FEE
      ]
    );
  }

  console.log("Database initialized");
  console.log(`Maximum players: ${MAX_PLAYERS}`);
}

/* =========================================================
   TELEGRAM AUTHENTICATION
========================================================= */

function validateTelegramInitData(initData) {
  if (!initData || !BOT_TOKEN) {
    return null;
  }

  try {
    const params = new URLSearchParams(initData);

    const hash = params.get("hash");

    if (!hash) {
      return null;
    }

    params.delete("hash");

    const dataCheckString = [...params.entries()]
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([key, value]) => `${key}=${value}`)
      .join("\n");

    const secretKey = crypto
      .createHmac("sha256", "WebAppData")
      .update(BOT_TOKEN)
      .digest();

    const calculatedHash = crypto
      .createHmac("sha256", secretKey)
      .update(dataCheckString)
      .digest("hex");

    const valid = crypto.timingSafeEqual(
      Buffer.from(calculatedHash, "hex"),
      Buffer.from(hash, "hex")
    );

    if (!valid) {
      return null;
    }

    const userRaw = params.get("user");

    if (!userRaw) {
      return null;
    }

    return JSON.parse(userRaw);
  } catch (error) {
    console.error(
      "Telegram auth error:",
      error.message
    );

    return null;
  }
}

async function authenticate(req, res, next) {
  try {
    const initData =
      req.headers["x-telegram-init-data"] ||
      req.body?.initData ||
      "";

    const user = validateTelegramInitData(initData);

    if (!user) {
      return res.status(401).json({
        success: false,
        error: "Invalid Telegram authentication"
      });
    }

    await pool.query(
      `
      INSERT INTO users
      (id, first_name, last_name, username)
      VALUES ($1,$2,$3,$4)
      ON CONFLICT (id)
      DO UPDATE SET
        first_name = EXCLUDED.first_name,
        last_name = EXCLUDED.last_name,
        username = EXCLUDED.username,
        updated_at = NOW()
      `,
      [
        user.id,
        user.first_name || "",
        user.last_name || "",
        user.username || ""
      ]
    );

    req.telegramUser = user;
    next();
  } catch (error) {
    console.error("Authentication error:", error);

    res.status(500).json({
      success: false,
      error: "Authentication failed"
    });
  }
}

function isOwner(user) {
  return String(user.id) === OWNER_TELEGRAM_ID;
}

function requireOwner(req, res, next) {
  if (
    !req.telegramUser ||
    !isOwner(req.telegramUser)
  ) {
    return res.status(403).json({
      success: false,
      error: "Owner only"
    });
  }

  next();
}

/* =========================================================
   USER
========================================================= */

app.get(
  "/api/me",
  authenticate,
  async (req, res) => {
    const user = req.telegramUser;
    const owner = isOwner(user);

    await pool.query(
      `
      UPDATE users
      SET role = $1
      WHERE id = $2
      `,
      [
        owner ? "owner" : "player",
        user.id
      ]
    );

    res.json({
      success: true,
      user: {
        id: String(user.id),
        first_name: user.first_name || "",
        last_name: user.last_name || "",
        username: user.username || ""
      },
      role: owner ? "owner" : "player",
      isOwner: owner
    });
  }
);

/* =========================================================
   GAME TYPES
========================================================= */

app.get("/api/game-types", async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT *
      FROM game_types
      WHERE active = TRUE
      ORDER BY id ASC
    `);

    res.json({
      success: true,
      games: result.rows
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      success: false,
      error: "Unable to load game types"
    });
  }
});

/* =========================================================
   OWNER - CREATE GAME
========================================================= */

app.post(
  "/api/owner/new-game",
  authenticate,
  requireOwner,
  async (req, res) => {
    try {
      const { game_type_id } = req.body;

      const type = await pool.query(
        `
        SELECT *
        FROM game_types
        WHERE id = $1
        AND active = TRUE
        `,
        [game_type_id]
      );

      if (type.rows.length === 0) {
        return res.status(404).json({
          success: false,
          error: "Game type not found"
        });
      }

      const existing = await pool.query(
        `
        SELECT id
        FROM games
        WHERE status IN ('waiting','playing')
        LIMIT 1
        `
      );

      if (existing.rows.length > 0) {
        return res.status(400).json({
          success: false,
          error: "There is already an active game"
        });
      }

      const result = await pool.query(
        `
        INSERT INTO games
        (game_type_id, status)
        VALUES ($1, 'waiting')
        RETURNING *
        `,
        [game_type_id]
      );

      const game = result.rows[0];

      broadcast({
        type: "game_created",
        game
      });

      res.json({
        success: true,
        game
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        success: false,
        error: "Could not create game"
      });
    }
  }
);

/* =========================================================
   CURRENT GAME
========================================================= */

app.get("/api/game", async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        g.*,
        gt.name,
        gt.entry_fee,
        gt.max_players,
        gt.prize_amount
      FROM games g
      JOIN game_types gt
      ON gt.id = g.game_type_id
      WHERE g.status IN ('waiting','playing')
      ORDER BY g.id DESC
      LIMIT 1
    `);

    if (result.rows.length === 0) {
      return res.json({
        success: true,
        game: null
      });
    }

    const game = result.rows[0];

    const players = await pool.query(
      `
      SELECT COUNT(*)
      FROM players
      WHERE game_id = $1
      AND payment_status = 'paid'
      `,
      [game.id]
    );

    res.json({
      success: true,
      game: {
        ...game,
        players: Number(
          players.rows[0].count
        )
      }
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      success: false,
      error: "Could not load game"
    });
  }
});

/* =========================================================
   BINGO CARD GENERATION
========================================================= */

function randomNumbers(min, max, count) {
  const numbers = [];

  while (numbers.length < count) {
    const number =
      Math.floor(
        Math.random() *
          (max - min + 1)
      ) + min;

    if (!numbers.includes(number)) {
      numbers.push(number);
    }
  }

  return numbers;
}

function generateBingoCard() {
  const B = randomNumbers(1, 15, 5);
  const I = randomNumbers(16, 30, 5);
  const N = randomNumbers(31, 45, 4);
  const G = randomNumbers(46, 60, 5);
  const O = randomNumbers(61, 75, 5);

  const card = [];

  for (let row = 0; row < 5; row++) {
    card.push([
      B[row],
      I[row],
      row === 2
        ? 0
        : N[row > 2 ? row - 1 : row],
      G[row],
      O[row]
    ]);
  }

  return card;
}

/* =========================================================
   PAYMENT
========================================================= */

app.post(
  "/api/payment/create",
  authenticate,
  async (req, res) => {
    try {
      const { game_id } = req.body;

      const gameResult = await pool.query(
        `
        SELECT
          g.*,
          gt.entry_fee,
          gt.max_players
        FROM games g
        JOIN game_types gt
        ON gt.id = g.game_type_id
        WHERE g.id = $1
        `,
        [game_id]
      );

      if (gameResult.rows.length === 0) {
        return res.status(404).json({
          success: false,
          error: "Game not found"
        });
      }

      const game = gameResult.rows[0];

      if (game.status !== "waiting") {
        return res.status(400).json({
          success: false,
          error: "Game is not accepting players"
        });
      }

      /* Check 50-player limit before creating payment */

      const playerCount = await pool.query(
        `
        SELECT COUNT(*)
        FROM players
        WHERE game_id = $1
        AND payment_status = 'paid'
        `,
        [game_id]
      );

      if (
        Number(playerCount.rows[0].count) >=
        game.max_players
      ) {
        return res.status(400).json({
          success: false,
          error: "Game is full"
        });
      }

      const txRef =
        "GEDA-" +
        Date.now() +
        "-" +
        crypto.randomBytes(4).toString("hex");

      await pool.query(
        `
        INSERT INTO payments
        (user_id, game_id, tx_ref, amount, currency)
        VALUES ($1,$2,$3,$4,'ETB')
        `,
        [
          req.telegramUser.id,
          game_id,
          txRef,
          game.entry_fee
        ]
      );

      /*
        TELEBIRR INTEGRATION

        This is still a placeholder.

        The official Telebirr merchant API credentials
        and API specification are required before real
        payment processing can be enabled.

        NEVER put Telebirr secrets in index.html.
      */

      res.json({
        success: true,
        tx_ref: txRef,
        amount: game.entry_fee,
        currency: "ETB",
        provider: "telebirr",
        status: "pending",
        message:
          "Payment request created. Telebirr integration requires merchant API configuration."
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        success: false,
        error: "Could not create payment"
      });
    }
  }
);

/* =========================================================
   TELEBIRR CALLBACK
========================================================= */

app.post(
  "/api/payment/telebirr/callback",
  async (req, res) => {
    try {
      console.log(
        "Telebirr callback received"
      );

      console.log(req.body);

      /*
        IMPORTANT:

        Callback data must NOT be trusted by itself.

        We will verify the transaction with the official
        Telebirr API before changing payment status to paid.
      */

      res.json({
        success: true,
        received: true
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        success: false
      });
    }
  }
);

/* =========================================================
   PAYMENT STATUS
========================================================= */

app.get(
  "/api/payment/:tx_ref",
  authenticate,
  async (req, res) => {
    try {
      const result = await pool.query(
        `
        SELECT *
        FROM payments
        WHERE tx_ref = $1
        AND user_id = $2
        `,
        [
          req.params.tx_ref,
          req.telegramUser.id
        ]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({
          success: false,
          error: "Payment not found"
        });
      }

      res.json({
        success: true,
        payment: result.rows[0]
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        success: false,
        error: "Could not load payment"
      });
    }
  }
);

/* =========================================================
   JOIN GAME
========================================================= */

app.post(
  "/api/game/join",
  authenticate,
  async (req, res) => {
    const client = await pool.connect();

    try {
      const {
        game_id,
        tx_ref
      } = req.body;

      await client.query("BEGIN");

      const payment = await client.query(
        `
        SELECT *
        FROM payments
        WHERE tx_ref = $1
        AND user_id = $2
        FOR UPDATE
        `,
        [
          tx_ref,
          req.telegramUser.id
        ]
      );

      if (payment.rows.length === 0) {
        throw new Error(
          "Payment not found"
        );
      }

      if (payment.rows[0].status !== "paid") {
        throw new Error(
          "Payment has not been verified"
        );
      }

      const existing = await client.query(
        `
        SELECT *
        FROM players
        WHERE game_id = $1
        AND user_id = $2
        `,
        [
          game_id,
          req.telegramUser.id
        ]
      );

      if (existing.rows.length > 0) {
        await client.query("COMMIT");

        return res.json({
          success: true,
          player: existing.rows[0]
        });
      }

      const gameResult = await client.query(
        `
        SELECT
          g.*,
          gt.max_players
        FROM games g
        JOIN game_types gt
        ON gt.id = g.game_type_id
        WHERE g.id = $1
        FOR UPDATE
        `,
        [game_id]
      );

      if (gameResult.rows.length === 0) {
        throw new Error(
          "Game not found"
        );
      }

      const game = gameResult.rows[0];

      if (game.status !== "waiting") {
        throw new Error(
          "Game is no longer accepting players"
        );
      }

      const playerCount = await client.query(
        `
        SELECT COUNT(*)
        FROM players
        WHERE game_id = $1
        AND payment_status = 'paid'
        `,
        [game_id]
      );

      if (
        Number(
          playerCount.rows[0].count
        ) >= game.max_players
      ) {
        throw new Error(
          "Game is full (50 players maximum)"
        );
      }

      const card =
        generateBingoCard();

      const player = await client.query(
        `
        INSERT INTO players
        (game_id, user_id, card, payment_status)
        VALUES ($1,$2,$3,'paid')
        RETURNING *
        `,
        [
          game_id,
          req.telegramUser.id,
          JSON.stringify(card)
        ]
      );

      await client.query("COMMIT");

      broadcast({
        type: "player_joined",
        game_id,
        user_id:
          String(req.telegramUser.id)
      });

      res.json({
        success: true,
        player: player.rows[0]
      });
    } catch (error) {
      await client.query("ROLLBACK");

      console.error(error);

      res.status(400).json({
        success: false,
        error: error.message
      });
    } finally {
      client.release();
    }
  }
);

/* =========================================================
   OWNER - CALL NUMBER
========================================================= */

app.post(
  "/api/owner/call-number",
  authenticate,
  requireOwner,
  async (req, res) => {
    try {
      const result = await pool.query(
        `
        SELECT *
        FROM games
        WHERE status IN ('waiting','playing')
        ORDER BY id DESC
        LIMIT 1
        `
      );

      if (result.rows.length === 0) {
        return res.status(404).json({
          success: false,
          error: "No active game"
        });
      }

      const game = result.rows[0];

      const called =
        game.called_numbers || [];

      if (called.length >= 75) {
        return res.status(400).json({
          success: false,
          error:
            "All numbers have been called"
        });
      }

      const remaining = [];

      for (let i = 1; i <= 75; i++) {
        if (!called.includes(i)) {
          remaining.push(i);
        }
      }

      const number =
        remaining[
          Math.floor(
            Math.random() *
              remaining.length
          )
        ];

      const updatedCalled = [
        ...called,
        number
      ];

      const updated =
        await pool.query(
          `
          UPDATE games
          SET
            called_numbers = $1,
            current_number = $2,
            status = 'playing',
            started_at =
              COALESCE(
                started_at,
                NOW()
              )
          WHERE id = $3
          RETURNING *
          `,
          [
            updatedCalled,
            number,
            game.id
          ]
        );

      const letter =
        getBingoLetter(number);

      const spoken =
        `${letter} ${number}`;

      broadcast({
        type: "number_called",
        game_id: game.id,
        number,
        letter,
        spoken,
        called_numbers:
          updatedCalled
      });

      res.json({
        success: true,
        number,
        letter,
        spoken,
        called_numbers:
          updatedCalled
      });

      await checkAllPlayersForWinner(
        game.id
      );
    } catch (error) {
      console.error(error);

      res.status(500).json({
        success: false,
        error:
          "Could not call number"
      });
    }
  }
);

/* =========================================================
   BINGO LETTER
========================================================= */

function getBingoLetter(number) {
  if (
    number >= 1 &&
    number <= 15
  ) {
    return "B";
  }

  if (
    number >= 16 &&
    number <= 30
  ) {
    return "I";
  }

  if (
    number >= 31 &&
    number <= 45
  ) {
    return "N";
  }

  if (
    number >= 46 &&
    number <= 60
  ) {
    return "G";
  }

  if (
    number >= 61 &&
    number <= 75
  ) {
    return "O";
  }

  return "";
}

/* =========================================================
   BINGO VALIDATION
========================================================= */

function hasBingo(
  card,
  calledNumbers
) {
  const called =
    new Set(calledNumbers);

  const marked =
    card.map((row, r) =>
      row.map((number, c) => {
        if (
          r === 2 &&
          c === 2
        ) {
          return true;
        }

        return called.has(number);
      })
    );

  /* Rows */

  for (let r = 0; r < 5; r++) {
    if (
      marked[r].every(Boolean)
    ) {
      return true;
    }
  }

  /* Columns */

  for (let c = 0; c < 5; c++) {
    let complete = true;

    for (
      let r = 0;
      r < 5;
      r++
    ) {
      if (!marked[r][c]) {
        complete = false;
        break;
      }
    }

    if (complete) {
      return true;
    }
  }

  /* Diagonal 1 */

  let diagonal1 = true;

  for (
    let i = 0;
    i < 5;
    i++
  ) {
    if (!marked[i][i]) {
      diagonal1 = false;
      break;
    }
  }

  if (diagonal1) {
    return true;
  }

  /* Diagonal 2 */

  let diagonal2 = true;

  for (
    let i = 0;
    i < 5;
    i++
  ) {
    if (
      !marked[i][4 - i]
    ) {
      diagonal2 = false;
      break;
    }
  }

  return diagonal2;
}

/* =========================================================
   WINNER CHECK
========================================================= */

async function checkAllPlayersForWinner(
  gameId
) {
  const gameResult =
    await pool.query(
      `
      SELECT *
      FROM games
      WHERE id = $1
      `,
      [gameId]
    );

  if (
    gameResult.rows.length === 0
  ) {
    return;
  }

  const game =
    gameResult.rows[0];

  if (game.winner_user_id) {
    return;
  }

  const players =
    await pool.query(
      `
      SELECT *
      FROM players
      WHERE game_id = $1
      AND payment_status = 'paid'
      ORDER BY id ASC
      `,
      [gameId]
    );

  for (
    const player of players.rows
  ) {
    let card;

    try {
      card =
        typeof player.card ===
        "string"
          ? JSON.parse(player.card)
          : player.card;
    } catch {
      continue;
    }

    if (
      hasBingo(
        card,
        game.called_numbers
      )
    ) {
      await pool.query(
        `
        UPDATE games
        SET
          winner_user_id = $1,
          status = 'finished',
          auto_call = FALSE,
          ended_at = NOW()
        WHERE id = $2
        `,
        [
          player.user_id,
          gameId
        ]
      );

      stopAutoCall();

      broadcast({
        type: "winner",
        game_id: gameId,
        user_id:
          String(player.user_id)
      });

      return;
    }
  }
}

/* =========================================================
   AUTO CALL
========================================================= */

app.post(
  "/api/owner/auto-call",
  authenticate,
  requireOwner,
  async (req, res) => {
    const enabled =
      Boolean(req.body.enabled);

    if (enabled) {
      startAutoCall();
    } else {
      stopAutoCall();
    }

    res.json({
      success: true,
      auto_call: enabled
    });
  }
);

function startAutoCall() {
  if (autoCallTimer) {
    return;
  }

  autoCallTimer =
    setInterval(
      async () => {
        if (autoCallBusy) {
          return;
        }

        autoCallBusy = true;

        try {
          const gameResult =
            await pool.query(
              `
              SELECT *
              FROM games
              WHERE status IN
              ('waiting','playing')
              ORDER BY id DESC
              LIMIT 1
              `
            );

          if (
            gameResult.rows.length ===
            0
          ) {
            stopAutoCall();
            return;
          }

          const game =
            gameResult.rows[0];

          if (
            game.winner_user_id
          ) {
            stopAutoCall();
            return;
          }

          const called =
            game.called_numbers ||
            [];

          if (
            called.length >= 75
          ) {
            stopAutoCall();
            return;
          }

          const remaining = [];

          for (
            let i = 1;
            i <= 75;
            i++
          ) {
            if (
              !called.includes(i)
            ) {
              remaining.push(i);
            }
          }

          const number =
            remaining[
              Math.floor(
                Math.random() *
                  remaining.length
              )
            ];

          const updatedCalled =
            [
              ...called,
              number
            ];

          await pool.query(
            `
            UPDATE games
            SET
              called_numbers = $1,
              current_number = $2,
              status = 'playing',
              auto_call = TRUE,
              started_at =
                COALESCE(
                  started_at,
                  NOW()
                )
            WHERE id = $3
            `,
            [
              updatedCalled,
              number,
              game.id
            ]
          );

          const letter =
            getBingoLetter(number);

          broadcast({
            type: "number_called",
            game_id: game.id,
            number,
            letter,
            spoken:
              `${letter} ${number}`,
            called_numbers:
              updatedCalled
          });

          await checkAllPlayersForWinner(
            game.id
          );
        } catch (error) {
          console.error(
            "Auto call error:",
            error.message
          );
        } finally {
          autoCallBusy = false;
        }
      },
      5000
    );
}

function stopAutoCall() {
  if (autoCallTimer) {
    clearInterval(
      autoCallTimer
    );

    autoCallTimer = null;
  }

  autoCallBusy = false;

  pool
    .query(`
      UPDATE games
      SET auto_call = FALSE
      WHERE status IN
      ('waiting','playing')
    `)
    .catch(console.error);

  broadcast({
    type: "auto_call_status",
    enabled: false
  });
}

/* =========================================================
   OWNER - RESET GAME
========================================================= */

app.post(
  "/api/owner/reset-game",
  authenticate,
  requireOwner,
  async (req, res) => {
    try {
      stopAutoCall();

      const result =
        await pool.query(
          `
          SELECT id
          FROM games
          WHERE status IN
          ('waiting','playing')
          ORDER BY id DESC
          LIMIT 1
          `
        );

      if (
        result.rows.length === 0
      ) {
        return res.json({
          success: true,
          message:
            "No active game"
        });
      }

      const gameId =
        result.rows[0].id;

      await pool.query(
        `
        UPDATE games
        SET
          status = 'finished',
          auto_call = FALSE,
          ended_at = NOW()
        WHERE id = $1
        `,
        [gameId]
      );

      broadcast({
        type: "game_reset",
        game_id: gameId
      });

      res.json({
        success: true
      });
    } catch (error) {
      console.error(error);

      res.status(500).json({
        success: false,
        error:
          "Could not reset game"
      });
    }
  }
);

/* =========================================================
   WEBSOCKET
========================================================= */

const server =
  app.listen(
    PORT,
    async () => {
      console.log(
        `🎱 Bingo Geda server running on port ${PORT}`
      );

      try {
        await initDatabase();
      } catch (error) {
        console.error(
          "Database initialization failed:",
          error.message
        );
      }
    }
  );

wss =
  new WebSocket.Server({
    server
  });

wss.on(
  "connection",
  (socket) => {
    const id =
      crypto.randomUUID();

    clients.set(
      id,
      socket
    );

    socket.send(
      JSON.stringify({
        type: "connected"
      })
    );

    socket.on(
      "message",
      async (message) => {
        try {
          const data =
            JSON.parse(
              message.toString()
            );

          if (
            data.type === "ping"
          ) {
            socket.send(
              JSON.stringify({
                type: "pong"
              })
            );
          }
        } catch {
          // Ignore invalid messages
        }
      }
    );

    socket.on(
      "close",
      () => {
        clients.delete(id);
      }
    );
  }
);

/* =========================================================
   BROADCAST
========================================================= */

function broadcast(message) {
  const data =
    JSON.stringify(message);

  for (
    const socket of clients.values()
  ) {
    if (
      socket.readyState ===
      WebSocket.OPEN
    ) {
      socket.send(data);
    }
  }
}
