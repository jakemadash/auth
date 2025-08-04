require("dotenv").config();
const bcrypt = require("bcryptjs");
const path = require("node:path");
const { Pool } = require("pg");
const express = require("express");
const session = require("express-session");
const pgSession = require("connect-pg-simple")(session);
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const { body, validationResult } = require("express-validator");

const pool = new Pool({
  host: process.env.DB_HOST,
  user: process.env.DB_USERNAME,
  database: process.env.DB_NAME,
  password: process.env.DB_PASS,
  port: process.env.DB_PORT,
});

const app = express();
app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");

app.use(
  session({
    store: new pgSession({
      pool: pool,
      tableName: "session",
    }),
    secret: "secret",
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 30 * 24 * 60 * 60 * 1000 }, // 30 days
  })
);
app.use(passport.initialize());
app.use(passport.session());

app.use(express.urlencoded({ extended: false }));

app.use((req, res, next) => {
  res.locals.currentUser = req.user;
  next();
});

app.get("/", (req, res) => {
  res.render("index");
});

app.get("/sign-up", (req, res) =>
  res.render("sign-up-form", { errors: [], formData: {} })
);

app.post(
  "/sign-up",
  body("confirm_password").custom((value, { req }) => {
    if (value !== req.body.password) {
      throw new Error("Passwords do not match");
    }
    return true;
  }),
  async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).render("sign-up-form", {
        errors: errors.array(),
        formData: req.body,
      });
    }

    const { first_name, last_name, email, password } = req.body;
    try {
      const hashedPassword = await bcrypt.hash(password, 10);
      await pool.query(
        "INSERT INTO users (first_name, last_name, email, password_hash) VALUES ($1, $2, $3, $4)",
        [first_name, last_name, email, hashedPassword]
      );
      res.redirect("/");
    } catch (error) {
      console.error(error);
      next(error);
    }
  }
);

app.post(
  "/log-in",
  passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/",
  })
);

app.get("/log-out", (req, res, next) => {
  req.logout((err) => {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

app.post("/membership", async (req, res, next) => {
  const { secret_code } = req.body;

  if (secret_code === "cubular") {
    try {
      await pool.query(
        "UPDATE users SET membership_status = 'member' WHERE id = $1",
        [req.user.id]
      );
      res.redirect("/");
    } catch (err) {
      next(err);
    }
  } else {
    res.status(401).send("Invalid secret code");
  }
});

app.post("/messages", async (req, res, next) => {
  const { title, message } = req.body;
  const user_id = req.user.id;

  try {
    await pool.query(
      "INSERT INTO messages (title, body, user_id) VALUES ($1, $2, $3)",
      [title, message, user_id]
    );
    res.redirect("/");
  } catch (err) {
    next(err);
  }
});

app.listen(3000, () => console.log("app listening on port 3000!"));

passport.use(
  new LocalStrategy(
    { usernameField: "email" },
    async (email, password, done) => {
      try {
        const { rows } = await pool.query(
          "SELECT * FROM users WHERE email = $1",
          [email]
        );
        const user = rows[0];

        if (!user) {
          return done(null, false, { message: "Incorrect email" });
        }

        const match = bcrypt.compare(password, user.password_hash);
        if (!match) {
          return done(null, false, { message: "Incorrect password" });
        }

        return done(null, user);
      } catch (err) {
        return done(err);
      }
    }
  )
);

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const { rows } = await pool.query("SELECT * FROM users WHERE id = $1", [
      id,
    ]);
    const user = rows[0];

    done(null, user);
  } catch (err) {
    done(err);
  }
});
