/// <reference path="./env.d.ts" />
import 'dotenv/config';
import mongoose, { Schema } from 'mongoose';
import express from 'express';
import session from 'express-session';
import passport from 'passport';
import { Strategy as LocalStrategy } from 'passport-local';
import path from 'path';
import asyncHandler from 'express-async-handler';
import { body } from 'express-validator';

const mongoDb = process.env.MONGODB_CONNECT_STRING;
const port = process.env.PORT ?? 3000;
const hostname = process.env.HOSTNAME ?? 'localhost';

mongoose.connect(mongoDb!);
const db = mongoose.connection;
db.on("error", console.error.bind(console, "mongo connection error"));

const User = mongoose.model(
  "User",
  new Schema({
    username: { type: String, required: true },
    password: { type: String, required: true }
  })
);

const app = express();
app.set("views", path.join(__dirname, 'views'));
app.set("view engine", "ejs");

app.use(session({ secret: "cats", resave: false, saveUninitialized: true }));

passport.use(
  new LocalStrategy(async (username, password, done) => {
    try {
      const user = await User.findOne({ username: username });
      if (!user) {
        return done(null, false, { message: "Incorrect username" });
      };
      if (user.password !== password) {
        return done(null, false, { message: "Incorrect password" });
      };
      return done(null, user);
    } catch (err) {
      return done(err);
    };
  })
);

passport.serializeUser((user, done) => {
  done(null, (user as unknown as { id: string }).id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err);
  };
});

app.use(passport.initialize());
app.use(passport.session());
app.use(express.urlencoded({ extended: false }));

app.get("/", (req, res) => res.render("index"));
app.get("/sign-up", (req, res) => res.render("sign-up-form"));
app.post("/sign-up", [
  // Validate and sanitize inputs
  body('username')
    .isLength({ min: 3, max: 100 })
    .withMessage('Username must be 3-100 characters long.')
    .escape(),
  body('password')
    .isLength({ min: 8, max: 30 })
    .withMessage('Password must be 8-30 characters long.')
    .escape(),

  // Process request after validation and sanitization
  asyncHandler(async (req, res, next) => {
    const user = new User({
      username: req.body.username,
      password: req.body.password
    });
    await user.save();
    res.redirect("/");
  })
]);

app.listen(port, () => console.log(`Server running on http://${hostname}:${port}/`));