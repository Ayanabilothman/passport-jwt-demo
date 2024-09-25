import express from "express";
import passport from "passport";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import dotenv from "dotenv";
import { Strategy, ExtractJwt } from "passport-jwt";
dotenv.config();

const app = express();

// User data (in a real app, use a database)
const users = [
  {
    id: 1,
    username: "user",
    password: "$2a$12$TCy/vHRFGvsqBTd/sAR6KeCDGuEXeHYDgPlLDR55G1Zn6QImrjdY.",
  },
];

app.use(express.json());

// JWT strategy options
const opts = {
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  secretOrKey: process.env.JWT_KEY,
};

passport.use(
  new Strategy(opts, (jwt_payload, done) => {
    const user = users.find((u) => u.id === jwt_payload.id);
    if (user) {
      return done(null, user);
    }
    return done(null, false);
  })
);

// Routes
app.post("/login", (req, res) => {
  const { username, password } = req.body;
  const user = users.find((u) => u.username === username);

  if (!user) {
    return res.status(401).json({ message: "Incorrect username or password" });
  }

  bcrypt.compare(password, user.password, (err, isMatch) => {
    if (err) throw err;
    if (isMatch) {
      const token = jwt.sign(
        { id: user.id, username: user.username },
        opts.secretOrKey
      );

      return res.json({ token });
    } else {
      return res
        .status(401)
        .json({ message: "Incorrect username or password" });
    }
  });
});

app.get(
  "/protected",
  passport.authenticate("jwt", { session: false }),
  (req, res) => {
    res.json({
      message: "You have accessed a protected route!",
      user: req.user,
    });
  }
);

app.listen(3000, () => {
  console.log("Server running on port 3000");
});
