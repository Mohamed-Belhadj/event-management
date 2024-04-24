import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy } from "passport-local";
import session from "express-session";
import env from "dotenv";

const app = express();
const port = 3000;
const saltRounds = process.env.SALT_ROUNDS;
env.config();

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    // cookie: {
    //     maxAge: 1000 * 60 * 60 * 24,
    // },
  })
);

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(passport.initialize());
app.use(passport.session());

const db = new pg.Client({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT,
});
db.connect();

//*********************************************** GET REQUESTS ************************************* */

app.get("/", (req, res) => {
    res.send("home Page");
});

app.get("/evento-admins/login", (req, res) => {
    res.render("login.ejs");
});

app.get("/evento-admins/register", (req, res) => {
    res.send("register page");
  });

app.get("/logout", (req, res) => {
    req.logout(function (err) {
      if (err) {
        return next(err);
      }
      res.redirect("/evento-admins/login");
    });
});

app.get("/evento-admins/dashboard", (req, res) => {
console.log(req.user);
if (req.isAuthenticated()) {
    res.send("dashboard page");
} else {
    res.redirect("/evento-admins/login");
}
});


//*********************************************** POST REQUESTS ************************************* */

app.post(
    "/login",
    passport.authenticate("local", {
        successRedirect: "/evento-admins/dashboard",
        failureRedirect: "/evento-admins/login",
    })
);

app.post("/register", async (req, res) => {
    const email = req.body.username;
    const password = req.body.password;
  
    try {
      const checkResult = await db.query("SELECT * FROM member WHERE email = $1", [
        email,
      ]);
  
      if (checkResult.rows.length > 0) {
        req.redirect("/evento-admins/login");
      } else {
        bcrypt.hash(password, saltRounds, async (err, hash) => {
          if (err) {
            console.error("Error hashing password:", err);
          } else {
            const result = await db.query(
              "INSERT INTO member (email, password) VALUES ($1, $2) RETURNING *",
              [email, hash]
            );
            const user = result.rows[0];
            req.login(user, (err) => {
              console.log("success");
              res.redirect("/evento-admins/login");
            });
          }
        });
      }
    } catch (err) {
      console.log(err);
    }
});

passport.use(
    "local",
    new Strategy(async function verify(username, password, cb) {
      try {
        const result = await db.query("SELECT * FROM member WHERE email = $1 ", [
          username,
        ]);
        if (result.rows.length > 0) {
          const user = result.rows[0];
          const storedHashedPassword = user.password;
          bcrypt.compare(password, storedHashedPassword, (err, valid) => {
            if (err) {
              //Error with password check
              console.error("Error comparing passwords:", err);
              return cb(err);
            } else {
              if (valid) {
                //Passed password check
                return cb(null, user);
              } else {
                //Did not pass password check
                return cb(null, false);
              }
            }
          });
        } else {
          return cb("User not found");
        }
      } catch (err) {
        console.log(err);
      }
    })
);

app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});