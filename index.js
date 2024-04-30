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

app.get("/evento-admins/dashboard", async(req, res) => {
console.log(req.user);
// if (req.isAuthenticated()) {
  try{
    const event = await db.query("SELECT * FROM event WHERE id = 2");
    const eventSpeackers = await db.query("SELECT s.first_name,s.last_name,s.expertise FROM speacker s INNER JOIN event_speacker_details esd ON s.id = esd.speacker_id INNER JOIN event e ON e.id = $1",[event.rows[0].id]);
    const eventAttendants = await db.query("SELECT a.first_name, a.last_name, a.email, ear.status FROM attendant a INNER JOIN event_attendant_registration ear ON a.id = ear.attendant_id INNER JOIN event e ON e.id = $1",[event.rows[0].id]);
    const eventInfo = {
      event: event.rows[0],
      eventSpeackers: eventSpeackers.rows,
      eventAttendants: eventAttendants.rows
    }
    console.log(eventInfo);
    res.render("dashboard.ejs");

  }catch(err){
    console.log(err);
  }
// } else {
//     res.redirect("/evento-admins/login");
// }
});

app.get('/evento-admins/attendant-list', async(req,res) => {
  try{
    const attendants = await db.query("SELECT * FROM attendant");;

    console.log(attendants.rows);
    res.json(attendants.rows);
  }catch(err){
    console.log(err);
  }
});

app.get('/evento-admins/speacker-list', async(req,res) => {
  try{
    const speackers = await db.query("SELECT * FROM speacker");
    
    console.log(speackers.rows);
    res.json(speackers.rows);
  }catch(err){
    console.log(err);
  }
});

app.get('/evento-admins/ressource-list', async(req,res) => {
  try{
    const ressources = await db.query("SELECT * FROM ressource");
    
    console.log(ressources.rows);
    res.json(ressources.rows);
  }catch(err){
    console.log(err);
  }
});

app.get('/evento-admins/event-details/id=:id', async(req,res) => {
  try{
    const {title,id} = req.params
    const event = await db.query("SELECT * FROM event WHERE id = $1",[id]);
    const eventSpeackers = await db.query("SELECT s.first_name,s.last_name,s.expertise FROM speacker s INNER JOIN event_speacker_details esd ON s.id = esd.speacker_id INNER JOIN event e ON e.id = $1",[id]);
    const eventAttendants = await db.query("SELECT a.first_name, a.last_name, a.email, ear.status FROM attendant a INNER JOIN event_attendant_registration ear ON a.id = ear.attendant_id INNER JOIN event e ON e.id = $1",[id]);
    const eventSponsors = await db.query("SELECT es.amount, s.name as sponsor, s.email as sponsor_email FROM event_sponsorship es INNER JOIN event e ON es.event_id = $1 INNER JOIN sponsor s ON s.id = es.sponsor_id",[id]);
    const eventInfo = {
      event: event.rows[0],
      speackers: eventSpeackers.rows,
      attendants: eventAttendants.rows,
      sponosors: eventSponsors.rows
    }
    console.log(eventInfo);
    res.json(eventInfo);
  }catch(err){
    console.log(err);
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