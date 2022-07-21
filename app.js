// Node Modules
const express = require("express");
const cookieParser = require("cookie-parser");
const bodyParser = require("body-parser");
const session = require("express-session");
const flash = require("express-flash");
const passport = require("passport");
const { pool } = require("./dbCon");
const bcrypt = require("bcrypt");

const initializePassport = require("./passportCon");

initializePassport(passport);

const app = express();
const port = 3000;

// user express-ejs=layouts
const expressLayouts = require("express-ejs-layouts");
app.use(expressLayouts);
app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: false }));
app.use(
  session({
    secret: "secret",
    resave: false,
    saveUninitialized: false,
  })
);
app.use(passport.initialize());
app.use(passport.session());


// Static File
// User Static File (Build in middleware)
app.use(express.static("public"));
app.use(express.urlencoded({
  extended: true
}));

app.use(flash());

// Index (Home) Page
app.get("/", checkAuthenticated, (req, res) => {
  res.render("loginPage", {
    title: "Webserver EJS",
    layout: "layouts/login-layout",
  });
});

// User Session
app.get("/users/dashboard", checkNotAuthenticated, (req, res) => {
  res.render("dashboard", {
    title: "Dashboard",
    layout: "layouts/main-layout",
    username: req.user.username,
    userRole: req.user.role,
  });
});

// Add User
app.get("/users/addUser", checkNotAuthenticated, (req, res) => {
  res.render("addUser", {
    title: "Add User",
    layout: "layouts/main-layout",
  });
});

app.get("/users/logout", (req, res, next) => {
  req.logout(function (err){
    if (err) {return next(err)}
    req.flash("success", "User logged out")
    res.redirect('/')
  });
});

app.post(
  "/users/login",
  passport.authenticate("local", {
    successRedirect: "/users/dashboard",
    failureRedirect: "/",
    failureFlash: true,
    successFlash: true,
  })
);

app.post("/users/addUser", async (req, res) => {
  const { username, password, role, password2 } = req.body;

  console.log({
    username,
    password,
    role,
  });

  const errors = [];

  if (password.length < 6) {
    errors.push({ message: "Password must be at least 6 characters" });
  }
  if (password !== password2) {
    errors.push({ message: "Password does not match" });
  }
  if (role === undefined) {
    errors.push({ message: "Please select a role" });
  }

  if (errors.length > 0) {
    res.render("addUser", {
      errors,
      layout: "layouts/main-layout",
      title: "Add User",
      params: req.body,
    });
  } else {
    const hashedPassword = await bcrypt.hash(password, 10);
    console.log(hashedPassword);

    pool.query(
      `SELECT * FROM users WHERE username = $1`,
      [username],
      (err, results) => {
        if (err) {
          throw err;
        }
        console.log(results.rows);

        if (results.rows.length > 0) {
          errors.push({ message: "Username already in use" });
          res.render("AddUser", {
            errors,
            layout: "layouts/main-layout",
            title: "Add User",
            params: req.body,
          });
        } else {
          const name = username.toLowerCase();
          pool.query(
            `INSERT INTO users (username, password, role) VALUES ($1, $2, $3) RETURNING id, password`,
            [name, hashedPassword, role],
            (err, result) => {
              if (err) {
              }
              console.log(result.rows);
              req.flash("success", "Successfully created a new user");
              res.redirect("/users/dashboard");
            }
          );
        }
      }
    );
  }
});

app.use("/", (req, res) => {
  res.status(404);
  res.send("404 Not Found");
});


function checkAuthenticated(req, res, next) {
  if(req.isAuthenticated()) {
    return res.redirect('/users/dashboard')
  }   
  next()
}


function checkNotAuthenticated(req, res, next) {
  if(req.isAuthenticated()){
    return next()
  }
  res.redirect('/')
}

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});
