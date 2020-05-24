const express = require("express");
const exphbs = require("express-handlebars");
const bodyParser = require("body-parser");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const flash = require("connect-flash");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const mongoose = require("mongoose");
const { ensureAuthenticated } = require("./helpers/auth");

mongoose.connect(
  "mongodb+srv://admin-abhishek:abhishek@cluster0-voopf.mongodb.net/loginDB",
  {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  }
);

const loginSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
  },
  email: {
    type: String,
    required: true,
  },
  password: {
    type: String,
    required: true,
  },
});

const User = mongoose.model("User", loginSchema);

passport.use(
  new LocalStrategy({ usernameField: "email" }, function (
    email,
    password,
    done
  ) {
    User.findOne({ email: email }, function (err, user) {
      if (err) {
        return done(err);
      }
      if (!user) {
        return done(null, false, { message: "User Not Found!" });
      }

      // Match Password
      bcrypt.compare(password, user.password).then((res) => {
        if (!res) {
          return done(null, false, { message: "Incorrect Password!" });
        } else {
          return done(null, user);
        }
      });
    });
  })
);

passport.serializeUser(function (user, done) {
  done(null, user.id);
});

passport.deserializeUser(function (id, done) {
  User.findById(id, function (err, user) {
    done(err, user);
  });
});

const app = express();

app.use(express.static("public"));
app.use(session({ resave: true, saveUninitialized: true, secret: "cats" }));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(passport.initialize());
app.use(passport.session());
app.use(flash());

app.use((req, res, next) => {
  res.locals.success_msg = req.flash("success_msg");
  res.locals.error_msg = req.flash("error_msg");
  res.locals.error = req.flash("error");
  res.locals.user = req.user || null;
  next();
});

app.engine("handlebars", exphbs());
app.set("view engine", "handlebars");

// Get Route

app.get("/", (req, res) => {
  res.render("sign_in");
});

app.get("/sign_up", (req, res) => {
  res.render("sign_up");
});

app.get("/index", ensureAuthenticated, (req, res) => {
  res.render("index");
});

app.get("/logout", (req, res) => {
  req.logout();
  req.flash("success_msg", "You are logged out");
  res.redirect("/");
});

// Post Route

app.post("/sign_up", (req, res) => {
  // Custom Validation
  const errors = [];

  if (req.body.password1 != req.body.password2) {
    errors.push("Anything");
  }
  if (req.body.password1.length < 4) {
    errors.push("Anything");
  }

  if (errors.length > 0) {
    req.flash(
      "error_msg",
      "Password should be atleast 4 characters and should be same!"
    );
    res.render("sign_up", {
      name: req.body.name,
      email: req.body.email,
    });
  } else {
    const newUser = {
      name: req.body.name,
      email: req.body.email,
      password: req.body.password1,
    };

    User.findOne({ email: req.body.email }).then((user) => {
      if (user) {
        req.flash("error_msg", "Email Already Exist");
        res.redirect("/sign_up");
      } else {
        // Encrypt Password
        bcrypt.genSalt(10, function (err, salt) {
          bcrypt.hash(newUser.password, salt, function (err, hash) {
            if (err) {
              res.send(err);
            } else {
              newUser.password = hash;
              new User(newUser).save().then((user) => {
                req.flash("success_msg", "Successfully Registered!");
                res.redirect("/");
              });
            }
          });
        });
      }
    });
  }
});

app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/index",
    failureRedirect: "/",
    failureFlash: true,
  })
);

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`The server is running on PORT: ${PORT}`);
});
