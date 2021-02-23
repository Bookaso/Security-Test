require('dotenv').config()
const express = require("express");
const ejs = require("ejs");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const session = require('express-session');
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');
const FacebookStrategy = require("passport-facebook").Strategy;

const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({extended:true}));

app.use(session({
  secret:"Keep secret from you.",
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB",{ useNewUrlParser: true, useUnifiedTopology: true });
mongoose.set('useCreateIndex', true);

const userSChema = new mongoose.Schema ({
  email: String,
  password: String,
  googleId: String,
  facebookId: String,
  secret: String
});

userSChema.plugin(passportLocalMongoose);
userSChema.plugin(findOrCreate);

const User = new mongoose.model("User", userSChema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

//Configure Strategy for google
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));
//Configure Strategy for facebook
passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/",function(req,res){
  res.render("home");
});
//Authenticate Requests for google
app.get("/auth/google",
  passport.authenticate("google",{ scope: ["profile"] })
);

app.get("/auth/google/secrets",
  passport.authenticate("google", {failureRedirect: "/login" }),
  function(req,res){
    //Successful authenticate, redirect to secret
    res.redirect("/secrets");
  });

//Authenticate Requests for facebook
app.get("/auth/facebook",
  passport.authenticate("facebook"));

app.get("/auth/facebook/secrets",
  passport.authenticate("facebook", {failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect secrets.
    res.redirect("/secrets");
  });

app.route("/login")
.get(function(req,res){
  res.render("login");
})
.post(function(req,res){
  const user = new User({
    username: req.body.username,
    password: req.body.password
  });

  req.login(user,function(err){
    if (err) {
      console.log(err);
    } else {
      passport.authenticate("local")(req,res,function(){
          res.redirect("/secrets");
        });
    }
  })

});

app.route("/register")
.get(function(req,res){
  res.render("register");
})
.post(function(req,res){

User.register({username: req.body.username}, req.body.password,function(err,user){
  if (err) {
    console.log(err);
    res.redirect("/register");
  } else {
    passport.authenticate("local")(req,res,function(){
        res.redirect("/secrets");
    });
  }
});

});

app.route("/secrets")
.get(function(req,res){
  User.find({"secret": {$ne:null}}, function(err,found){
    if (err) {
      console.log(err);
    } else {
      if (found) {
        res.render("secrets",{userWithSecrets:found})
      }
    }
  });
});

app.route("/submit")
.get(function(req,res){
  if (req.isAuthenticated()) {
    res.render("submit");
  } else {
    res.redirect("/login");
  }
})
.post(function(req,res){
  const submitSecret = req.body.secret;

  User.findById(req.user._id,function(err,found){
    if (err) {
      console.log(err);
    } else {
      if (found) {
        found.secret = submitSecret;
        found.save();
        res.redirect("/secrets");
      };
    }
  });
});

app.route("/logout")
.get(function(req,res){
  req.logout();
  res.redirect("/");
});

app.listen(3000,()=>{
  console.log("Server running at port 3000");
});
