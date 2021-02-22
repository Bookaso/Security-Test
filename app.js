require('dotenv').config()
const express = require("express");
const ejs = require("ejs");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const md5 = require("md5");

const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({extended:true}));

mongoose.connect("mongodb://localhost:27017/userDB",{ useNewUrlParser: true, useUnifiedTopology: true });

const userSChema = new mongoose.Schema ({
  email: String,
  password: String
});


const User = new mongoose.model("User", userSChema);

app.get("/",function(req,res){
  res.render("home");
});

app.route("/login")
.get(function(req,res){
  res.render("login");
})
.post(function(req,res){
  const username = req.body.username;
  const password = md5(req.body.password);
    User.findOne({email: username},function(err,foundUser){
      if (err) {
        console.log(err);
      } else {
        if (foundUser) {
          if (foundUser.password === password) {
              res.render("secrets");
          } else {
            console.log("Password incorrect.");
          }
        } else {
          console.log("This E-mail are not register.");
        }
      }
    });
})

app.route("/register")
.get(function(req,res){
  res.render("register");
})
.post(function(req,res){
  const newUser = new User({
    email: req.body.username,
    password: md5(req.body.password)
  })
  newUser.save((err)=>{
    if (err) {
      console.log(err);
    } else {
      res.render("secrets");
    }
  });
})




app.listen(3000,()=>{
  console.log("Server running at port 3000");
});
