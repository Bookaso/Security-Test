require('dotenv').config()
const express = require("express");
const ejs = require("ejs");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const saltRounds = 10;

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
  const password = req.body.password;

   User.findOne({email: username},function(err,foundUser){
     if (err) {
       console.log(err);
     } else {
       if (foundUser) {
         //to check password in DB using compare(input,hash from DB)
         bcrypt.compare(password,foundUser.password,function(err,hash){
           if (hash) {
               res.render("secrets");
           } else {
             console.log("Password incorrect.");
           }
         });
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
  //to generate salt hash
  bcrypt.hash(req.body.password,saltRounds,function(err,hash){
    const newUser = new User({
      email: req.body.username,
      password: hash
    })
    newUser.save((err)=>{
      if (err) {
        console.log(err);
      } else {
        res.render("secrets");
      }
    });
  });

})




app.listen(3000,()=>{
  console.log("Server running at port 3000");
});
