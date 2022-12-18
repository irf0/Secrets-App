//jshint esversion:6
require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs')
const path = require("path");
const mongoose = require('mongoose');
// const encrypt = require('mongoose-encryption'); //Lvl.2
// const md5 = require('md5') //Lvl.3
// const bcrypt = require('bcrypt') //Lvl.4
// const saltRounds = 10
const  session  = require('express-session');
const passport = require('passport'); //Lvl.5
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');


const app = express();

app.use(express.static(path.join(__dirname, 'public')))
app.engine('ejs', require('ejs').renderFile)
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'))
app.use(bodyParser.urlencoded({extended:true}));

app.use(session({
    secret: "This is my little secret",
    resave:false,
    saveUninitialized:false
}));
app.use(passport.initialize());
app.use(passport.session());

//Google OAuth
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL:"https://www.googleapis.com/oauth2/v3/userinfo" //Just bcs Google+ is now deprecated
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

mongoose.connect("mongodb://localhost:27017/userDB");

//Creating User Schema
const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId:String,
    secret:String

});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

//Creating User Model
const User = new mongoose.model("User", userSchema);
passport.use(User.createStrategy());

passport.serializeUser(function(user, done){
    done(null, user.id);
});
passport.deserializeUser(function(id, done){
    User.findById(id, function(err, user){
        done(err, user)
    })
});


//Home page
app.get("/", (req, res)=>{
    res.render("home")
});

//Google Auth page
app.get("/auth/google",
  passport.authenticate('google', { scope:["profile"] }
));

app.get("/auth/google/secrets",
passport.authenticate('google', {failureRedirect:"/login"}),
function(req, res){
    res.redirect("/secrets")
}
);

//Login page
app.get("/login", (req, res)=>{
    res.render("login")
});

//Register page
app.get("/register", (req, res)=>{
    res.render("register")
});

//Secrets page - render only if the user is in a logged in session
app.get("/secrets", (req, res)=>{
    User.find({"secret":{$ne:null}}, function(err, foundUsers){
        if(err){
            console.log(err)
        }
        else{
            if(foundUsers){
                res.render("secrets", {usersWithSecrets:foundUsers})
            }
        }
    })
});
app.get("/logout", (req, res)=>{
    req.logOut(function(err){
        if(err){
            console.log(err)
        }
    });
    res.redirect("/")
});

//Post request in /register page with email and password
app.post("/register", (req, res)=>{
    User.register({username:req.body.username}, req.body.password, function(err, user){
        if(err){
            console.log(err)
            res.redirect("/register")
        }
        else{
            passport.authenticate("local")(req, res, function(){
                res.redirect("/secrets");
                //Here we're using "/secrets" route to directly serve the secrets page if the user is in a logged session without needing to re-register.

            })
        }
    })
})
//Post request in /login page with already existing email and password.
app.post("/login", (req ,res)=>{
  const user = new User({
    username:req.body.username,
    password:req.body.password
  });
  req.login(user, function(err){
    if(err){
        console.log(err)
    }
    else{
        passport.authenticate("local")(req, res, function(){
            res.redirect("/secrets")
        })
    }
  })
});

//Letting users submit their secret and save the secrets into the DB.
app.get("/submit", (req, res)=>{
    if(req.isAuthenticated()){
        res.render("submit")
    }
    else{
        res.redirect("/login")
    }
    
});
app.post("/submit", (req, res)=>{
    const submittedSecret = req.body.secret;
    User.findById(req.user.id, function(err, foundUser){
        if(err){
            console.log(err)
        }
        else{
            if(foundUser){
              foundUser.secret = submittedSecret
              foundUser.save(function(){
                res.redirect("/secrets")
              });
            }
        }
    });
});

app.listen(3000,()=>{
    console.log("Server is running on port 3000");
})