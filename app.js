//jshint esversion:6
require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs=require("ejs");
const mongoose=require("mongoose");
//in this particular chronology
//1.
const session = require('express-session')
//2.
const passport=require('passport');
//3.
const passportLocalMongoose=require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FindOrCreate=require("mongoose-findorcreate");
const GitHubStrategy = require('passport-github').Strategy;
// const bcrypt=require('bcrypt');
//const saltround=10; //more we increase this number harder my computer even to generate the hashes   
// const md5=require('md5');

// const encrypt=require("mongoose-encryption") //using hash function md5 method we can encode the password and store the hash value in the database
const app = express();

// console.log(process.env.SECRET);
app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({extended: true}));

//initialize sessions before connecting mongodb and definitely before we use 'session'
app.use(session({
    secret:"little secret",
    resave:false,
    saveUninitialized:false
}));

app.use(passport.initialize());
app.use(passport.session());
 
mongoose.connect("mongodb+srv://AK78:Vinayak8158@cluster0.euxh9ex.mongodb.net/userDB");

const userSchema=new mongoose.Schema({
    email:String,
    password:String,
    googleId:String,
    githubId:String,
    secret:String
});
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(FindOrCreate);

// userSchema.plugin(encrypt, {secret:process.env.SECRET, encryptedFields:["password"] });
const User=mongoose.model("user",userSchema);

passport.use(User.createStrategy());
// passport.serializeUser(User.serializeUser()); //stuffs data inside cookie
// passport.deserializeUser(User.deserializeUser()); //destroys cookie after 
passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
      cb(null, { id: user.id, username: user.username, name: user.name });
    });
  });
  
  passport.deserializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, user);
    });
  });
passport.use(new GoogleStrategy({
    clientID:process.env.GCLIENT_ID,
    clientSecret:process.env.GCLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    scope:['profile'],
    state:true
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));
passport.use(new GitHubStrategy({
    clientID: process.env.GITCLIENT_ID,
    clientSecret: process.env.GITCLIENT_SECRET,
    callbackURL: "http://127.0.0.1:3000/auth/github/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ githubId: profile.id }, function (err, user) {
        
      return cb(err, user);
    });
  }
));

app.post("/register",function(req,res){
    app.post("/register", function(req, res) {
        User.register({ username: req.body.username }, req.body.password, function(err, user) {
          if (err) {
            console.log(err);
            res.redirect("/register");
          } else {
            passport.authenticate("local")(req, res, function() {
              res.redirect("/secrets");
            });
          }
        });
      });
    // bcrypt.hash(req.body.password, saltround).then(function(hash){
    //     const newUser=new User
    //     ({
    //         email:req.body.username,
    //         password:hash
    //     });
    //     newUser.save().then(function()
    //     {
    //         res.render("secrets");
    //     }).catch(function(err){
    //     console.log(err);
 
    // }).catch(function(err){
    //     console.log(err);
    // });
    // });
    
});

app.post("/login",function(req,res){
    const user=new User({
      username:req.body.username,
      password:req.body.password

    });
    req.login(user,function(err,users){
        if(err){
            console.log(err);
        }
        else{
            passport.authenticate("local")(req,res,function(){
                res.redirect("/secrets");
                // In the provided code snippet, passport.authenticate("local") is a middleware function provided by Passport.js. It is used for authenticating user credentials using the "local" strategy, which typically involves checking the username and password against a local database.
                // Here's how the code works:
                // 1. When this middleware is invoked, it checks the user credentials (username and password) submitted in the request body against the local strategy.
                //2. If the credentials are valid, Passport.js sets up a session for the authenticated user, storing the user's information in the session.
                // 3.If the credentials are invalid, Passport.js will handle the authentication failure and return an appropriate response.
            });
        
        }
    });
    
    // const Username= req.body.username;
    // const Password= req.body.password;

    // User.findOne({"email":Username}).then(function(foundUser)
    // {
    //     // console.log(foundUser);
    //    bcrypt.compare(Password, foundUser.password).then(function(result){
    //     if(result===true){
    //         res.render("secrets");
    //     }
    //     else{
    //         res.send("<h1 class='centered'>Wrong password, Homie</h1>");
    //     }
    //    }).catch(function(err){
    //    console.log(err);
    //    });
       
    // });
});

app.get("/",function(req,res){
    res.render("home");
});
app.get("/auth/google",
passport.authenticate('google',{scope:["profile"]}) 
);
app.get("/auth/google/secrets",
passport.authenticate('google',{failureRedirect:'/login'}),function(req,res){
    //successfully logged in
    res.redirect("/secrets");
}
);
app.get('/auth/github',
  passport.authenticate('github'));

app.get('/auth/github/secrets', 
  passport.authenticate('github', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });
app.get("/login",function(req,res){
    res.render("login");
});
app.get("/register",function(req,res){
    res.render("register");
});
app.get("/secrets",function(req,res){
    User.find({"secret":{$ne:null}}).then(function(usersfound){
        // console.log(usersfound);
        res.render("secrets",{userWithSecrets:usersfound});
    }).catch(function(err){
        console.log(err);
    });
});
app.get("/submit",function(req,res){
    if(req.isAuthenticated()){
        res.render("submit");
    }
    else{
        res.redirect("/login");
    }
});
app.post("/submit",function(req, res) {
    if (!req.isAuthenticated()) {
        // User is not authenticated, redirect to the login page or handle the error
        res.redirect("/login");
        return;
    }

    const submittedSecret = req.body.secret;
    if (!submittedSecret) {
        // Handle the case when the submitted secret is empty
        res.redirect("/submit");
        return;
    }
    User.findById(req.user.id).then( function(foundUser) 
    {
        // console.log(foundUser);
         foundUser.secret = submittedSecret;
        foundUser.save().then(function() {
          res.redirect("/secrets");
        }).catch(function(err){
            console.log(err)
        });
    
    
    }).catch(function(err){
        console.log(err);
        res.redirect("/submit");
    })

  });
 
  
  
  
  
  
  
  
app.get("/logout",function(req,res){
    req.logout(function(err){ //req.logout() is not a synchronous function anymore it requires a callback function now
        if(err){
            console.log(err);
        }
        res.redirect("/");
    });
    
});

app.listen(3000, function(){
    console.log("Server started on port 3000.");
});