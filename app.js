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

app.use(passport.initialize()); //initialize passport package and use it to manage our sessions 
app.use(passport.session());//use passport to deal with our sessions 
 
mongoose.connect(process.env.MONGODB_URI);

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

passport.use(User.createStrategy());//create local login strategy using passport-local-mongoose ie. using user specified username and password

// passport.serializeUser(User.serializeUser()); //stuffs data inside cookie
// passport.deserializeUser(User.deserializeUser()); //destroys cookie after 
passport.serializeUser(function(user, cb) { //stuffs data inside cookie 
    process.nextTick(function() {
      cb(null, { id: user.id, username: user.username, name: user.name });
    });
  });
  
  passport.deserializeUser(function(user, cb) { //destroys cookie after 
    process.nextTick(function() {
      return cb(null, user);
    });
  });
passport.use(new GoogleStrategy({ //create google login strategy using passport-google-oauth20 
    clientID:process.env.GCLIENT_ID, //client id and secret are provided by google
    clientSecret:process.env.GCLIENT_SECRET,  //client id and secret are provided by google
    callbackURL: "http://localhost:3000/auth/google/secrets", //callback url is the url where google will redirect the user after authentication
    scope:['profile'], //scope is the information that we want to access from the user's google account
    state:true //state is used to prevent cross-site request forgery attacks 
  },
  function(accessToken, refreshToken, profile, cb) { // this function is called when the user is authenticated by google
    User.findOrCreate({ googleId: profile.id }, function (err, user) { //findOrCreate is a function provided by mongoose-findorcreate package used to find or create a new user in the database
      return cb(err, user); //cb is a callback function that is called after the user is authenticated by google and the user is found or created in the database 
    });
  }
));
passport.use(new GitHubStrategy({ //create github login strategy using passport-github 
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
    app.post("/register", function(req, res) { //register route for registering a new user 
        User.register({ username: req.body.username }, req.body.password, function(err, user) { //register is a function provided by passport-local-mongoose package used to register a new user in the database
          if (err) {
            console.log(err);
            res.redirect("/register"); //redirect to register page if there is an error
          } else {
            passport.authenticate("local")(req, res, function() {
              res.redirect("/secrets"); //redirect to secrets page if the user is successfully registered
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

app.post("/login",function(req,res){ //login route for logging in an existing user
    const user=new User({ //create a new user object using the username and password provided by the user
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
    }); //login is a function provided by passport-local-mongoose package used to login an existing user
    
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
app.get("/auth/google", //google login route 
passport.authenticate('google',{scope:["profile"]})  //scope is the information that we want to access from the user's google account 
);
app.get("/auth/google/secrets", 
passport.authenticate('google',{failureRedirect:'/login'}),function(req,res){ //this function is called when the user is authenticated by google
    //successfully logged in
    res.redirect("/secrets");
}
);
app.get('/auth/github',
  passport.authenticate('github'));

app.get('/auth/github/secrets', 
  passport.authenticate('github', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect secrets.
    res.redirect('/secrets');
  });
app.get("/login",function(req,res){ //login route for logging in an existing user
    res.render("login");
});
app.get("/register",function(req,res){ //register route for registering a new user using the register.ejs file 
    res.render("register");
});
app.get("/secrets",function(req,res){ //secrets route for displaying the secrets page
    User.find({"secret":{$ne:null}}).then(function(usersfound){
        // console.log(usersfound);
        res.render("secrets",{userWithSecrets:usersfound}); //render the secrets page and pass the usersfound array to the secrets.ejs file
    }).catch(function(err){
        console.log(err); 
    });
});
app.get("/submit",function(req,res){
    if(req.isAuthenticated()){
        res.render("submit"); //render the submit page if the user is authenticated
    }
    else{
        res.redirect("/login"); //redirect to the login page if the user is not authenticated
    }
});
app.post("/submit",function(req, res) {
    if (!req.isAuthenticated()) { //check if the user is authenticated
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
         foundUser.secret = submittedSecret; //add the submitted secret to the user's secret field in the database but only secret is possible in one profile
        foundUser.save().then(function() { // save the user's secret to the database
          res.redirect("/secrets");
        }).catch(function(err){
            console.log(err); //handle the error
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

app.listen(process.env.PORT||3000, function(){
    console.log("Server started on port 3000.");
});