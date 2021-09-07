	const express			    = require('express');
const session			    = require('express-session');
const ejs				      = require('ejs');
const mongoose		    = require('mongoose');
const passport			  = require('passport');
const localStrategy		= require('passport-local').Strategy;
const bcrypt			    = require('bcrypt');
const app				      = express();
const flash           = require("connect-flash");
const passportLocalMongoose = require("passport-local-mongoose");




// Middleware

app.set('view engine', 'ejs');
app.use(express.static(__dirname + '/public/'));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());


// Config Express Session

app.use(session({
    secret: "My little secret.",
    resave: false,
    saveUninitialized: true
}));

//Initialize Passport Session

app.use(passport.initialize());
app.use(passport.session());

//Connect Flash
app.use(flash());

//Connect to MongoDB
mongoose.connect("mongodb://localhost:27017/userDB", {
	useNewUrlParser: true,
	useUnifiedTopology: true
});

// Create Schema
const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true
  },
  email: {
    type: String,
    required: true,
   
  },
  password: {
    type: String,
    required: true
  },
  date: {
    type: Date,
    default: Date.now
  }
});


//Create Mongoose Model and Serilizer User
const User = new mongoose.model("User",userSchema);

passport.serializeUser(function (user, done) {
	done(null, user.id);
});

passport.deserializeUser(function (id, done) {
	User.findById(id, function (err, user) {
		done(err, user);
	});
});


// Global Vars
app.use(function (req,res,next) {
    res.locals.success_msg = req.flash("success_msg");
    res.locals.error_msg = req.flash("error_msg");
    next();
});

//Config Passport Authentication
passport.use(new localStrategy({
  usernameField: "email",
  passwordField: "password"
},
  function (email, password, done) {
	User.findOne({ email: email }, function (err, user) {
		if (err) return done(err);
		if (!user) return done(null, false, { message: 'Incorrect username.' });


		bcrypt.compare(password, user.password, function (err, res) {
			if (err) return done(err);
			if (res === false) return done(null, false, { message: 'Incorrect password.' });
			
			return done(null, user);
		});
	});
}));



// ROUTES
app.get('/',  (req, res) => {
	res.render("index");
});



app.get("/dashboard",function (req,res) {
     if(req.isAuthenticated()){
       res.render("dashboard",{user: req.user});
   }else{
       res.redirect("/login");
   }
});

app.get('/register', (req, res) => {
	res.render("register");
});


app.get("/login", function (req,res) {
    res.render("login");
});


// Register
app.post('/register', (req, res) => {
  const { name, email, password, password2 } = req.body;
  let errors = [];

  if (!name || !email || !password || !password2) {
    errors.push({ msg: 'Please enter all fields' });
  }

  if (password != password2) {
    errors.push({ msg: 'Passwords do not match' });
  }

  if (password.length < 6) {
    errors.push({ msg: 'Password must be at least 6 characters' });
  }

  if (errors.length > 0) {
    res.render('register', {
      errors,
      name,
      email,
      password,
      password2
    });
  } else {
    User.findOne({ email: email }).then(user => {
      if (user) {
        errors.push({ msg: 'Email already exists' });
        res.render('register', {
          errors,
          name,
          email,
          password,
          password2
        });
      } else {
        const newUser = new User({
          name,
          email,
          password
        });

        bcrypt.genSalt(10, (err, salt) => {
          bcrypt.hash(newUser.password, salt, (err, hash) => {
            if (err) throw err;
            newUser.password = hash;
            newUser
              .save()
              .then(user => {
                req.flash(
                  'success_msg',
                  'You are now registered and can log in'
                );
                res.redirect('/login');
              })
              .catch(err => console.log(err));
          });
        });
      }
    });
  }
});


// Login
app.post('/login', (req, res, next) => {
  passport.authenticate('local', {
    successRedirect: '/dashboard',
    failureRedirect: '/login',
    failureFlash: req.flash("error_msg","Invaild email or password.")
	  })(req, res, next);
});


  

// Logout
app.get('/logout', (req, res) => {
  req.logout();
  req.flash('success_msg', 'You are logged out');
  res.redirect('/login');
});




app.listen(3000, () => {
	console.log("Listening on port 3000");
});
