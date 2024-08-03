const express = require('express');
const serverless=require('serverless-http');
const mongoose = require('mongoose');
const path = require('path');
const bodyParser = require("body-parser");
const cors = require("cors");
const _ = require("lodash");
const sanitizeHtml = require('sanitize-html'); // Import sanitize-html
const multer = require('multer');
const { type } = require("os");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');
const MongoStore = require('connect-mongo');
const app = express();
const router= express.Router();

mongoose.connect('mongodb+srv://saifullah22044:Test123@cluster0.svl6zpm.mongodb.net/blog_and_logins')
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => {
    console.error('Could not connect to MongoDB:', err);
    process.exit(1);  // Exit process if connection fails
  });

app.get('/favicon.ico', (req, res) => res.status(204).end());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');
app.get('/favicon.ico', (req, res) => res.status(204).end());
app.use(session({
  secret: 'your_secret_key',
  resave: false,
  saveUninitialized: true,
  cookie: {
    maxAge: 3300000 // 5 minutes
  },
  store: MongoStore.create({
    mongoUrl: 'mongodb+srv://saifullah22044:Test123@cluster0.svl6zpm.mongodb.net/sessions',
    autoRemove: 'interval',
    autoRemoveInterval: 10
  }),
  rolling: false
}));
const listSchema = new mongoose.Schema({
  name: String,
  content: String,
  isPublic: Boolean,
  author: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  image: {
    data: Buffer,
    content: String
  }, // Field to indicate visibility
  comments: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Comment'
  }],
  likes: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }]
});

// Create the Blog model
const Blog = mongoose.models.Blog || mongoose.model('Blog', listSchema);
const Storage = multer.diskStorage({
  destination: 'upload',
  filename: (req, file, cb) => {
    cb(null, file.originalname)
  }
});
const upload = multer({ storage: Storage }).single('testImage');
const commentSchema = new mongoose.Schema({
  author: String,
  comment: String
});

const Comment = mongoose.models.Comment || mongoose.model('Comment', commentSchema);
// Sample default item
const defaultItems = [];

// Insert default items into the database
Blog.insertMany(defaultItems);
app.options("", cors({
  origin: "*",
  methods: ["POST", "GET", "DELETE", "PUT"],
  credentials: true
}));

app.use(cors({
  origin: "*",
  methods: ["POST", "GET", "DELETE", "PUT"],
  credentials: true
}));

app.use(passport.initialize());
app.use(passport.session());

// Update the user schema to include the name field
const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  name: String // Add this field to store the user's name
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);
const User = mongoose.models.User || mongoose.model('User', userSchema);

passport.use(User.createStrategy());
passport.serializeUser(function (user, done) {
  done(null, user.id);
});

passport.deserializeUser(async function (id, done) {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err, null);
  }
});

passport.use(new GoogleStrategy({
  clientID: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
  callbackURL: "http://localhost:3000/auth/google/secrets",
  userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
},
  function (accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

// Use a helper function to pass isAuthenticated status to views
function renderWithAuthStatus(req, res, view, options = {}) {
  res.render(view, { isAuthenticated: req.isAuthenticated(), ...options });
}
router.use((req, res, next) => {
  if (!req.session.createdAt) {
    req.session.createdAt = new Date();
    // console.log(`Session created at: ${req.session.createdAt}`);
    // console.log(`Session will expire in: ${req.session.cookie.maxAge / 60000} minutes`);
  }
  next();
});

// Log session access
router.use((req, res, next) => {
  // console.log(`Session accessed at: ${new Date()}`);
  // console.log(`Session data: `, req.session);
  next();
});

// Protected route example
router.get('/protected', (req, res) => {
  if (!req.isAuthenticated()) {
    console.log('Session expired or not authenticated.');
    return res.redirect('/login');
  }
  res.send('This is a protected route');
});

router.get("/home", function (req, res) {
  renderWithAuthStatus(req, res, "home");
});

router.get("/login", function (req, res) {
  renderWithAuthStatus(req, res, "login");
});

router.get("/about", function (req, res) {
  renderWithAuthStatus(req, res, "about");
});

router.get('/logout', function (req, res, next) {
  req.logout(function (err) {
    if (err) { return next(err); }
    res.redirect('/');
  });
});

router.get("/register", function (req, res) {
  renderWithAuthStatus(req, res, "register");
});

router.get("/auth/google", passport.authenticate("google", { scope: ['profile'] }));
router.get("/auth/google/secrets", passport.authenticate("google", { failureRedirect: "/login" }), function (req, res) {
  res.redirect("/submitarticle"); // Change it to where you want to go
});

router.get("/submitarticle", function (req, res) {
  if (req.isAuthenticated()) {
    renderWithAuthStatus(req, res, "submitarticle");
  } else {
    res.redirect("/login");
  }
});

router.get("/account", function (req, res) {
  if (req.isAuthenticated()) {
    // Assuming your User model has fields for username, name, and email
    const user = req.user; // This should contain the authenticated user's details
    renderWithAuthStatus(req, res, "account", {
      username: user.username,
      fname: user.name || '', // Correctly access the 'name' field
      email: user.email
    });
  } else {
    res.redirect("/login");
  }
});

router.post("/register", function (req, res) {
  const id = req.body.username;
  const pass = req.body.password;
  const name = req.body.name; // Get the name from the request

  User.register({ username: id, name: name }, pass) // Store the name during registration
    .then((foundUser) => {
      passport.authenticate("local")(req, res, function () {
        res.redirect("/submitarticle");
      });
    })
    .catch(err => {
      console.error(err);
      res.redirect("/register");
    });
});

router.post("/login", function (req, res) {
  const id = req.body.username;
  const pass = req.body.password;
  const user = new User({
    username: id,
    password: pass
  });

  req.login(user, function (err) {
    if (err) {
      console.log(err);
      res.redirect("/login");
    } else {
      passport.authenticate("local", {
        successRedirect: "/submitarticle",
        failureRedirect: "/login"
      })(req, res);
    }
  });
});
const today = new Date();
const day = today.getDate();
const month = today.getMonth() + 1; // Months are zero-based
const year = today.getFullYear();



router.get('/blog', function (req, res) {
  Blog.find({ isPublic: true }) // Only retrieve public articles
    .then(foundItems => {
      if (foundItems.length === 0) {
        Blog.insertMany(defaultItems)
          .then(() => res.redirect("/blog"))
          .catch(err => console.error(err));
      } else {
        res.render("article", {
          Titles: foundItems,
          Content: foundItems,
          buttonTitle: foundItems,
          date: day,
          month: month,
          years: year
        });
      }
    })
    .catch(err => console.error(err));
});

router.get('/all-blogs', function (req, res) {
  Blog.find({})
    .then(blogs => {
      // Log all blog entries
      res.json(blogs); // Return blogs as JSON for debugging
    })
    .catch(err => {
      console.error('Error fetching blogs:', err);
      res.status(500).send('Error fetching blogs');
    });
});

function renderWithAuthStatus(req, res, view, data = {}) {
  res.render(view, { ...data, isAuthenticated: req.isAuthenticated() });
}

router.get("/viewingarticles", function (req, res) {
  if (req.isAuthenticated()) {
    Blog.find({ author: req.user._id })
      .then(articles => {
        renderWithAuthStatus(req, res, "viewingarticles", { articles });
      })
      .catch(err => console.error(err));
  } else {
    res.redirect("/login");
  }
});

router.get("/:postName", function (req, res) {
  const requestedTitle = req.params.postName;
  console.log("Requested Title:", requestedTitle);

  Blog.findOne({ name: { $regex: new RegExp(`^${requestedTitle}$`, 'i') } }).populate('comments') // Case-insensitive search
    .then(item => {
      if (item) {
        console.log("Article Found:", item);
        res.render("viewarticle", {
          Titles: [item],
          date: day,
          month: month,
          years: year,
        });
      } else {
        console.log("Post not found");
        res.status(404).send("Post not found");
      }
    })
    .catch(err => {
      console.error("Error finding post:", err);
      res.status(500).send("Internal server error");
    });
});


router.post('/submitarticle', function (req, res) {
  const itemName = req.body.blogTitle;

  // Sanitize the content before saving it to the database
  const sanitizedContent = sanitizeHtml(req.body.content, {
    allowedTags: ['b', 'i', 'em', 'strong', 'a', 'p', 'ul', 'ol', 'li'],
    allowedAttributes: {
      'a': ['href']
    }
  });

  const visibility = req.body.visibility;
  console.log(sanitizedContent);

  const isPublic = visibility === "public";
  const item = new Blog({
    name: itemName,
    content: sanitizedContent, // Use sanitized content
    isPublic: isPublic,
    author: req.user._id
  });

  item.save()
    .then(() => res.redirect("/blog"))
    .catch(err => console.error(err));
});
router.post("/blog/:id/comments", function (req, res) {
  if (req.isAuthenticated()) {
    const user = req.user;
    // console.log(req.params.id);
    // console.log(req.body.comment);
    const comment = new Comment({
      author: user.username,
      comment: req.body.comment
    });
    comment.save()
      .then((result) => {
        console.log('Saved Comment:', result);
        Blog.findById(req.params.id)
          .then((blogs) => {
            console.log(blogs.comments);
            blogs.comments.push(result);
            blogs.save();
            console.log("==comments==");
            console.log(blogs.comments);
            res.redirect('/');
          })
          .catch(err => console.error(err));
      })
      .catch(err => console.error(err));;

  }
  else { res.redirect("/login"); }
});
router.post("/like", function (req, res) {
  if (req.isAuthenticated()) {
    Blog.findByIdAndUpdate(
      req.body.postId,
      { $addToSet: { likes: req.user._id } }, // Use $addToSet to avoid duplicates
      { new: true }
    )
      .then(result => {
        console.log('Article liked successfully');
        res.redirect("/blog");
      })
      .catch(err => {
        console.log(err);
        res.status(500).send('Internal Server Error');
      });
  } else { res.redirect("/login"); }
});

router.post("/unlike", function (req, res) {
  if (req.isAuthenticated()) {
    Blog.findByIdAndUpdate(
      req.body.postId,
      { $pull: { likes: req.user._id } },
      { new: true }
    )
      .then(result => {
        console.log('Article unliked successfully');
        res.redirect("/blog");
      })
      .catch(err => {
        console.log(err);
        res.status(500).send('Internal Server Error');
      });
  } else { res.redirect("/login"); }
});
// Error handling middleware
router.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send('Something broke!');
});
// const port = process.env.PORT || 3000;
// router.listen(port, function() {
//   console.log("Server has started running on port " + port);
// });

router.get("/",(req,res)=>{
  res.send("App is running..");
});
app.use("/.netlify/functions/api", router);
module.exports.handler = serverless(app);