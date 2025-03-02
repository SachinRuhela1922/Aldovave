require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const session = require('express-session');
const MongoStore = require('connect-mongo');
const path = require('path');
const bcrypt = require('bcryptjs');

const app = express();

// Middleware
app.use(express.json());
app.use(session({
  secret: process.env.SESSION_SECRET || 'X7kP9mQvL3tR8wF2nJ5sY4bZ6cA1dH0gT',
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({ mongoUrl: process.env.MONGO_URI }),
  cookie: { secure: process.env.NODE_ENV === 'production', maxAge: 24 * 60 * 60 * 1000 }
}));
app.use(passport.initialize());
app.use(passport.session());
app.use(express.static(path.join(__dirname, 'public')));

// MongoDB Connection
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB connection error:', err));

// User Schema for storing email/password
const UserSchema = new mongoose.Schema({
  email: { type: String, unique: true, required: true },
  password: String, // Hashed password for local users
  googleId: String // For Google auth users
});
const User = mongoose.model('User', UserSchema);

// Passport Configuration
passport.use(new LocalStrategy(
  async (email, password, done) => {
    try {
      const user = await User.findOne({ email });
      if (!user) return done(null, false, { message: 'Incorrect email.' });
      if (!user.password) return done(null, false, { message: 'Use Google login instead.' });
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) return done(null, false, { message: 'Incorrect password.' });
      return done(null, user);
    } catch (err) {
      return done(err);
    }
  }
));

require('./config/passport'); // Google strategy still configured here

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err);
  }
});

// Routes
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html'))); // Updated to serve index.html
app.get('/signup.html', (req, res) => res.sendFile(path.join(__dirname, 'public', 'signup.html')));
app.get('/login.html', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));

app.get('/auth/google',
    passport.authenticate('google', { 
      scope: ['profile', 'email'],
      prompt: 'select_account' // Forces account selection every time
    })
  );

app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/' }), // Redirects to index.html on failure
  (req, res) => {
    
    res.redirect('/profile.html');
  }
);

app.post('/signup', async (req, res) => {
  const { email, password } = req.body;
  try {
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).send('User already exists');
    
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ email, password: hashedPassword });
    await user.save();

    // Create user-specific collection on signup
    const collectionName = email.replace(/[^a-zA-Z0-9]/g, '_');
    const userCollectionSchema = new mongoose.Schema({
      hello: String,
      title: String,
      description: String,
      createdAt: { type: Date, default: Date.now }
    }, { collection: collectionName });
    const UserCollection = mongoose.model(collectionName, userCollectionSchema);
    await new UserCollection({
      hello: 'Welcome to your collection!',
      title: 'Welcome',
      description: 'Your first entry'
    }).save();

    req.login(user, (err) => {
      if (err) return res.status(500).send('Login error');
      res.status(201).send();
    });
  } catch (err) {
    res.status(500).send('Signup error: ' + err.message);
  }
});

app.post('/login', passport.authenticate('local', { failureRedirect: '/' }), // Redirects to index.html on failure
async (req, res) => {
  const email = req.user.email;
  const collectionName = email.replace(/[^a-zA-Z0-9]/g, '_');
  
  try {
    const collections = await mongoose.connection.db.listCollections({ name: collectionName }).toArray();
    if (collections.length === 0) {
      const userCollectionSchema = new mongoose.Schema({
        hello: String,
        title: String,
        description: String,
        createdAt: { type: Date, default: Date.now }
      }, { collection: collectionName });
      const UserCollection = mongoose.model(collectionName, userCollectionSchema);
      await new UserCollection({
        hello: 'Welcome to your collection!',
        title: 'Welcome',
        description: 'Your first entry'
      }).save();
    }
    res.status(200).send();
  } catch (err) {
    res.status(500).send('Login error: ' + err.message);
  }
});

app.get('/profile.html', (req, res) => {
  if (!req.isAuthenticated()) return res.redirect('/login.html'); // Redirects to index.html if not authenticated
  res.sendFile(path.join(__dirname, 'public', 'profile.html'));
});

app.get('/profile', async (req, res) => {
  if (!req.isAuthenticated()) return res.status(401).json({ error: 'Unauthorized' });

  const email = req.user.email;
  const collectionName = email.replace(/[^a-zA-Z0-9]/g, '_');
  
  try {
    let UserCollection;
    if (mongoose.models[collectionName]) {
      UserCollection = mongoose.models[collectionName];
    } else {
      const userCollectionSchema = new mongoose.Schema({
        hello: String,
        title: String,
        description: String,
        createdAt: { type: Date, default: Date.now }
      }, { collection: collectionName });
      UserCollection = mongoose.model(collectionName, userCollectionSchema);
    }

    const collectionData = await UserCollection.find();
    res.json({
      user: { email: req.user.email },
      collectionData: collectionData
    });
  } catch (err) {
    console.error('Error fetching collection data:', err);
    res.status(500).json({ error: 'Error fetching collection data', details: err.message });
  }
});

app.post('/add-data', async (req, res) => {
  if (!req.isAuthenticated()) return res.status(401).json({ error: 'Unauthorized' });

  const email = req.user.email;
  const collectionName = email.replace(/[^a-zA-Z0-9]/g, '_');
  const { hello, title, description } = req.body;

  if (!hello || !title || !description) return res.status(400).json({ error: 'All fields are required' });

  try {
    let UserCollection;
    if (mongoose.models[collectionName]) {
      UserCollection = mongoose.models[collectionName];
    } else {
      const userCollectionSchema = new mongoose.Schema({
        hello: String,
        title: String,
        description: String,
        createdAt: { type: Date, default: Date.now }
      }, { collection: collectionName });
      UserCollection = mongoose.model(collectionName, userCollectionSchema);
    }

    const newEntry = new UserCollection({ hello, title, description });
    await newEntry.save();
    res.status(201).json({ message: 'Data added successfully' });
  } catch (err) {
    console.error('Error adding data:', err);
    res.status(500).json({ error: 'Error adding data', details: err.message });
  }
});

app.get('/logout', (req, res) => {
  req.logout(() => res.redirect('/')); // Redirects to index.html after logout
});

// Start Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));