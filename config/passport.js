const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const mongoose = require('mongoose');
const User = mongoose.model('User'); // Assuming User model is defined in server.js

passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: '/auth/google/callback' // Fallback if not set in .env
}, async (accessToken, refreshToken, profile, done) => {
  try {
    let user = await User.findOne({ googleId: profile.id });

    if (!user) {
      // Check if user exists with this email from another method (e.g., local signup)
      user = await User.findOne({ email: profile.emails[0].value });
      if (!user) {
        // New user via Google
        user = new User({
          googleId: profile.id,
          email: profile.emails[0].value
        });
        await user.save();
      } else {
        // Existing user, link Google ID
        user.googleId = profile.id;
        await user.save();
      }

      // Create user-specific collection
      const collectionName = user.email.replace(/[^a-zA-Z0-9]/g, '_');
      const collections = await mongoose.connection.db.listCollections({ name: collectionName }).toArray();
      
      if (collections.length === 0) {
        await mongoose.connection.db.createCollection(collectionName);
        
        const userCollectionSchema = new mongoose.Schema({
          hello: String,
          title: String,
          description: String,
          createdAt: { type: Date, default: Date.now }
        }, { collection: collectionName });

        const UserCollection = mongoose.models[collectionName] || mongoose.model(collectionName, userCollectionSchema);
        await new UserCollection({
          hello: 'Welcome to your collection!',
          title: 'Welcome',
          description: 'Your first entry'
        }).save();
      }
    }

    return done(null, user);
  } catch (err) {
    console.error('Error in Google Strategy:', err);
    return done(err, null);
  }
}));

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    console.error('Error in deserializeUser:', err);
    done(err, null);
  }
});

module.exports = passport;