const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const LocalStrategy = require('passport-local').Strategy;
const { findOrCreateUserByGoogleId, loginUser, createConnection } = require('../src/cli');
require('dotenv').config();

passport.serializeUser((user, done) => {
    console.log('Serializing user with UserID:', user.UserID);
    done(null, user.UserID);
  });

passport.deserializeUser(async (id, done) => {
    try {
      const connection = await createConnection();
      const [user] = await connection.query('SELECT * FROM Users WHERE UserID = ?', [id]);
      connection.end();
  
      if (user.length > 0) {
        const deserializedUser = user[0];
        console.log('Deserializing user:', deserializedUser);
  
        done(null, deserializedUser); // Pass the full user object
      } else {
        done(new Error('User not found in the database'), null);
      }
    } catch (err) {
      console.error('Error during deserialization:', err);
      done(err, null);
    }
  });

  passport.use(new LocalStrategy({
    usernameField: 'email',
    passwordField: 'password'
  }, async (email, password, done) => {
    try {
      const result = await loginUser(email, password);
  
      if (result.success) {
        console.log('Local strategy: User authenticated:', result.user);
        return done(null, result.user);
      } else {
        return done(null, false, { message: result.message });
      }
    } catch (err) {
      console.error('Error in local strategy:', err);
      return done(err);
    }
  }));

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:1339/auth/google/callback"
}, async function(accessToken, refreshToken, profile, done) {
    try {
        console.log('Received Google profile:', profile);

        const user = await findOrCreateUserByGoogleId(profile);

        console.log('Google OAuth: User found or created:', user);

        return done(null, user);
    } catch (err) {
        console.error('Error during Google OAuth authentication:', err);
        return done(err, null);
    }
}));

module.exports = passport;
