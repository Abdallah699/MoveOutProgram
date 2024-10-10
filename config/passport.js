const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const { findOrCreateUserByGoogleId } = require('../src/cli');
require('dotenv').config();

// Serialize user into the session
passport.serializeUser(function(user, done) {
    console.log('Serializing user with UserID:', user.UserID);  // Log UserID for debugging
    done(null, user.UserID);  // Store only the UserID in the session
});

// Deserialize user from the session
passport.deserializeUser(async function(id, done) {
    try {
        const connection = await require('../src/cli').createConnection();
        const [user] = await connection.query('SELECT * FROM Users WHERE UserID = ?', [id]);
        connection.end();

        if (user.length > 0) {
            const deserializedUser = user[0];
            console.log('Deserializing user:', deserializedUser);

            // If Google ID exists, skip password checks
            if (deserializedUser.GoogleID) {
                console.log('Google user detected, skipping password checks.');
                return done(null, deserializedUser);
            }

            // Check for email verification and password validity for non-Google users
            if (deserializedUser.EmailVerified && deserializedUser.PasswordHash !== '0') {
                return done(null, deserializedUser);
            } else {
                return done(new Error('User is not verified or password is not set'), null);
            }
        } else {
            return done(new Error('User not found in the database'), null);
        }
    } catch (err) {
        console.error('Error during deserialization:', err);
        return done(err, null);
    }
});

// Use Google OAuth strategy
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:1339/auth/google/callback"  // Adjust this based on your deployment
},
async function(accessToken, refreshToken, profile, done) {
    try {
        // Log the incoming profile from Google OAuth
        console.log('Received Google profile:', profile);

        // Find or create the user based on Google ID
        const user = await findOrCreateUserByGoogleId(profile);

        // Log the user object that is being returned
        console.log('Google OAuth: User found or created:', user);

        return done(null, user);
    } catch (err) {
        console.error('Error during Google OAuth authentication:', err);
        return done(err, null);
    }
}));

module.exports = passport;
