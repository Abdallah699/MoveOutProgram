const db = require('../config/sql');

async function requireLogin(req, res, next) {
    // Check if the user is authenticated via Passport (Google login)
    if (req.isAuthenticated()) {
        console.log('Authenticated via Passport.');
        
        // If logged in via Google, or email is verified, proceed
        if (req.user.GoogleID || req.user.EmailVerified) {
            return next();
        } else {
            console.log('User is not verified.');
            return res.redirect("/verify-notice");
        }
    }

    // If not authenticated via Passport, fall back to session token
    const sessionToken = req.cookies.sessionToken;
    console.log(`Session token from cookie: ${sessionToken}`);

    if (!sessionToken) {
        console.log('No session token found, redirecting to login');
        return res.redirect('/login');
    }

    try {
        const [session] = await db.query(
            'SELECT * FROM Sessions WHERE SessionToken = ? AND ExpiresAt > NOW()',
            [sessionToken]
        );

        if (!session.length) {
            console.log('No active session found or session expired');
            return res.redirect('/login');
        }

        console.log(`Session found: ${JSON.stringify(session[0])}`);

        // Fetch user data including Email
        const [user] = await db.query(
            'SELECT FullName, UserID, Email, EmailVerified, GoogleID, ProfilePicture, Username FROM Users WHERE UserID = ?',
            [session[0].UserID]
        );

        if (!user.length) {
            console.log('User not found for this session');
            return res.redirect('/login');
        }

        const userData = user[0];

        // Check if the user is verified (either via Google login or email verification)
        if (!userData.EmailVerified && !userData.GoogleID) {
            console.log('User is authenticated but not verified, redirecting to verify notice');
            return res.redirect('/verify-notice');
        }

        // Attach user info to the request object, including ProfilePicture, Username, and Email
        req.user = {
            UserID: userData.UserID,
            FullName: userData.FullName,
            Email: userData.Email,  // Added Email field
            EmailVerified: userData.EmailVerified,
            GoogleID: userData.GoogleID,
            ProfilePicture: userData.ProfilePicture || '/uploads/profile_pictures/default.png',  // Default if no profile picture
            Username: userData.Username
        };

        console.log(`User authenticated: ${JSON.stringify(req.user)}`);
        next(); // Proceed to the next middleware or route handler
    } catch (error) {
        console.error('Authentication Error:', error);
        return res.status(500).send('Internal Server Error');
    }
}

module.exports = requireLogin;
