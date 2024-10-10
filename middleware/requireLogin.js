const db = require('../config/sql');

async function requireLogin(req, res, next) {
    if (req.isAuthenticated()) {
        console.log('Authenticated via Passport.');
        
        if (req.user.GoogleID || req.user.EmailVerified) {
            return next();
        } else {
            console.log('User is not verified.');
            return res.redirect("/verify-notice");
        }
    }

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

        const [user] = await db.query(
            'SELECT FullName, UserID, Email, EmailVerified, GoogleID, ProfilePicture, Username FROM Users WHERE UserID = ?',
            [session[0].UserID]
        );

        if (!user.length) {
            console.log('User not found for this session');
            return res.redirect('/login');
        }

        const userData = user[0];

        if (!userData.EmailVerified && !userData.GoogleID) {
            console.log('User is authenticated but not verified, redirecting to verify notice');
            return res.redirect('/verify-notice');
        }

        req.user = {
            UserID: userData.UserID,
            FullName: userData.FullName,
            Email: userData.Email, 
            EmailVerified: userData.EmailVerified,
            GoogleID: userData.GoogleID,
            ProfilePicture: userData.ProfilePicture || '/uploads/profile_pictures/default.png', 
            Username: userData.Username
        };

        console.log(`User authenticated: ${JSON.stringify(req.user)}`);
        next(); 
    } catch (error) {
        console.error('Authentication Error:', error);
        return res.status(500).send('Internal Server Error');
    }
}

module.exports = requireLogin;
