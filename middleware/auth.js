const db = require('../config/sql');

async function requireLogin(req, res, next) {
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
            'SELECT FullName, UserID FROM Users WHERE UserID = ?',
            [session[0].UserID]
        );

        if (!user.length) {
            console.log('User not found for this session');
            return res.redirect('/login');
        }

        req.user = {
            UserID: user[0].UserID,
            FullName: user[0].FullName
        };

        console.log(`User authenticated: ${JSON.stringify(req.user)}`);
        next();
    } catch (error) {
        console.error('Authentication Error:', error);
        return res.status(500).send('Internal Server Error');
    }
}

module.exports = requireLogin;
