
const db = require('../config/sql');

async function attachUser(req, res, next) {
    const sessionToken = req.cookies.sessionToken;

    if (sessionToken) {
        try {
            const [session] = await db.query(
                'SELECT * FROM Sessions WHERE SessionToken = ? AND ExpiresAt > NOW()',
                [sessionToken]
            );

            if (session.length) {
                const [user] = await db.query(
                    'SELECT FullName, UserID FROM Users WHERE UserID = ?',
                    [session[0].UserID]
                );

                if (user.length) {
                    req.user = {
                        UserID: user[0].UserID,
                        FullName: user[0].FullName
                    };
                    console.log('User attached:', req.user);
                }
            }
        } catch (error) {
            console.error('Error in attachUser middleware:', error);
        }
    }
    next();
}

module.exports = attachUser;
