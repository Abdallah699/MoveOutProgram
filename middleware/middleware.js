module.exports.isAuthenticated = async (req, res, next) => {
    const sessionToken = req.cookies.sessionToken;
    if (!sessionToken) {
        return res.redirect('/login');
    }

    const [session] = await db.query('SELECT * FROM Sessions WHERE SessionToken = ? AND ExpiresAt > NOW()', [sessionToken]);
    if (!session) {
        return res.redirect('/login');
    }

    req.user = session.UserID;
    next();
};
