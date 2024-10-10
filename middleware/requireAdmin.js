function requireAdmin(req, res, next) {
    if (req.user && req.user.Admin) {
        return next();
    } else {
        return res.status(403).send('Access denied. Admins only.');
    }
}

module.exports = requireAdmin;
