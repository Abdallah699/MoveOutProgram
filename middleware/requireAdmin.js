function requireAdmin(req, res, next) {
    console.log("Checking admin access...");

    if (req.isAuthenticated() && req.user) {
        console.log("User session found:", req.user);
        
        if (req.user.AdminLevel >= 2) {  // Ensure that AdminLevel is being checked
            console.log("User is an admin. Proceeding to the next middleware...");
            return next();  // User is an admin
        } else {
            console.log("User is not an admin. Access denied.");
            return res.status(403).send("Access denied. Admins only.");
        }
    } else {
        console.log("No user session found. Access denied.");
        return res.status(403).send("Access denied. No session found.");
    }
}

module.exports = requireAdmin;

