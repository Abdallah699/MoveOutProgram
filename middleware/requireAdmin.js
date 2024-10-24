function requireAdmin(req, res, next) {
    console.log("Checking admin access...");
    console.log("Current user data:", req.user);
  
    if (req.isAuthenticated() && req.user) {
      if (req.user.AdminLevel >= 1) {
        console.log("User is an admin. Proceeding to the next middleware...");
        return next();
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
  