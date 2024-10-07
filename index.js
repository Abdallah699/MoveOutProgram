const express = require("express");
const app = express();
const routes = require("./routes/routes.js");
const cookieParser = require('cookie-parser');
const session = require('express-session');
const passport = require('passport');

app.use(express.static("public"));
app.use('/uploads', express.static('public/uploads'));
app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
// app.use(express.static('public'));

// kir

app.use(session({
    secret: 'your_secret_key',
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

app.use((req, res, next) => {
    res.locals.isAuthenticated = !!req.user; // Set isAuthenticated flag based on req.user presence
    res.locals.user = req.user || null; // Set user object if it exists
    next();
});



// Routes
app.use("/", routes);

const port = 1339;
app.listen(port, () => {
    console.log(`Server is listening on port: ${port}`);
});
