const express = require("express");
const app = express();
const routes = require("./routes/routes.js");
const cookieParser = require('cookie-parser');
const session = require('express-session');
const passport = require('passport');
const path = require('path');  // <-- Add this line to import the 'path' module

app.use(express.static("public"));
app.use('/uploads', express.static('public/uploads'));
app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

app.use(session({
    secret: 'your_secret_key',
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

app.use((req, res, next) => {
    res.locals.isAuthenticated = !!req.user; 
    res.locals.user = req.user || null; 
    next();
});

app.use("/", routes);

const port = 1339;
app.listen(port, () => {
    console.log(`Server is listening on port: ${port}`);
});
