const express = require("express");
const router = express.Router();
const bcrypt = require("bcrypt");  // <-- Add this line
const {
    registerUser,
    verifyEmail,
    loginUser,
    createLabel,
    getUserLabels,
    createConnection,
    findOrCreateUserByGoogleId,
    hashPassword
} = require("../src/cli.js");
const requireLogin = require("../middleware/requireLogin");
const { canViewLabel } = require('../middleware/permissions');
const fs = require('fs');
const path = require('path');
const multer = require('multer');
const QRCode = require('qrcode');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
require('dotenv').config();
const { sendPasswordResetConfirmation } = require('../src/cli');
const requireAdmin = require('../middleware/requireAdmin');


// Rest of your routes.js code...


const passport = require('passport');
require('../config/passport');

const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        if (file.fieldname === 'profilePicture') {
            cb(null, path.join(__dirname, '../public/uploads/profile_pictures'));
        } else {
            cb(null, path.join(__dirname, '../public/uploads'));
        }
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + '-' + file.originalname);
    }
});


const upload = multer({
    storage: storage,
    fileFilter: (req, file, cb) => {
        // Validate file types
        if (file.fieldname === 'profilePicture' || file.fieldname === 'contentImages') {
            if (!file.mimetype.match(/image\/(jpeg|png|gif|bmp)/)) {
                return cb(new Error('Only image files are allowed!'), false);
            }
        }
        if (file.fieldname === 'contentAudio') {
            if (!file.mimetype.match(/audio\/(mpeg|ogg|wav)/)) {
                return cb(new Error('Only audio files are allowed!'), false);
            }
        }
        cb(null, true);
    }
});

// Email transporter setup
const transporter = nodemailer.createTransport({
    service: "Gmail",
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

router.get("/login", (req, res) => {
    const verified = req.query.verified === "true";
    const message = verified ? "Email verified, you can log in now." : null;
    res.render("move_out/pages/login.ejs", { title: "Login", message, errorMessage: null });
});

// Registration route
router.get("/register", (req, res) => {
    res.render("move_out/pages/register.ejs", { title: "Register", errorMessage: null });
});

router.post("/register", async (req, res) => {
    const { email, password, fullName } = req.body;
    const result = await registerUser(email, password, fullName);

    console.log('Register User Result:', result);  // Log registration result

    if (result.success) {
        // Redirect to the verify page after successful registration
        console.log(`Redirecting to verification for email: ${email}`);  // Log the redirection
        return res.redirect(`/verify?email=${encodeURIComponent(email)}`);
    }

    // Render registration page with error message if failed
    res.status(400).render("move_out/pages/register.ejs", {
        errorMessage: result.message,
        title: "Register"
    });
});




router.get("/verify", (req, res) => {
    const email = req.query.email;
    res.render("move_out/pages/verify.ejs", { title: "Verify Email", email });
});


router.post("/verify-code", async (req, res) => {
    const { email, verificationCode } = req.body;
    const result = await verifyEmail(email, verificationCode);

    if (result.success) {
        return res.redirect(`/login?verified=true`);
    }

    // Re-render the verification page with an error message if failed
    res.status(400).render("move_out/pages/verify.ejs", {
        errorMessage: result.message,
        email,
        title: "Verify Email"
    });
});



router.post("/login", async (req, res) => {
    const { email, password } = req.body;
    const result = await loginUser(email, password);

    if (result.success) {
        // Create session token and set cookie
        const sessionToken = crypto.randomBytes(32).toString("hex");
        const db = require("../config/sql");

        await db.query(
            'INSERT INTO Sessions (UserID, SessionToken, ExpiresAt) VALUES (?, ?, DATE_ADD(NOW(), INTERVAL 1 HOUR))',
            [result.userId, sessionToken]
        );

        // Set the session cookie
        res.cookie('sessionToken', sessionToken, { httpOnly: true });

        // Ensure req.user is set for regular users
        req.user = {
            UserID: result.userId,
            FullName: result.fullName, // Assuming your loginUser function returns fullName
            EmailVerified: result.emailVerified,
            GoogleID: null // This is not a Google user
        };

        return res.redirect("/welcome"); // Redirect to welcome page after login
    }

    res.status(400).render("move_out/pages/login.ejs", {
        errorMessage: result.message,
        message: null,
        title: "Login"
    });
});








router.get("/welcome", requireLogin, (req, res) => {
    res.render("move_out/pages/welcome.ejs", { 
        title: "Welcome Page",
        isAuthenticated: !!req.user,  // Boolean to indicate if user is logged in
        user: req.user  // The logged-in user's data
    });
});


router.get("/logout", (req, res) => {
    // If a session exists, destroy it
    if (req.session) {
        req.session.destroy(err => {
            if (err) {
                return res.status(500).send("Error logging out.");
            }

            // Clear the session cookie
            res.clearCookie("sessionToken"); 
            return res.redirect("/login"); // Redirect to login page
        });
    } else {
        // If no session exists, simply redirect
        res.redirect("/login");
    }
});


// Handle Google OAuth login
router.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

router.get('/auth/google/callback', 
    passport.authenticate('google', { failureRedirect: '/login', failureFlash: true }),
    function(req, res) {
        // Successful Google login, redirect to welcome page
        res.redirect('/welcome');
    }
);


// Create label (requires login)
router.get("/create-label", requireLogin, (req, res) => {
    const labelModelsPath = path.join(__dirname, '../config/labelModels.json');
    const labelModels = JSON.parse(fs.readFileSync(labelModelsPath, 'utf-8'));

    res.render("move_out/pages/create_label.ejs", {
        title: "Create Label",
        errorMessage: null,
        labelModels,
        isAuthenticated: true,
        user: req.user
    });
});

// Submit label creation form
router.post('/create-label/submit', requireLogin, upload.fields([
    { name: 'contentImages', maxCount: 5 },
    { name: 'contentAudio', maxCount: 1 }
]), async (req, res) => {
    const { labelDesign, labelName, labelOption, contentType, contentText, status } = req.body;
    const userId = req.user.UserID;

    let contentData = {};

    if (contentType === 'text') {
        contentData = { type: 'text', data: contentText };
    } else if (contentType === 'audio') {
        const audioFile = req.files['contentAudio'] ? req.files['contentAudio'][0] : null;
        contentData = { type: 'audio', data: audioFile };
    } else if (contentType === 'image') {
        const imageFiles = req.files['contentImages'] || [];
        contentData = { type: 'image', data: imageFiles };
    }

    await createLabel(userId, labelDesign, labelName, labelOption, status, contentData);
    res.redirect('/labels');
});

// Display user labels
router.get('/labels', requireLogin, async (req, res) => {
    const connection = await createConnection();
    const [labels] = await connection.query('SELECT * FROM Labels WHERE UserID = ?', [req.user.UserID]);

    const qrCodes = {};
    for (const label of labels) {
        const qrUrl = `http://localhost:1339/labels/view/${label.LabelID}`;
        const qrCodeOptions = {
            color: {
                dark: '#000000',
                light: '#0000'
            }
        };
        qrCodes[label.LabelID] = await QRCode.toDataURL(qrUrl, qrCodeOptions);
    }

    res.render('move_out/pages/labels.ejs', {
        labels,
        qrCodes,
        title: 'My Labels',
        isAuthenticated: true,
        user: req.user
    });
});


router.post("/create-label/step2", requireLogin, (req, res) => {
    const { labelDesign, labelName, labelOption, status } = req.body;

    if (labelName.length > 10) {
        return res.status(400).render("move_out/pages/create_label.ejs", {
            errorMessage: "Label name cannot be longer than 10 characters.",
            title: "Create Label",
            labelModels: JSON.parse(fs.readFileSync(path.join(__dirname, '../config/labelModels.json'), 'utf-8')),
            isAuthenticated: !!req.user, // Explicitly pass isAuthenticated
            user: req.user // Explicitly pass user object
        });
    }

    res.render('move_out/pages/label-content.ejs', {
        labelDesign,
        labelName,
        labelOption,
        status,
        title: "Add Content",
        errorMessage: null,
        isAuthenticated: !!req.user, // Explicitly pass isAuthenticated
        user: req.user // Explicitly pass user object
    });
});




router.post('/create-label/submit', requireLogin, upload.fields([
    { name: 'contentImages', maxCount: 5 },
    { name: 'contentAudio', maxCount: 1 }
]), async (req, res) => {
    const { labelDesign, labelName, labelOption, contentType, contentText, status } = req.body;
    const userId = req.user.UserID;

    let contentData = {};

    if (contentType === 'text') {
        contentData = { type: 'text', data: contentText };
    } else if (contentType === 'audio') {
        const audioFile = req.files['contentAudio'] ? req.files['contentAudio'][0] : null;
        contentData = { type: 'audio', data: audioFile };
    } else if (contentType === 'image') {
        const imageFiles = req.files['contentImages'] || [];
        contentData = { type: 'image', data: imageFiles };
    }

    await createLabel(userId, labelDesign, labelName, labelOption, status, contentData);
    res.redirect('/labels');
});

router.get('/labels/view/:id', requireLogin, canViewLabel, async (req, res) => {
    const label = req.label;
    const canEdit = req.canEdit;
    
    try {
        const connection = await createConnection();
        const [labelContents] = await connection.query('SELECT * FROM LabelContents WHERE LabelID = ?', [label.LabelID]);
        
        res.render('move_out/pages/view.ejs', {
            label,
            labelContents,
            title: `Viewing Label: ${label.LabelName}`,
            canEdit,
            isAuthenticated: !!req.user,
            user: req.user
        });
    } catch (error) {
        console.error('Error fetching label contents:', error);
        res.status(500).send('Internal server error.');
    }
});


router.get('/labels/edit/:id', requireLogin, async (req, res) => {
    const labelId = req.params.id;
    const connection = await createConnection();

    const [labelRows] = await connection.query('SELECT * FROM Labels WHERE LabelID = ? AND UserID = ?', [labelId, req.user.UserID]);
    const [labelContents] = await connection.query('SELECT * FROM LabelContents WHERE LabelID = ?', [labelId]);

    if (labelRows.length > 0) {
        const label = labelRows[0];

        res.render('move_out/pages/edit_label.ejs', {
            title: `Edit Label: ${label.LabelName}`,
            label,
            labelContents,
            errorMessage: null,
            isAuthenticated: true,
            user: req.user
        });
    } else {
        res.status(404).send('Label not found');
    }
});

router.post('/labels/edit/:id', requireLogin, upload.fields([
    { name: 'contentImages', maxCount: 10 },
    { name: 'contentAudio', maxCount: 1 }
]), async (req, res) => {
    const labelId = req.params.id;
    const { labelName, labelOption, removeContent = [], contentType, contentText, status } = req.body;
    const userId = req.user.UserID;

    const connection = await createConnection();

    await connection.query('UPDATE Labels SET LabelName = ?, LabelOption = ?, Status = ? WHERE LabelID = ? AND UserID = ?',
        [labelName, labelOption, status, labelId, userId]);

    if (Array.isArray(removeContent) && removeContent.length > 0) {
        for (const contentId of removeContent) {
            const [contentRows] = await connection.query('SELECT * FROM LabelContents WHERE ContentID = ? AND LabelID = ?', [contentId, labelId]);
            if (contentRows.length > 0) {
                const content = contentRows[0];
                await connection.query('DELETE FROM LabelContents WHERE ContentID = ? AND LabelID = ?', [contentId, labelId]);
                if (content.ContentType === 'image' || content.ContentType === 'audio') {
                    fs.unlinkSync(path.join(__dirname, '../public/uploads', content.ContentData));
                }
            }
        }
    }

    if (contentType === 'text' && contentText) {
        await connection.query('INSERT INTO LabelContents (LabelID, ContentType, ContentData) VALUES (?, ?, ?)',
            [labelId, 'text', contentText]);
    } else if (contentType === 'image') {
        const newImages = req.files['contentImages'] || [];
        for (const image of newImages) {
            await connection.query('INSERT INTO LabelContents (LabelID, ContentType, ContentData) VALUES (?, ?, ?)',
                [labelId, 'image', image.filename]);
        }
    } else if (contentType === 'audio') {
        const newAudio = req.files['contentAudio'] ? req.files['contentAudio'][0] : null;
        if (newAudio) {
            await connection.query('INSERT INTO LabelContents (LabelID, ContentType, ContentData) VALUES (?, ?, ?)',
                [labelId, 'audio', newAudio.filename]);
        }
    }

    res.redirect('/labels');
});

router.post('/labels/share/:id', requireLogin, async (req, res) => {
    const labelId = req.params.id;
    const { recipientEmail } = req.body;
    const userId = req.user.UserID;

    const connection = await createConnection();
    const [labelRows] = await connection.query('SELECT * FROM Labels WHERE LabelID = ? AND UserID = ?', [labelId, userId]);

    if (labelRows.length === 0) {
        return res.status(403).send('You do not have permission to share this label.');
    }

    const shareToken = crypto.randomBytes(16).toString('hex');

    await connection.query(
        'INSERT INTO SharedLabels (LabelID, ShareToken, RecipientEmail) VALUES (?, ?, ?)',
        [labelId, shareToken, recipientEmail]
    );

    const shareLink = `http://localhost:1339/labels/view/${labelId}?token=${shareToken}`;

    const mailOptions = {
        from: process.env.EMAIL_USER,
        to: recipientEmail,
        subject: `Label Shared with You: ${labelRows[0].LabelName}`,
        text: `A label has been shared with you. Click the link below to view it:\n\n${shareLink}`
    };

    await transporter.sendMail(mailOptions);

    res.redirect('/labels');
});

router.get('/leaderboard', requireLogin, async (req, res) => {
    const connection = await createConnection();
    const query = `
        SELECT Users.UserID, Users.FullName, COUNT(Labels.LabelID) AS LabelCount
        FROM Users
        LEFT JOIN Labels ON Users.UserID = Labels.UserID AND Labels.Status = 'public'
        GROUP BY Users.UserID
        ORDER BY LabelCount DESC
    `;

    const [users] = await connection.query(query);

    res.render('move_out/pages/leaderboard.ejs', {
        title: 'Leaderboard',
        users,
        isAuthenticated: !!req.user, // This ensures isAuthenticated is true when user is logged in
        user: req.user  // Pass the logged-in user information
    });
});

router.get('/users/:userId/labels', async (req, res) => {
    const userId = req.params.userId;
    const connection = await createConnection();
    const [userResult] = await connection.query('SELECT FullName FROM Users WHERE UserID = ?', [userId]);

    if (userResult.length === 0) {
        return res.status(404).send('User not found');
    }

    const userName = userResult[0].FullName;

    const [labels] = await connection.query(
        'SELECT * FROM Labels WHERE UserID = ? AND Status = "public"',
        [userId]
    );

    res.render('move_out/pages/user_labels.ejs', {
        title: `${userName}'s Public Labels`,
        labels,
        userName,
        isAuthenticated: req.user ? true : false,
        user: req.user
    });
});

router.post('/labels/delete/:id', requireLogin, async (req, res) => {
    const labelId = req.params.id;
    const userId = req.user.UserID;

    const connection = await createConnection();
    const [labelRows] = await connection.query('SELECT * FROM Labels WHERE LabelID = ? AND UserID = ?', [labelId, userId]);

    if (labelRows.length === 0) {
        return res.status(403).send('You do not have permission to delete this label.');
    }

    const [contentRows] = await connection.query('SELECT * FROM LabelContents WHERE LabelID = ?', [labelId]);

    await connection.query('DELETE FROM LabelContents WHERE LabelID = ?', [labelId]);

    await connection.query('DELETE FROM Labels WHERE LabelID = ?', [labelId]);

    contentRows.forEach(content => {
        if (content.ContentType === 'image' || content.ContentType === 'audio') {
            const filePath = path.join(__dirname, '../public/uploads', content.ContentData);
            if (fs.existsSync(filePath)) {
                fs.unlinkSync(filePath);
            }
        }
    });

    await connection.query('DELETE FROM SharedLabels WHERE LabelID = ?', [labelId]);

    res.redirect('/labels');
});

router.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

router.get('/auth/google/callback', 
    passport.authenticate('google', { failureRedirect: '/login', failureFlash: true }),
    function(req, res) {
        console.log('Google authentication successful, user:', req.user); // Log user after Google login
        res.redirect('/welcome'); // Redirect to a route that requires authentication
    }
);

router.get('/logout', (req, res) => {
    req.logout(function(err) {
        if (err) { return next(err); }
        res.redirect('/login');
    });
});

router.get('/auth/google/callback', 
    passport.authenticate('google', { failureRedirect: '/login', failureFlash: true }),
    function(req, res) {
        console.log('Google authentication successful, user:', req.user); 
        res.redirect('/welcome'); 
    }
);

// Account Settings
router.get('/account', requireLogin, (req, res) => {
    res.render('move_out/pages/settings', {
        title: 'Account Settings',
        user: req.user,  // Make sure the user object is passed
        isAuthenticated: !!req.user,  // Pass the isAuthenticated flag
        successMessage: null,
        errorMessage: null
    });
});

// Update Account Information
router.post("/account/update", requireLogin, async (req, res) => {
    const { username, password } = req.body;
    const userId = req.user.UserID;

    let updateFields = { Username: username };

    if (!req.user.GoogleID && password) {
        const hashedPassword = hashPassword(password);
        updateFields.PasswordHash = hashedPassword;
    }

    try {
        const db = require('../config/sql');
        await db.query('UPDATE Users SET ? WHERE UserID = ?', [updateFields, userId]);

        req.user.Username = username;

        res.redirect('/account');
    } catch (err) {
        console.error(err);
        res.status(500).send("Error updating account");
    }
});

router.post('/account/update-picture', requireLogin, upload.single('profilePicture'), async (req, res) => {
    const userId = req.user.UserID;

    if (req.file) {
        console.log("File uploaded: ", req.file); // Log uploaded file details
        const profilePicturePath = '/uploads/profile_pictures/' + req.file.filename;

        const db = require('../config/sql');
        await db.query('UPDATE Users SET ProfilePicture = ? WHERE UserID = ?', [profilePicturePath, userId]);

        // Update the profile picture in the session
        req.user.ProfilePicture = profilePicturePath;
    } else {
        console.log("No file uploaded.");
    }

    res.redirect('/account');
});




router.post('/account/update-password', requireLogin, async (req, res) => {
    const { currentPassword, newPassword } = req.body;
    const userId = req.user.UserID;

    // Ensure that only non-Google users (with PasswordHash !== '0') can update their password
    if (req.user.PasswordHash === '0') {
        return res.status(403).send("Google OAuth users cannot change their password.");
    }

    try {
        const db = require('../config/sql');
        
        // Fetch the user's current password hash and salt from the database
        const [user] = await db.query('SELECT PasswordHash, Salt, Email FROM Users WHERE UserID = ?', [userId]);

        if (!user.length) {
            return res.status(404).send("User not found.");
        }

        const userData = user[0];

        // Verify if the current password entered matches the stored password hash
        const isPasswordValid = await bcrypt.compare(currentPassword + userData.Salt, userData.PasswordHash);
        
        if (!isPasswordValid) {
            return res.status(400).render('move_out/pages/settings', {
                errorMessage: 'Current password is incorrect.',
                successMessage: null,
                user: req.user
            });
        }

        // Validate the new password (must contain at least one uppercase letter and one number)
        const passwordRegex = /^(?=.*[A-Z])(?=.*\d).+$/;
        if (!passwordRegex.test(newPassword)) {
            return res.status(400).render('move_out/pages/settings', {
                errorMessage: 'New password must contain at least one uppercase letter and one number.',
                successMessage: null,
                user: req.user
            });
        }

        // If the current password is correct and the new password is valid, update it
        const { salt, hashedPassword } = await hashPassword(newPassword);

        // Update the password hash and salt in the database
        await db.query('UPDATE Users SET PasswordHash = ?, Salt = ? WHERE UserID = ?', [hashedPassword, salt, userId]);

        // Send password reset confirmation email
        const transporter = nodemailer.createTransport({
            service: "Gmail",
            auth: {
                user: process.env.EMAIL_USER,
                pass: process.env.EMAIL_PASS
            }
        });

        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: userData.Email,  // Send the email to the user
            subject: "Password Reset Confirmation",
            text: `Hello ${req.user.FullName},\n\nYour password has been successfully updated. If you didn't make this change, please contact our support team immediately.\n\nThank you,\nThe Alhamad Relocations Team`
        };

        await transporter.sendMail(mailOptions);

        // Redirect to the settings page with a success message
        return res.render('move_out/pages/settings', {
            successMessage: 'Password updated successfully. A confirmation email has been sent to your email address.',
            errorMessage: null,
            user: req.user
        });
    } catch (err) {
        console.error('Error updating password:', err);
        res.status(500).send("Error updating password");
    }
});


router.post('/account/deactivate', requireLogin, async (req, res) => {
    const userId = req.user.UserID;
    const email = req.user.Email;  // Assuming the email is available in the user object
    const fullName = req.user.FullName;

    try {
        const db = require('../config/sql');

        // Generate a unique token for reactivation/deletion links
        const token = crypto.randomBytes(32).toString('hex');

        // Set the user's account as deactivated and store the token in the database
        await db.query('UPDATE Users SET IsDeactivated = TRUE, DeactivationToken = ? WHERE UserID = ?', [token, userId]);

        // Log the user out after deactivation with a callback function to handle potential errors
        req.logout(function (err) {
            if (err) {
                console.error('Error logging out after deactivation:', err);
                return res.status(500).send('Error logging out. Please try again.');
            }

            // Send email with reactivation and deletion links
            const transporter = nodemailer.createTransport({
                service: "Gmail",
                auth: {
                    user: process.env.EMAIL_USER,
                    pass: process.env.EMAIL_PASS
                }
            });

            const reactivateLink = `http://localhost:1339/account/reactivate/${token}`;
            const deleteLink = `http://localhost:1339/account/delete/${token}`;

            const mailOptions = {
                from: process.env.EMAIL_USER,
                to: email,  // Send the email to the user's email
                subject: "Account Deactivated",
                text: `Hello ${fullName},\n\nYour account has been deactivated. If you did not initiate this, you have two options:\n\n1. Reactivate your account: ${reactivateLink}\n2. Delete your account: ${deleteLink}\n\nIf you don't respond, your account will remain deactivated. Thank you.\n\nThe Alhamad Relocations Team`
            };

            transporter.sendMail(mailOptions, function (error) {
                if (error) {
                    console.error('Error sending deactivation email:', error);
                    return res.status(500).send('Error sending deactivation email.');
                }

                return res.redirect('/login');  // Redirect to login after successful deactivation and email sent
            });
        });

    } catch (err) {
        console.error('Error deactivating account:', err);
        res.status(500).send('Error deactivating account');
    }
});


router.get('/account/reactivate/:token', async (req, res) => {
    const token = req.params.token;

    try {
        const db = require('../config/sql');

        // Check if the token is valid and if the user is deactivated
        const [user] = await db.query('SELECT UserID, Email, FullName FROM Users WHERE DeactivationToken = ? AND IsDeactivated = TRUE', [token]);

        if (!user.length) {
            return res.status(400).send('Invalid or expired reactivation token.');
        }

        const userData = user[0];

        // Reactivate the user's account
        await db.query('UPDATE Users SET IsDeactivated = FALSE, DeactivationToken = NULL WHERE UserID = ?', [userData.UserID]);

        return res.send(`Hello ${userData.FullName}, your account has been successfully reactivated. You can now log in.`);
    } catch (err) {
        console.error('Error reactivating account:', err);
        res.status(500).send('Error reactivating account');
    }
});




router.get('/account/delete/:token', async (req, res) => {
    const token = req.params.token;

    try {
        const db = require('../config/sql');

        // Check if the token is valid and if the user is deactivated
        const [user] = await db.query('SELECT UserID, FullName FROM Users WHERE DeactivationToken = ? AND IsDeactivated = TRUE', [token]);

        if (!user.length) {
            return res.status(400).send('Invalid or expired deletion token.');
        }

        const userData = user[0];

        // Delete the user's account
        await db.query('DELETE FROM Users WHERE UserID = ?', [userData.UserID]);

        return res.send(`Goodbye ${userData.FullName}, your account has been permanently deleted.`);
    } catch (err) {
        console.error('Error deleting account:', err);
        res.status(500).send('Error deleting account');
    }
});


router.get('/admin/dashboard', requireLogin, requireAdmin, async (req, res) => {
    const db = require('../config/sql');

    try {
        const [users] = await db.query('SELECT UserID, FullName, Email, ProfilePicture, Admin, IsDeactivated FROM Users');

        res.render('admin/dashboard', {
            title: 'Admin Dashboard',
            users,
            isAuthenticated: !!req.user,
            user: req.user
        });
    } catch (error) {
        console.error('Error fetching users:', error);
        res.status(500).send('Error fetching users');
    }
});


router.get('/admin/users', requireLogin, requireAdmin, async (req, res) => {
    const db = require('../config/sql');

    try {
        const [users] = await db.query('SELECT UserID, FullName, Email, ProfilePicture, Admin, IsDeactivated FROM Users');

        res.render('admin/users', {
            title: 'All Users',
            users,
            isAuthenticated: !!req.user,
            user: req.user
        });
    } catch (error) {
        console.error('Error fetching users:', error);
        res.status(500).send('Error fetching users');
    }
});


router.post('/admin/users/:id/toggle-activation', requireLogin, requireAdmin, async (req, res) => {
    const userId = req.params.id;
    const db = require('../config/sql');

    try {
        // Fetch user details
        const [user] = await db.query('SELECT IsDeactivated FROM Users WHERE UserID = ?', [userId]);

        if (!user.length) {
            return res.status(404).send('User not found.');
        }

        const newStatus = !user[0].IsDeactivated;

        // Toggle activation status
        await db.query('UPDATE Users SET IsDeactivated = ? WHERE UserID = ?', [newStatus, userId]);

        res.redirect('/admin/users');
    } catch (error) {
        console.error('Error toggling activation:', error);
        res.status(500).send('Error toggling activation');
    }
});


router.get('/admin/send-email', requireLogin, requireAdmin, (req, res) => {
    res.render('admin/send-email', {
        title: 'Send Marketing Email',
        isAuthenticated: !!req.user,
        user: req.user
    });
});


router.post('/admin/send-email', requireLogin, requireAdmin, async (req, res) => {
    const { subject, message } = req.body;
    const db = require('../config/sql');
    const nodemailer = require('nodemailer');

    try {
        // Fetch all users' emails
        const [users] = await db.query('SELECT Email FROM Users WHERE IsDeactivated = FALSE');

        // Set up email transporter
        const transporter = nodemailer.createTransport({
            service: 'Gmail',
            auth: {
                user: process.env.EMAIL_USER,
                pass: process.env.EMAIL_PASS
            }
        });

        // Send email to each user
        for (const user of users) {
            const mailOptions = {
                from: process.env.EMAIL_USER,
                to: user.Email,
                subject: subject,
                text: message
            };

            await transporter.sendMail(mailOptions);
        }

        res.redirect('/admin/users');
    } catch (error) {
        console.error('Error sending email:', error);
        res.status(500).send('Error sending email');
    }
});

// Example of calling it in your routes.js
const { generateHashedPassword } = require('../src/cli');

// Generate hashed password for admin
generateHashedPassword('Hello1')
.then(hash => {
    console.log('Use this hashed password in your database:', hash);
    // You can also update the database directly here if needed
})
.catch(err => console.error(err));





module.exports = router;
