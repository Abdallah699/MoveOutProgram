const express = require("express");
const router = express.Router();
const bcrypt = require("bcrypt");
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
const passport = require('passport');
require('../config/passport');

const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        if (file.fieldname === 'profilePicture') {
            cb(null, path.join(__dirname, '../public/uploads/profile_pictures'));
        } else if (file.fieldname === 'insuranceLogo') {
            cb(null, path.join(__dirname, '../public/uploads'));
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
        if (['profilePicture', 'contentImages', 'insuranceLogo'].includes(file.fieldname)) {
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

const parseForm = multer();

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

function generateAccessCode() {
    return crypto.randomInt(100000, 999999);
}

router.get("/login", (req, res) => {
    const verified = req.query.verified === "true";
    const message = verified ? "Email verified, you can log in now." : null;
    res.render("move_out/pages/login.ejs", { title: "Login", message, errorMessage: null });
});

router.get("/register", (req, res) => {
    res.render("move_out/pages/register.ejs", { title: "Register", errorMessage: null });
});

router.post("/register", async (req, res) => {
    const { email, password, fullName } = req.body;
    const result = await registerUser(email, password, fullName);

    if (result.success) {
        return res.redirect(`/verify?email=${encodeURIComponent(email)}`);
    }

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

    res.status(400).render("move_out/pages/verify.ejs", {
        errorMessage: result.message,
        email,
        title: "Verify Email"
    });
});

router.post('/login', (req, res, next) => {
    passport.authenticate('local', (err, user, info) => {
      if (err) {
        console.error('Error in authentication:', err);
        return next(err);
      }
      if (!user) {
        return res.status(400).render("move_out/pages/login.ejs", {
          errorMessage: info ? info.message : 'Invalid credentials',
          message: null,
          title: "Login"
        });
      }
      req.logIn(user, (err) => {
        if (err) {
          console.error('Error logging in user:', err);
          return next(err);
        }
        console.log("Session data after login:", req.session);
  
        return res.redirect("/welcome");
      });
    })(req, res, next);
  });
  
router.get("/welcome", requireLogin, (req, res) => {
    res.render("move_out/pages/welcome.ejs", {
        title: "Welcome Page",
        isAuthenticated: !!req.user,
        user: req.user
    });
});

router.get('/logout', (req, res) => {
    req.logout(function (err) {
        if (err) { return next(err); }
        res.redirect('/login');
    });
});

router.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

router.get('/auth/google/callback',
    passport.authenticate('google', { failureRedirect: '/login', failureFlash: true }),
    function (req, res) {
        res.redirect('/welcome');
    }
);

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

router.post("/create-label/step2", requireLogin, parseForm.none(), (req, res) => {
    const { labelDesign, labelName, labelOption, status } = req.body;

    console.log("Form data received in step2:", req.body);

    if (typeof labelName === 'string' && labelName.trim().length > 10) {
        return res.status(400).render("move_out/pages/create_label.ejs", {
            errorMessage: "Label name cannot be longer than 10 characters.",
            title: "Create Label",
            labelModels: JSON.parse(fs.readFileSync(path.join(__dirname, '../config/labelModels.json'), 'utf-8')),
            isAuthenticated: !!req.user,
            user: req.user
        });
    }

    if (labelOption === 'insurance') {
        res.redirect(307, '/create-label/submit');
    } else {
        res.render('move_out/pages/label-content.ejs', {
            labelDesign,
            labelName,
            labelOption,
            status,
            title: "Add Content",
            errorMessage: null,
            isAuthenticated: !!req.user,
            user: req.user
        });
    }
});

requireLogin, upload.fields([
    { name: 'contentImages', maxCount: 5 },
    { name: 'contentAudio', maxCount: 1 },
    { name: 'insuranceLogo', maxCount: 1 }
]), async (req, res) => {
    const { labelDesign, labelName, labelOption, contentType, contentText, status, itemNames, itemValues, itemCurrencies } = req.body;
    const userId = req.user.UserID;

    console.log('Form data received in submit:', req.body);
    console.log('Files received:', req.files);

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

    const connection = await createConnection();
    try {
        await connection.query(
            'INSERT INTO Labels (UserID, LabelDesign, LabelName, LabelOption, Status) VALUES (?, ?, ?, ?, ?)',
            [userId, labelDesign, labelName, labelOption, status]
        );

        const [result] = await connection.query('SELECT LAST_INSERT_ID() AS LabelID');
        const labelId = result[0].LabelID;

        if (labelOption === 'insurance') {
            const insuranceLogo = req.files['insuranceLogo'] ? req.files['insuranceLogo'][0].filename : null;

            if (Array.isArray(itemNames) && Array.isArray(itemValues) && Array.isArray(itemCurrencies)) {
                for (let i = 0; i < itemNames.length; i++) {
                    await connection.query(
                        'INSERT INTO InsuranceBoxItems (LabelID, ItemName, ItemValue, Currency) VALUES (?, ?, ?, ?)',
                        [labelId, itemNames[i], itemValues[i], itemCurrencies[i]]
                    );
                }
            }

            if (insuranceLogo) {
                await connection.query(
                    'INSERT INTO LabelContents (LabelID, ContentType, ContentData) VALUES (?, ?, ?)',
                    [labelId, 'image', insuranceLogo]
                );
            }
        }

        if (contentData.type === 'text') {
            await connection.query(
                'INSERT INTO LabelContents (LabelID, ContentType, ContentText) VALUES (?, ?, ?)',
                [labelId, 'text', contentData.data]
            );
        } else if (contentData.type === 'audio' && contentData.data) {
            await connection.query(
                'INSERT INTO LabelContents (LabelID, ContentType, ContentData) VALUES (?, ?, ?)',
                [labelId, 'audio', contentData.data.filename]
            );
        } else if (contentData.type === 'image') {
            for (const image of contentData.data) {
                await connection.query(
                    'INSERT INTO LabelContents (LabelID, ContentType, ContentData) VALUES (?, ?, ?)',
                    [labelId, 'image', image.filename]
                );
            }
        }

        res.redirect('/labels');
    } catch (error) {
        console.error('Error creating label:', error);
        res.status(500).send('Error creating label');
    } finally {
        if (connection) {
            await connection.end();
        }
    }
}


router.post('/create-label/submit', requireLogin, upload.fields([
    { name: 'contentImages', maxCount: 5 },
    { name: 'contentAudio', maxCount: 1 },
    { name: 'insuranceLogo', maxCount: 1 }
]), async (req, res) => {
    const {
        labelDesign,
        labelName,
        labelOption,
        contentType,
        contentText,
        status,
        itemNames,
        itemValues,
        itemCurrencies
    } = req.body;

    const userId = req.user.UserID;

    let contentData = {}; 

    if (contentType === 'text') {
        contentData = { type: 'text', data: contentText };
    } else if (contentType === 'audio') {
        const audioFile = req.files['contentAudio'] ? req.files['contentAudio'][0] : null;
        if (audioFile) {
            contentData = { type: 'audio', data: audioFile.filename };
        }
    } else if (contentType === 'image') {
        const imageFiles = req.files['contentImages'] || [];
        contentData = { type: 'image', data: imageFiles.map(file => file.filename) };
    }

    const connection = await createConnection();
    try {
        await connection.query(
            'INSERT INTO Labels (UserID, LabelDesign, LabelName, LabelOption, Status) VALUES (?, ?, ?, ?, ?)',
            [userId, labelDesign, labelName, labelOption, status]
        );

        const [result] = await connection.query('SELECT LAST_INSERT_ID() AS LabelID');
        const labelId = result[0].LabelID;

        if (contentData.type === 'text') {
            await connection.query(
                'INSERT INTO LabelContents (LabelID, ContentType, ContentText) VALUES (?, ?, ?)',
                [labelId, 'text', contentData.data]
            );
        } else if (contentData.type === 'audio') {
            await connection.query(
                'INSERT INTO LabelContents (LabelID, ContentType, ContentData) VALUES (?, ?, ?)',
                [labelId, 'audio', contentData.data]
            );
        } else if (contentData.type === 'image') {
            for (const image of contentData.data) {
                await connection.query(
                    'INSERT INTO LabelContents (LabelID, ContentType, ContentData) VALUES (?, ?, ?)',
                    [labelId, 'image', image]
                );
            }
        }

        if (status === 'private') {
            const accessCode = generateAccessCode();
            await connection.query('UPDATE Labels SET AccessCode = ? WHERE LabelID = ?', [accessCode, labelId]);
        }

        if (labelOption === 'insurance') {
            const insuranceLogo = req.files['insuranceLogo'] ? req.files['insuranceLogo'][0].filename : null;

            let itemNamesArray = Array.isArray(itemNames) ? itemNames : [itemNames];
            let itemValuesArray = Array.isArray(itemValues) ? itemValues : [itemValues];
            let itemCurrenciesArray = Array.isArray(itemCurrencies) ? itemCurrencies : [itemCurrencies];

            for (let i = 0; i < itemNamesArray.length; i++) {
                await connection.query(
                    'INSERT INTO InsuranceBoxItems (LabelID, ItemName, ItemValue, Currency) VALUES (?, ?, ?, ?)',
                    [labelId, itemNamesArray[i], itemValuesArray[i], itemCurrenciesArray[i]]
                );
            }

            if (insuranceLogo) {
                await connection.query(
                    'INSERT INTO LabelContents (LabelID, ContentType, ContentData) VALUES (?, ?, ?)',
                    [labelId, 'insuranceLogo', insuranceLogo]
                );
            }
        }

        res.redirect('/labels');
    } catch (error) {
        console.error('Error creating label:', error);
        res.status(500).send('Error creating label');
    } finally {
        if (connection) {
            await connection.end();
        }
    }
});



router.get('/labels', requireLogin, async (req, res) => {
    const connection = await createConnection();

    try {
        const [labels] = await connection.query('SELECT * FROM Labels WHERE UserID = ?', [req.user.UserID]);

        const [users] = await connection.query('SELECT UserID, FullName, Email FROM Users WHERE UserID != ?', [req.user.UserID]);

        for (let label of labels) {
            if (label.LabelOption === 'insurance') {
                const [insuranceItems] = await connection.query('SELECT * FROM InsuranceBoxItems WHERE LabelID = ?', [label.LabelID]);
                label.insuranceItems = insuranceItems;

                const [logoRows] = await connection.query('SELECT ContentData FROM LabelContents WHERE LabelID = ? AND ContentType = ?', [label.LabelID, 'insuranceLogo']);
                if (logoRows.length > 0) {
                    label.insuranceLogo = logoRows[0].ContentData;
                } else {
                    label.insuranceLogo = null;
                }
            }
        }

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

        console.log('Users:', users);

        res.render('move_out/pages/labels.ejs', {
            labels,
            qrCodes,
            users,
            isAuthenticated: true,
            user: req.user
        });
    } catch (error) {
        console.error('Error fetching labels or users:', error);
        res.status(500).send('Error fetching labels or users.');
    } finally {
        if (connection) {
            await connection.end();
        }
    }
});


router.get('/labels/view/:id', requireLogin, async (req, res) => {
    const labelId = req.params.id;
    const userId = req.user.UserID;

    const connection = await createConnection();
    try {
        // Fetch the label details
        const [labelRows] = await connection.query('SELECT * FROM Labels WHERE LabelID = ?', [labelId]);

        if (labelRows.length === 0) {
            return res.status(404).send('Label not found.');
        }

        const label = labelRows[0];

        // Check if the user is the owner of the label
        const isOwner = label.UserID === userId;

        // If the label is private and the user is not the owner, ask for the access code
        if (label.Status === 'private' && !isOwner) {
            // Check if the access code has already been validated
            if (!req.query.code || req.query.code !== label.AccessCode) {
                return res.render('move_out/pages/enter_access_code', {
                    labelId: label.LabelID,
                    errorMessage: req.query.code ? 'Invalid code. Please try again.' : null,
                    title: `Enter Access Code for ${label.LabelName}`,
                    isAuthenticated: !!req.user,
                    user: req.user
                });
            }
        }

        const [labelContents] = await connection.query('SELECT * FROM LabelContents WHERE LabelID = ?', [label.LabelID]);

        const qrUrl = `http://localhost:1339/labels/view/${label.LabelID}`;
        const qrCodeOptions = {
            color: {
                dark: '#000000',
                light: '#0000'
            }
        };
        const qrCode = await QRCode.toDataURL(qrUrl, qrCodeOptions);

        res.render('move_out/pages/view.ejs', {
            label,
            labelContents,
            qrCode,
            title: `Viewing Label: ${label.LabelName}`,
            canEdit: isOwner, 
            isAuthenticated: !!req.user,
            user: req.user
        });
    } catch (error) {
        console.error('Error fetching label:', error);
        res.status(500).send('Error fetching label.');
    } finally {
        if (connection) {
            await connection.end();
        }
    }
});


router.get('/labels/view/:id', requireLogin, canViewLabel, async (req, res) => {
    const label = req.label;
    const canEdit = req.canEdit;

    const connection = await createConnection();
    const [labelContents] = await connection.query('SELECT * FROM LabelContents WHERE LabelID = ?', [label.LabelID]);

    const qrUrl = `http://localhost:1339/labels/view/${label.LabelID}`;
    const qrCodeOptions = {
        color: {
            dark: '#000000',
            light: '#0000'
        }
    };
    const qrCode = await QRCode.toDataURL(qrUrl, qrCodeOptions);

    res.render('move_out/pages/view.ejs', {
        label,
        labelContents,
        qrCode,
        title: `Viewing Label: ${label.LabelName}`,
        canEdit,
        isAuthenticated: !!req.user,
        user: req.user
    });
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
        await connection.query('INSERT INTO LabelContents (LabelID, ContentType, ContentText) VALUES (?, ?, ?)',
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

    if (status === 'private') {
        const accessCode = generateAccessCode();
        await connection.query('UPDATE Labels SET AccessCode = ? WHERE LabelID = ?', [accessCode, labelId]);
    } else {
        await connection.query('UPDATE Labels SET AccessCode = NULL WHERE LabelID = ?', [labelId]);
    }

    res.redirect('/labels');
});


router.post('/labels/share/:id', requireLogin, async (req, res) => {
    const labelId = req.params.id;
    const userId = req.user.UserID;
    const { recipientUserId } = req.body;

    if (!recipientUserId) {
        return res.status(400).send('Recipient user ID is required.');
    }

    const connection = await createConnection();
    try {
        const [labelRows] = await connection.query('SELECT * FROM Labels WHERE LabelID = ? AND UserID = ?', [labelId, userId]);
        if (labelRows.length === 0) {
            return res.status(403).send('You do not have permission to share this label.');
        }

        const [recipientRows] = await connection.query('SELECT UserID, FullName, Email FROM Users WHERE UserID = ?', [recipientUserId]);
        if (recipientRows.length === 0) {
            return res.status(404).send('Recipient user not found.');
        }

        const recipientUser = recipientRows[0];

        const [existingShare] = await connection.query(
            'SELECT * FROM SharedLabels WHERE LabelID = ? AND RecipientUserID = ?',
            [labelId, recipientUserId]
        );

        if (existingShare.length > 0) {
            return res.status(400).send('This label has already been shared with the selected user.');
        }

        const shareToken = crypto.randomBytes(16).toString('hex');

        await connection.query(
            'INSERT INTO SharedLabels (LabelID, ShareToken, RecipientEmail, RecipientUserID) VALUES (?, ?, ?, ?)',
            [labelId, shareToken, recipientUser.Email, recipientUserId]
        );

        const shareLink = `http://localhost:1339/labels/view/${labelId}?token=${shareToken}`;
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: recipientUser.Email,
            subject: `Label Shared with You: ${labelRows[0].LabelName || 'Insurance Label'}`,
            text: `A label has been shared with you by ${req.user.FullName}. Click the link below to view it:\n\n${shareLink}`
        };

        await transporter.sendMail(mailOptions);

        return res.redirect('/labels');
    } catch (error) {
        console.error('Error sharing label or sending email:', error);
        if (!res.headersSent) {
            return res.status(500).send('Error sharing label or sending email.');
        }
    } finally {
        if (connection) {
            await connection.end();
        }
    }
});


router.get('/shared-labels', requireLogin, async (req, res) => {
    const userId = req.user.UserID;
    const connection = await createConnection();

    try {
        const [sharedLabels] = await connection.query(`
            SELECT sl.LabelID, l.LabelName, l.LabelDesign, l.LabelOption, l.Status, u.FullName AS SharedBy
            FROM SharedLabels sl
            JOIN Labels l ON sl.LabelID = l.LabelID
            JOIN Users u ON l.UserID = u.UserID
            WHERE sl.RecipientUserID = ?
        `, [userId]);

        const qrCodes = {};
        for (const label of sharedLabels) {
            const qrUrl = `http://localhost:1339/labels/view/${label.LabelID}`;
            const qrCodeOptions = {
                color: {
                    dark: '#000000',
                    light: '#0000'
                }
            };
            qrCodes[label.LabelID] = await QRCode.toDataURL(qrUrl, qrCodeOptions);
        }

        res.render('move_out/pages/shared_labels.ejs', {
            title: 'Shared Labels',
            sharedLabels,
            qrCodes,
            isAuthenticated: true,
            user: req.user
        });
    } catch (error) {
        console.error('Error fetching shared labels:', error);
        res.status(500).send('Error fetching shared labels.');
    } finally {
        if (connection) {
            await connection.end();
        }
    }
});

router.get('/phonebook', requireLogin, async (req, res) => {
    const searchQuery = req.query.search || '';

    const connection = await createConnection();
    try {
        let usersQuery = 'SELECT UserID, FullName, Email, ProfilePicture FROM Users';
        let queryParams = [];

        if (searchQuery) {
            usersQuery += ' WHERE FullName LIKE ? OR Email LIKE ?';
            queryParams.push(`%${searchQuery}%`, `%${searchQuery}%`);
        }

        const [users] = await connection.query(usersQuery, queryParams);

        res.render('move_out/pages/phonebook.ejs', {
            title: 'Phone Book',
            users,
            searchQuery,
            isAuthenticated: true,
            user: req.user
        });
    } catch (error) {
        console.error('Error fetching users:', error);
        res.status(500).send('Error fetching users.');
    } finally {
        if (connection) {
            await connection.end();
        }
    }
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

    res.render('move_out/pages/user_labels.ejs', {
        title: `${userName}'s Public Labels`,
        labels,
        qrCodes,
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

router.get('/account', requireLogin, (req, res) => {
    res.render('move_out/pages/settings', {
        title: 'Account Settings',
        user: req.user,
        isAuthenticated: !!req.user,
        successMessage: null,
        errorMessage: null
    });
});

router.post("/account/update", requireLogin, async (req, res) => {
    const { username, password } = req.body;
    const userId = req.user.UserID;

    let updateFields = { Username: username };

    if (!req.user.GoogleID && password) {
        const { hashedPassword, salt } = await hashPassword(password);
        updateFields.PasswordHash = hashedPassword;
        updateFields.Salt = salt;
    }

    const db = require('../config/sql');
    await db.query('UPDATE Users SET ? WHERE UserID = ?', [updateFields, userId]);

    req.user.Username = username;

    res.redirect('/account');
});

router.post('/account/update-picture', requireLogin, upload.single('profilePicture'), async (req, res) => {
    const userId = req.user.UserID;

    if (req.file) {
        const profilePicturePath = '/uploads/profile_pictures/' + req.file.filename;

        const db = require('../config/sql');
        await db.query('UPDATE Users SET ProfilePicture = ? WHERE UserID = ?', [profilePicturePath, userId]);

        req.user.ProfilePicture = profilePicturePath;
    }

    res.redirect('/account');
});

router.post('/account/update-password', requireLogin, async (req, res) => {
    const { currentPassword, newPassword } = req.body;
    const userId = req.user.UserID;

    if (req.user.PasswordHash === '0') {
        return res.status(403).send("Google OAuth users cannot change their password.");
    }

    const db = require('../config/sql');
    const [user] = await db.query('SELECT PasswordHash, Salt, Email FROM Users WHERE UserID = ?', [userId]);

    if (!user.length) {
        return res.status(404).send("User not found.");
    }

    const userData = user[0];

    const isPasswordValid = await bcrypt.compare(currentPassword + userData.Salt, userData.PasswordHash);

    if (!isPasswordValid) {
        return res.status(400).render('move_out/pages/settings', {
            errorMessage: 'Current password is incorrect.',
            successMessage: null,
            user: req.user
        });
    }

    const passwordRegex = /^(?=.*[A-Z])(?=.*\d).+$/;
    if (!passwordRegex.test(newPassword)) {
        return res.status(400).render('move_out/pages/settings', {
            errorMessage: 'New password must contain at least one uppercase letter and one number.',
            successMessage: null,
            user: req.user
        });
    }

    const { hashedPassword, salt } = await hashPassword(newPassword);

    await db.query('UPDATE Users SET PasswordHash = ?, Salt = ? WHERE UserID = ?', [hashedPassword, salt, userId]);

    const mailOptions = {
        from: process.env.EMAIL_USER,
        to: userData.Email,
        subject: "Password Reset Confirmation",
        text: `Hello ${req.user.FullName},\n\nYour password has been successfully updated. If you didn't make this change, please contact our support team immediately.\n\nThank you,\nThe Alhamad Relocations Team`
    };

    await transporter.sendMail(mailOptions);

    return res.render('move_out/pages/settings', {
        successMessage: 'Password updated successfully. A confirmation email has been sent to your email address.',
        errorMessage: null,
        user: req.user
    });
});

router.post('/account/deactivate', requireLogin, async (req, res) => {
    const userId = req.user.UserID;
    const email = req.user.Email;
    const fullName = req.user.FullName;

    const db = require('../config/sql');

    const token = crypto.randomBytes(32).toString('hex');

    await db.query('UPDATE Users SET IsDeactivated = TRUE, DeactivationToken = ? WHERE UserID = ?', [token, userId]);

    req.logout(function (err) {
        if (err) {
            return res.status(500).send('Error logging out. Please try again.');
        }

        const reactivateLink = `http://localhost:1339/account/reactivate/${token}`;
        const deleteLink = `http://localhost:1339/account/delete/${token}`;

        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: "Account Deactivated",
            text: `Hello ${fullName},\n\nYour account has been deactivated. If you did not initiate this, you have two options:\n\n1. Reactivate your account: ${reactivateLink}\n2. Delete your account: ${deleteLink}\n\nIf you don't respond, your account will remain deactivated. Thank you.\n\nThe Alhamad Relocations Team`
        };

        transporter.sendMail(mailOptions, function (error) {
            if (error) {
                return res.status(500).send('Error sending deactivation email.');
            }

            return res.redirect('/login');
        });
    });
});

router.get('/account/reactivate/:token', async (req, res) => {
    const token = req.params.token;

    const db = require('../config/sql');

    const [user] = await db.query('SELECT UserID, Email, FullName FROM Users WHERE DeactivationToken = ? AND IsDeactivated = TRUE', [token]);

    if (!user.length) {
        return res.status(400).send('Invalid or expired reactivation token.');
    }

    const userData = user[0];

    await db.query('UPDATE Users SET IsDeactivated = FALSE, DeactivationToken = NULL WHERE UserID = ?', [userData.UserID]);

    return res.send(`Hello ${userData.FullName}, your account has been successfully reactivated. You can now log in.`);
});

router.get('/account/delete/:token', async (req, res) => {
    const token = req.params.token;

    const db = require('../config/sql');

    const [user] = await db.query('SELECT UserID, FullName FROM Users WHERE DeactivationToken = ? AND IsDeactivated = TRUE', [token]);

    if (!user.length) {
        return res.status(400).send('Invalid or expired deletion token.');
    }

    const userData = user[0];

    await db.query('DELETE FROM Users WHERE UserID = ?', [userData.UserID]);

    return res.send(`Goodbye ${userData.FullName}, your account has been permanently deleted.`);
});

router.get('/admin/dashboard', requireLogin, requireAdmin, async (req, res) => {
    const db = require('../config/sql');
    
    try {
        const [users] = await db.query('SELECT UserID, FullName, Email, ProfilePicture, AdminLevel, IsDeactivated FROM Users');

        const userStorageInfo = [];
        for (const user of users) {
            let totalStorageMB = 0;

            if (user.ProfilePicture && user.ProfilePicture !== '/uploads/profile_pictures/default.png') {
                const profilePicturePath = path.join(__dirname, '..', 'public', user.ProfilePicture);
                totalStorageMB += calculateFileSizeInMB(profilePicturePath);
            }

            const [labelContents] = await db.query('SELECT ContentData FROM LabelContents WHERE LabelID IN (SELECT LabelID FROM Labels WHERE UserID = ?)', [user.UserID]);
            for (const content of labelContents) {
                if (content.ContentData) {
                    const contentPath = path.join(__dirname, '..', 'public', 'uploads', content.ContentData);
                    totalStorageMB += calculateFileSizeInMB(contentPath);
                }
            }

            userStorageInfo.push({
                ...user,
                totalStorageMB: totalStorageMB.toFixed(2)
            });
        }

        res.render('move_out/pages/dashboard', {
            title: 'Admin Dashboard',
            users: userStorageInfo,
            successMessage: req.query.successMessage || null,
            errorMessage: req.query.errorMessage || null,
            isAuthenticated: !!req.user,
            user: req.user
        });
    } catch (error) {
        console.error('Error fetching users or calculating storage:', error);
        res.status(500).send('Error fetching users or calculating storage.');
    }
});




router.get('/admin/users', requireLogin, requireAdmin, async (req, res) => {
    const db = require('../config/sql');

    const [users] = await db.query('SELECT UserID, FullName, Email, ProfilePicture, AdminLevel, IsDeactivated FROM Users');

    res.render('admin/users', {
        title: 'All Users',
        users,
        isAuthenticated: !!req.user,
        user: req.user
    });
});

router.post('/admin/users/:id/toggle', requireLogin, requireAdmin, async (req, res) => {
    const userId = req.params.id;
    const connection = await createConnection();

    try {
        const [user] = await connection.query('SELECT Email, FullName, IsDeactivated FROM Users WHERE UserID = ?', [userId]);

        if (user.length === 0) {
            return res.status(404).send('User not found.');
        }

        const userEmail = user[0].Email;
        const userName = user[0].FullName;
        const newStatus = !user[0].IsDeactivated; 

        await connection.query('UPDATE Users SET IsDeactivated = ? WHERE UserID = ?', [newStatus, userId]);

        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: process.env.EMAIL_USER,
                pass: process.env.EMAIL_PASS
            }
        });

        if (newStatus) {
            const mailOptions = {
                from: process.env.EMAIL_USER,
                to: userEmail,
                subject: 'Your Account Has Been Deactivated',
                text: `Hello ${userName},\n\nYour account has been deactivated by an admin.\nIf you would like to appeal this decision or need further assistance, please contact us at alhamadrelocations@gmail.com.\n\nThank you,\nAlhamad Relocations Team`
            };
            await transporter.sendMail(mailOptions);

        } else {
            const mailOptions = {
                from: process.env.EMAIL_USER,
                to: userEmail,
                subject: 'Your Account Has Been Activated',
                text: `Hello ${userName},\n\nGood news! Your account has been reactivated by an admin.\nYou can now log in and access your account.\nIf you have any questions, feel free to contact us at alhamadrelocations@gmail.com.\n\nThank you,\nAlhamad Relocations Team`
            };
            await transporter.sendMail(mailOptions);
        }

        res.redirect('/admin/dashboard');
    } catch (error) {
        console.error('Error updating user status or sending email:', error);
        res.status(500).send('Error updating user status.');
    } finally {
        if (connection) {
            await connection.end();
        }
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
    const { emailSubject, emailBody } = req.body;

    const db = require('../config/sql');
    const [users] = await db.query('SELECT Email FROM Users WHERE IsDeactivated = FALSE');

    const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASS
        }
    });

    try {
        for (const user of users) {
            const mailOptions = {
                from: process.env.EMAIL_USER,
                to: user.Email,
                subject: emailSubject,
                text: emailBody
            };

            await transporter.sendMail(mailOptions);
        }

        res.redirect('/admin/dashboard?successMessage=Emails have been sent successfully!');
    } catch (error) {
        console.error('Error sending emails:', error);
        res.redirect('/admin/dashboard?errorMessage=There was an error sending the emails. Please try again.');
    }
});

    


router.post('/admin/users/:id/update-role', requireLogin, requireAdmin, async (req, res) => {
    const userId = req.params.id; 
    const { AdminLevel } = req.body;
    const connection = await createConnection();

    try {
        if (req.user.AdminLevel !== 2) {
            return res.status(403).send('Access denied. Only Super Admins can change roles.');
        }

        if (req.user.UserID === parseInt(userId)) {
            return res.status(403).send('You cannot change your own role.');
        }

        await connection.query('UPDATE Users SET AdminLevel = ? WHERE UserID = ?', [AdminLevel, userId]);

        res.redirect('/admin/dashboard');
    } catch (error) {
        console.error('Error updating role:', error);
        res.status(500).send('Error updating role.');
    } finally {
        if (connection) {
            await connection.end();
        }
    }
});





router.get('/insurance/view/:id', requireLogin, async (req, res) => {
    const labelId = req.params.id;
    const connection = await createConnection();

    try {
        const [insuranceLabel] = await connection.query('SELECT * FROM Labels WHERE LabelID = ? AND LabelOption = "insurance"', [labelId]);
        const [insuranceItems] = await connection.query('SELECT * FROM InsuranceBoxItems WHERE LabelID = ?', [labelId]);

        if (insuranceLabel.length === 0) {
            return res.status(404).send('Insurance label not found.');
        }

        const qrUrl = `http://localhost:1339/insurance/view/${labelId}`;
        const qrCodeOptions = {
            color: {
                dark: '#000000',
                light: '#0000'
            }
        };
        const qrCode = await QRCode.toDataURL(qrUrl, qrCodeOptions);



        res.render('move_out/pages/insurance_view', {
            title: `View Insurance Label: ${insuranceLabel[0].LabelName || 'Insurance Label'}`,
            label: insuranceLabel[0],
            items: insuranceItems,
            qrCode,
            user: req.user,
            isAuthenticated: true
        });
    } catch (error) {
        console.error('Error fetching insurance label:', error);
        res.status(500).send('Error fetching insurance label.');
    } finally {
        if (connection) {
            await connection.end();
        }
    }
});

router.post('/insurance/item/add/:labelId', requireLogin, async (req, res) => {
    const { itemName, itemValue, currency } = req.body;
    const labelId = req.params.labelId;

    const connection = await createConnection();
    try {
        await connection.query(
            'INSERT INTO InsuranceBoxItems (LabelID, ItemName, ItemValue, Currency) VALUES (?, ?, ?, ?)',
            [labelId, itemName, itemValue, currency]
        );
        res.redirect(`/insurance/edit/${labelId}`);
    } catch (error) {
        console.error('Error adding insurance item:', error);
        res.status(500).send('Error adding insurance item.');
    } finally {
        if (connection) await connection.end();
    }
});

router.get('/insurance/edit/:labelId', requireLogin, async (req, res) => {
    const labelId = req.params.labelId;
    const connection = await createConnection();

    try {
        const [label] = await connection.query('SELECT * FROM Labels WHERE LabelID = ?', [labelId]);
        const [items] = await connection.query('SELECT * FROM InsuranceBoxItems WHERE LabelID = ?', [labelId]);

        res.render('move_out/pages/insurance_edit', { label: label[0], items: items });
    } catch (error) {
        console.error('Error fetching insurance data:', error);
        res.status(500).send('Error loading insurance data.');
    } finally {
        if (connection) {
            await connection.end();
        }
    }
});







router.post('/insurance/item/delete/:itemId', requireLogin, async (req, res) => {
    const itemId = req.params.itemId;
    const connection = await createConnection();

    try {
        await connection.query('DELETE FROM InsuranceBoxItems WHERE InsuranceItemID = ?', [itemId]);
        
        res.redirect('back');
    } catch (error) {
        console.error('Error deleting insurance item:', error);
        res.status(500).send('Error deleting insurance item.');
    } finally {
        if (connection) {
            await connection.end();
        }
    }
});



router.get('/shared-labels', requireLogin, async (req, res) => {
    try {
        const sharedLabels = await getSharedLabels(req.user.UserID);

        const qrCodes = {};
        for (const label of sharedLabels) {
            const qrUrl = `http://localhost:1339/labels/view/${label.LabelID}`;
            const qrCodeOptions = {
                color: {
                    dark: '#000000',
                    light: '#0000'
                }
            };
            qrCodes[label.LabelID] = await QRCode.toDataURL(qrUrl, qrCodeOptions);
        }

        res.render('move_out/pages/shared_labels', {
            sharedLabels,
            qrCodes,
            isAuthenticated: true,
            user: req.user
        });
    } catch (error) {
        console.error('Error fetching shared labels:', error);
        res.status(500).send('Server error');
    }
});



const getSharedLabels = async (userID) => {
    const connection = await createConnection();

    try {
        const [sharedLabels] = await connection.query(`
            SELECT labels.*, users.FullName as SharedBy
            FROM SharedLabels AS shared
            JOIN Labels AS labels ON shared.LabelID = labels.LabelID
            LEFT JOIN Users AS users ON shared.SharedByUserID = users.UserID
            WHERE shared.RecipientUserID = ?
        `, [userID]);

        for (const label of sharedLabels) {
            if (label.LabelOption === 'insurance') {
                const [insuranceItems] = await connection.query(`
                    SELECT * FROM InsuranceBoxItems WHERE LabelID = ?
                `, [label.LabelID]);

                label.insuranceItems = insuranceItems;

                const [insuranceLogo] = await connection.query(`
                    SELECT ContentData FROM LabelContents WHERE LabelID = ? AND ContentType = 'insuranceLogo'
                `, [label.LabelID]);

                if (insuranceLogo.length > 0) {
                    label.insuranceLogo = insuranceLogo[0].ContentData;
                } else {
                    label.insuranceLogo = null;
                }
            }
        }

        return sharedLabels;
    } catch (error) {
        console.error('Error fetching shared labels with insurance data:', error);
        throw error;
    } finally {
        await connection.end();
    }
};


router.get("/about", (req, res) => {
    res.render("move_out/pages/about", {
        title: "About Alhamad Relocations",
        isAuthenticated: !!req.user,
        user: req.user
    });
});

router.get('/contact', (req, res) => {
    res.render('move_out/pages/contact', {
        title: 'Contact Us',
        isAuthenticated: !!req.user,
        user: req.user
    });
});


router.post('/contact/send', (req, res) => {
    const { name, email, subject, message } = req.body;

    if (!name || !email || !subject || !message) {
        return res.status(400).render('move_out/pages/contact', {
            title: 'Contact Us',
            errorMessage: 'All fields are required.',
            isAuthenticated: !!req.user,
            user: req.user
        });
    }

    const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASS
        }
    });

    const mailOptions = {
        from: email,
        to: process.env.CONTACT_RECEIVE_EMAIL || 'support@alhamadrelocations.com',
        subject: `Contact Form: ${subject}`,
        text: `You have received a new contact message from ${name} (${email}):\n\n${message}`
    };

    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            console.error('Error sending contact message:', error);
            return res.status(500).render('move_out/pages/contact', {
                title: 'Contact Us',
                errorMessage: 'There was an issue sending your message. Please try again later.',
                isAuthenticated: !!req.user,
                user: req.user
            });
        }

        console.log('Message sent: %s', info.messageId);
        return res.render('move_out/pages/contact', {
            title: 'Contact Us',
            successMessage: 'Your message has been sent successfully! We will get back to you shortly.',
            isAuthenticated: !!req.user,
            user: req.user
        });
    });
});


function calculateFileSizeInMB(filePath) {
    const stats = fs.statSync(filePath);
    return stats.size / (1024 * 1024);
}


module.exports = router;
