"use strict";

const bcrypt = require("bcrypt");
const crypto = require("crypto");
const nodemailer = require("nodemailer");
const mysql = require("mysql2/promise");
require('dotenv').config();

const config = {
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    database: process.env.DB_NAME || 'moveout',
    multipleStatements: true,
    googleClientID: process.env.GOOGLE_CLIENT_ID,
    googleClientSecret: process.env.GOOGLE_CLIENT_SECRET
};

async function createConnection() {
    return mysql.createConnection({
        host: config.host,
        user: config.user,
        password: config.password,
        database: config.database
    });
}

async function hashPassword(password) {
    const salt = crypto.randomBytes(16).toString('hex');
    const hashedPassword = await bcrypt.hash(password + salt, 10);
    return { salt, hashedPassword };
}

async function sendVerificationEmail(email, verificationCode) {
    const transporter = nodemailer.createTransport({
        service: "Gmail",
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASS
        }
    });

    const mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: "Email Verification",
        text: `Your verification code is: ${verificationCode}. It will expire in 1 hour.`
    };

    await transporter.sendMail(mailOptions);
}

async function registerUser(email, password, fullName) {
    const connection = await createConnection();
    const [existingUser] = await connection.query('SELECT Email FROM Users WHERE Email = ?', [email]);

    if (existingUser.length) {
        return { success: false, message: 'Email is already registered.' };
    }

    const passwordRegex = /^(?=.*[a-zA-Z])(?=.*\d)[A-Za-z\d]{6,}$/;
    if (!passwordRegex.test(password)) {
        return { success: false, message: 'Password must be at least 6 characters long and contain both letters and numbers.' };
    }

    const { salt, hashedPassword } = await hashPassword(password);

    let emailVerified = false;
    let verificationCode = Math.floor(100000 + Math.random() * 900000);
    let verificationExpiresAt = new Date(Date.now() + 60 * 60 * 1000);

    await sendVerificationEmail(email, verificationCode);

    await connection.query(
        'INSERT INTO Users (Email, PasswordHash, Salt, FullName, EmailVerified, VerificationCode, VerificationExpiresAt, AdminLevel) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
        [email, hashedPassword, salt, fullName, emailVerified, verificationCode, verificationExpiresAt, 0] // Regular users get AdminLevel 0
    );

    connection.end();

    return { success: true, message: 'Registration successful! Please check your email for the verification code.' };
}

async function verifyEmail(email, verificationCode) {
    const connection = await createConnection();
    const [user] = await connection.query(
        'SELECT VerificationCode, VerificationExpiresAt, UserID FROM Users WHERE Email = ? AND EmailVerified = FALSE',
        [email]
    );

    if (user.length === 0) {
        return { success: false, message: 'Invalid email or email already verified.' };
    }

    const userData = user[0];

    if (userData.VerificationCode !== parseInt(verificationCode)) {
        return { success: false, message: 'Invalid verification code.' };
    }

    if (new Date(userData.VerificationExpiresAt) < new Date()) {
        return { success: false, message: 'Verification code has expired.' };
    }

    await connection.query(
        'UPDATE Users SET EmailVerified = TRUE, VerificationCode = NULL, VerificationExpiresAt = NULL WHERE UserID = ?',
        [userData.UserID]
    );

    connection.end();

    return { success: true, message: 'Email verified successfully!' };
}

async function loginUser(email, password) {
    const connection = await createConnection();
    
    // Query the database for the user with the provided email
    const [user] = await connection.query(
        'SELECT UserID, FullName, Email, EmailVerified, IsDeactivated, AdminLevel, PasswordHash, Salt FROM Users WHERE Email = ?',
        [email]
    );

    if (user.length === 0) {
        return { success: false, message: 'Invalid email or password.' };
    }

    const userData = user[0];

    if (userData.IsDeactivated) {
        return { success: false, message: 'Your account is deactivated. Please check your email for reactivation options.' };
    }

    if (!userData.EmailVerified) {
        return { success: false, message: 'Please verify your email before logging in.' };
    }

    // Check password for regular user
    const isPasswordValid = await bcrypt.compare(password + userData.Salt, userData.PasswordHash);

    if (!isPasswordValid) {
        return { success: false, message: 'Invalid email or password.' };
    }

    connection.end();

// cli.js
return {
    success: true,
    message: 'Login successful!',
    user: {
      UserID: userData.UserID,
      FullName: userData.FullName,
      Email: userData.Email,
      EmailVerified: userData.EmailVerified,
      AdminLevel: userData.AdminLevel,  // Ensure AdminLevel is included
      // Include any other necessary fields
    }
  };
  
}


async function sendPasswordResetConfirmation(email) {
    const transporter = nodemailer.createTransport({
        service: "Gmail",
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASS
        }
    });

    const mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: "Password Reset Confirmation",
        text: `Hello,\n\nThis is a confirmation that the password for your account ${email} has just been changed.\n\nIf you didn't do this, please contact support immediately.`
    };

    await transporter.sendMail(mailOptions);
}

async function findOrCreateUserByGoogleId(profile) {
    const connection = await createConnection();
    const googleId = profile.id;
    const email = profile.emails[0].value;
    const fullName = profile.displayName;

    const [existingUser] = await connection.query('SELECT * FROM Users WHERE GoogleID = ?', [googleId]);

    if (existingUser.length > 0) {
        let user = existingUser[0];

        if (!user.Username) {
            let sanitizedUsername = fullName.replace(/\s+/g, '').toLowerCase();
            let [existingUsername] = await connection.query('SELECT Username FROM Users WHERE Username = ?', [sanitizedUsername]);
            let counter = 1;
            while (existingUsername.length > 0) {
                sanitizedUsername = sanitizedUsername + counter;
                [existingUsername] = await connection.query('SELECT Username FROM Users WHERE Username = ?', [sanitizedUsername]);
                counter++;
            }
            await connection.query('UPDATE Users SET Username = ? WHERE UserID = ?', [sanitizedUsername, user.UserID]);
            user.Username = sanitizedUsername;
        }

        connection.end();
        return user;
    } else {
        let sanitizedUsername = fullName.replace(/\s+/g, '').toLowerCase();
        let [existingUsername] = await connection.query('SELECT Username FROM Users WHERE Username = ?', [sanitizedUsername]);
        let counter = 1;
        while (existingUsername.length > 0) {
            sanitizedUsername = sanitizedUsername + counter;
            [existingUsername] = await connection.query('SELECT Username FROM Users WHERE Username = ?', [sanitizedUsername]);
            counter++;
        }

        const [result] = await connection.query(
            'INSERT INTO Users (Email, FullName, Username, EmailVerified, GoogleID, ProfilePicture, AdminLevel) VALUES (?, ?, ?, ?, ?, ?, ?)',
            [email, fullName, sanitizedUsername, true, googleId, '/uploads/profile_pictures/default.png', 0]  // Google users start as regular users
        );

        connection.end();

        return {
            UserID: result.insertId,
            Email: email,
            FullName: fullName,
            Username: sanitizedUsername,
            EmailVerified: true,
            GoogleID: googleId,
            ProfilePicture: '/uploads/profile_pictures/default.png',
            AdminLevel: 0  // Default for Google users is also regular user
        };
    }
}

async function createLabel(userId, labelDesign, labelName, labelOption, status, contentData) {
    const connection = await createConnection();

    const [labelResult] = await connection.query(
        'INSERT INTO Labels (UserID, LabelDesign, LabelName, LabelOption, Status) VALUES (?, ?, ?, ?, ?)',
        [userId, labelDesign, labelName, labelOption, status]
    );
    const labelId = labelResult.insertId;

    if (contentData.type === 'text') {
        await connection.query('INSERT INTO LabelContents (LabelID, ContentType, ContentData) VALUES (?, ?, ?)',
            [labelId, 'text', contentData.data]
        );
    } else if (contentData.type === 'audio' && contentData.data) {
        await connection.query('INSERT INTO LabelContents (LabelID, ContentType, ContentData) VALUES (?, ?, ?)',
            [labelId, 'audio', contentData.data.filename]
        );
    } else if (contentData.type === 'image') {
        for (let imageFile of contentData.data) {
            await connection.query('INSERT INTO LabelContents (LabelID, ContentType, ContentData) VALUES (?, ?, ?)',
                [labelId, 'image', imageFile.filename]
            );
        }
    }

    connection.end();
    return { success: true, message: 'Label created successfully.' };
}

async function generateHashedPassword(plaintextPassword) {
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(plaintextPassword, saltRounds);
    return hashedPassword;
}

module.exports = {
    createConnection,
    registerUser,
    verifyEmail,
    loginUser,
    findOrCreateUserByGoogleId,
    createLabel,
    hashPassword,
    sendPasswordResetConfirmation,
    generateHashedPassword
};
