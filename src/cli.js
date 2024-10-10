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
    const salt = crypto.randomBytes(16).toString('hex'); // Generate a salt
    const hashedPassword = await bcrypt.hash(password + salt, 10); // Hash password with salt
    return { salt, hashedPassword };
}



// Send verification email function
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

    try {
        await transporter.sendMail(mailOptions);
        console.log(`Verification email sent to: ${email} with code: ${verificationCode}`);
    } catch (error) {
        console.error(`Failed to send email to ${email}:`, error);
    }
}

async function registerUser(email, password, fullName) {
    const connection = await createConnection();

    // Check if email is already registered
    const [existingUser] = await connection.query('SELECT Email FROM Users WHERE Email = ?', [email]);

    if (existingUser.length) {
        return { success: false, message: 'Email is already registered.' };
    }

    // Validate password
    const passwordRegex = /^(?=.*[a-zA-Z])(?=.*\d)[A-Za-z\d]{6,}$/;
    if (!passwordRegex.test(password)) {
        return { success: false, message: 'Password must be at least 6 characters long and contain both letters and numbers.' };
    }

    // Hash the password and generate a salt
    const { salt, hashedPassword } = await hashPassword(password);

    let emailVerified = false;
    let verificationCode = Math.floor(100000 + Math.random() * 900000);  // Generate verification code
    let verificationExpiresAt = new Date(Date.now() + 60 * 60 * 1000);  // 1-hour expiration

    // Send the verification email
    await sendVerificationEmail(email, verificationCode);

    // Insert the new user into the database with the hashed password and salt
    await connection.query(
        'INSERT INTO Users (Email, PasswordHash, Salt, FullName, EmailVerified, VerificationCode, VerificationExpiresAt) VALUES (?, ?, ?, ?, ?, ?, ?)',
        [email, hashedPassword, salt, fullName, emailVerified, verificationCode, verificationExpiresAt]
    );

    connection.end();

    return { success: true, message: 'Registration successful! Please check your email for the verification code.' };
}


// Verify email by checking verification code
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
    console.log(`Checking user in DB for email: ${email}`);

    const [user] = await connection.query(
        'SELECT Salt, PasswordHash, EmailVerified, IsDeactivated, UserID FROM Users WHERE Email = ?',
        [email]
    );

    if (user.length === 0) {
        console.log(`No user found for email: ${email}`);
        return { success: false, message: 'Invalid email or password.' };
    }

    const userData = user[0];
    console.log(`User found: ${JSON.stringify(userData)}`);

    if (userData.IsDeactivated) {
        console.log('User account is deactivated');
        return { success: false, message: 'Your account is deactivated. Please check your email for reactivation options.' };
    }

    if (!userData.EmailVerified) {
        console.log('User email is not verified');
        return { success: false, message: 'Please verify your email before logging in.' };
    }

    // Compare the password with the stored hash
    const isPasswordValid = await bcrypt.compare(password + userData.Salt, userData.PasswordHash);
    console.log(`Password valid: ${isPasswordValid}`);

    if (!isPasswordValid) {
        console.log('Password mismatch');
        return { success: false, message: 'Invalid email or password.' };
    }

    console.log('Password matched');
    connection.end();
    
    return { success: true, message: 'Login successful!', userId: userData.UserID };
}



// Function to send password reset confirmation email
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
        text: `Hello, \n\nThis is a confirmation that the password for your account ${email} has just been changed. \n\nIf you didn't do this, please contact support immediately.`
    };

    try {
        await transporter.sendMail(mailOptions);
        console.log(`Password reset confirmation email sent to: ${email}`);
    } catch (error) {
        console.error(`Failed to send password reset confirmation to ${email}:`, error);
    }
}

async function findOrCreateUserByGoogleId(profile) {
    const connection = await createConnection();
    const googleId = profile.id;
    const email = profile.emails[0].value;
    const fullName = profile.displayName;

    try {
        // Check if the user already exists in the database by Google ID
        const [existingUser] = await connection.query('SELECT * FROM Users WHERE GoogleID = ?', [googleId]);

        if (existingUser.length > 0) {
            let user = existingUser[0];

            console.log('User found in database:', user);

            // If the username is null, set it to the FullName
            if (!user.Username) {
                let sanitizedUsername = fullName.replace(/\s+/g, '').toLowerCase();  // Remove spaces and convert to lowercase

                // Ensure the generated username is unique
                let [existingUsername] = await connection.query('SELECT Username FROM Users WHERE Username = ?', [sanitizedUsername]);
                let counter = 1;
                while (existingUsername.length > 0) {
                    sanitizedUsername = sanitizedUsername + counter;  // Append a number to make it unique
                    [existingUsername] = await connection.query('SELECT Username FROM Users WHERE Username = ?', [sanitizedUsername]);
                    counter++;
                }

                // Update the user with the new username
                await connection.query('UPDATE Users SET Username = ? WHERE UserID = ?', [sanitizedUsername, user.UserID]);
                user.Username = sanitizedUsername;  // Set the updated username in the user object

                console.log('Generated and updated username for existing user:', sanitizedUsername);
            }

            connection.end();
            return user;
        } else {
            console.log('User not found, creating new user...');

            // Set the Username to the sanitized FullName
            let sanitizedUsername = fullName.replace(/\s+/g, '').toLowerCase();  // Remove spaces and convert to lowercase

            // Ensure the generated username is unique
            let [existingUsername] = await connection.query('SELECT Username FROM Users WHERE Username = ?', [sanitizedUsername]);
            let counter = 1;
            while (existingUsername.length > 0) {
                sanitizedUsername = sanitizedUsername + counter;  // Append a number to make it unique
                [existingUsername] = await connection.query('SELECT Username FROM Users WHERE Username = ?', [sanitizedUsername]);
                counter++;
            }

            console.log('Generated unique username for new user:', sanitizedUsername);

            // Insert the new user into the database with the sanitized username
            const [result] = await connection.query(
                'INSERT INTO Users (Email, FullName, Username, EmailVerified, GoogleID, ProfilePicture) VALUES (?, ?, ?, ?, ?, ?)',
                [email, fullName, sanitizedUsername, true, googleId, '/uploads/profile_pictures/default.png']
            );

            connection.end();

            // Return the newly created user
            return {
                UserID: result.insertId,
                Email: email,
                FullName: fullName,
                Username: sanitizedUsername,
                EmailVerified: true,
                GoogleID: googleId,
                ProfilePicture: '/uploads/profile_pictures/default.png'
            };
        }
    } catch (error) {
        console.error('Error finding or creating Google user:', error);
        connection.end();
        throw error;
    }
}







async function createLabel(userId, labelDesign, labelName, labelOption, status, contentData) {
    try {
        const connection = await createConnection();

        // Insert the label into the Labels table with Status
        const [labelResult] = await connection.query(
            'INSERT INTO Labels (UserID, LabelDesign, LabelName, LabelOption, Status) VALUES (?, ?, ?, ?, ?)',
            [userId, labelDesign, labelName, labelOption, status]
        );
        const labelId = labelResult.insertId;

        // Insert label contents if any
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
    } catch (error) {
        console.error('Error creating label:', error);
        throw error;
    }
}

async function generateHashedPassword(plaintextPassword) {
    const saltRounds = 10;
    try {
        const hashedPassword = await bcrypt.hash(plaintextPassword, saltRounds);
        console.log("Hashed Password:", hashedPassword);  // Log the hashed password to the console
        return hashedPassword;
    } catch (err) {
        console.error("Error hashing password:", err);
    }
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
