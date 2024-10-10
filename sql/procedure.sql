use moveOut;

DELIMITER //

CREATE PROCEDURE RegisterUser(
    IN p_email VARCHAR(255),
    IN p_passwordHash VARCHAR(255),
    IN p_salt VARCHAR(255),
    IN p_fullName VARCHAR(255),
    IN p_verificationToken VARCHAR(255)
)
BEGIN
    DECLARE existingEmail INT;

    -- Check if email is already registered
    SELECT COUNT(*) INTO existingEmail FROM Users WHERE Email = p_email;

    IF existingEmail = 0 THEN
        -- Insert the new user if email is not already registered
        INSERT INTO Users (Email, PasswordHash, Salt, FullName, EmailVerified)
        VALUES (p_email, p_passwordHash, p_salt, p_fullName, 0);
    ELSE
        -- Handle the case where the email is already registered (if needed)
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Email already exists';
    END IF;
END //

DELIMITER ;


DELIMITER //

CREATE PROCEDURE VerifyEmail(IN p_token VARCHAR(255))
BEGIN
    UPDATE Users
    SET EmailVerified = TRUE
    WHERE VerificationToken = p_token;

    IF ROW_COUNT() = 0 THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Invalid token';
    END IF;
END //

DELIMITER ;


DELIMITER //

CREATE PROCEDURE LoginUser(
    IN p_email VARCHAR(255),
    IN p_passwordHash VARCHAR(255),
    OUT p_userId INT,
    OUT p_emailVerified BOOLEAN
)
BEGIN
    SELECT UserID, EmailVerified INTO p_userId, p_emailVerified
    FROM Users
    WHERE Email = p_email AND PasswordHash = p_passwordHash;
    
    IF p_userId IS NULL THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Invalid email or password';
    END IF;
END //

DELIMITER ;
