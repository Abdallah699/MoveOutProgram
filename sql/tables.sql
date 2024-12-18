DROP TABLE IF EXISTS SharedLabels;
DROP TABLE IF EXISTS QRScans;
DROP TABLE IF EXISTS Sessions;
DROP TABLE IF EXISTS AuditLog;
DROP TABLE IF EXISTS BoxLabels;
DROP TABLE IF EXISTS LabelContents;
DROP TABLE IF EXISTS BoxContents;
DROP TABLE IF EXISTS Boxes;
DROP TABLE IF EXISTS Labels;
DROP TABLE IF EXISTS Users;

CREATE TABLE Users (
    UserID INT PRIMARY KEY AUTO_INCREMENT,
    Email VARCHAR(255) UNIQUE NOT NULL,
    PasswordHash VARCHAR(255) DEFAULT '0',
    Salt VARCHAR(255) DEFAULT '0',
    FullName VARCHAR(255),
    GoogleID VARCHAR(255) UNIQUE,
    Username VARCHAR(50) UNIQUE NULL,
    ProfilePicture VARCHAR(255) DEFAULT '/uploads/profile_pictures/default.png',
    EmailVerified BOOLEAN DEFAULT FALSE,
    VerificationCode INT,
    VerificationExpiresAt DATETIME,
    RegisteredAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    IsDeactivated BOOLEAN DEFAULT FALSE,
    DeactivationToken VARCHAR(64) DEFAULT NULL,
    AdminLevel TINYINT DEFAULT 0,  -- IMPORTANT 0: Regular user, 1: Admin, 2: Super Admin
    CONSTRAINT uc_Email UNIQUE (Email)
);

CREATE TABLE Labels (
    LabelID INT AUTO_INCREMENT PRIMARY KEY,
    UserID INT NOT NULL,
    LabelDesign VARCHAR(255),
    LabelName VARCHAR(255),
    LabelOption VARCHAR(50),
    Status ENUM('public', 'private') DEFAULT 'private',
    InsuranceLogo VARCHAR(255),
    CreatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    AccessCode VARCHAR(6),
    FOREIGN KEY (UserID) REFERENCES Users(UserID) ON DELETE CASCADE
);

CREATE TABLE LabelContents (
    ContentID INT PRIMARY KEY AUTO_INCREMENT,
    LabelID INT,
    ContentText TEXT,
    ContentData VARCHAR(255),
    ContentURL VARCHAR(255),
    CreatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ContentType VARCHAR(20),
    FOREIGN KEY (LabelID) REFERENCES Labels(LabelID) ON DELETE CASCADE
);

CREATE TABLE AuditLog (
    LogID INT PRIMARY KEY AUTO_INCREMENT,
    UserID INT,
    ActionDescription TEXT,
    Timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (UserID) REFERENCES Users(UserID) ON DELETE CASCADE
);

CREATE TABLE Sessions (
    SessionID INT PRIMARY KEY AUTO_INCREMENT,
    UserID INT,
    SessionToken VARCHAR(255) UNIQUE,
    CreatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ExpiresAt TIMESTAMP,
    FOREIGN KEY (UserID) REFERENCES Users(UserID) ON DELETE CASCADE
);

CREATE TABLE QRScans (
    ScanID INT PRIMARY KEY AUTO_INCREMENT,
    LabelID INT,
    ScannedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (LabelID) REFERENCES Labels(LabelID) ON DELETE CASCADE
);

CREATE TABLE SharedLabels (
    ShareID INT PRIMARY KEY AUTO_INCREMENT,
    LabelID INT NOT NULL,
    ShareToken VARCHAR(255) UNIQUE NOT NULL,
    RecipientEmail VARCHAR(255) NOT NULL,
    RecipientUserID INT, 
    SharedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ExpiresAt TIMESTAMP NULL,
    FOREIGN KEY (LabelID) REFERENCES Labels(LabelID) ON DELETE CASCADE,
    FOREIGN KEY (RecipientUserID) REFERENCES Users(UserID) ON DELETE CASCADE
);

CREATE TABLE InsuranceBoxItems (
    InsuranceItemID INT PRIMARY KEY AUTO_INCREMENT,
    LabelID INT NOT NULL,
    ItemName VARCHAR(255),
    ItemValue DECIMAL(10, 2),
    Currency VARCHAR(10),
    FOREIGN KEY (LabelID) REFERENCES Labels(LabelID) ON DELETE CASCADE
);
