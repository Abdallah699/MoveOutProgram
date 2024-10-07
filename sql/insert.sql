
use moveOut;
SET GLOBAL local_infile = 1;

USE moveOut;

SET GLOBAL local_infile = 1;

LOAD DATA LOCAL INFILE '/home/abdalla/moveOut/MoveOutProject/sql/admin_user.csv'
INTO TABLE Users
FIELDS TERMINATED BY ',' 
LINES TERMINATED BY '\n'
IGNORE 1 ROWS 
(Email, PasswordHash, Salt, FullName, GoogleID, Username, ProfilePicture, EmailVerified, VerificationCode, VerificationExpiresAt, IsDeactivated, DeactivationToken, Admin);

-- Same for other CSV files, adjust paths accordingly


LOAD DATA LOCAL INFILE 'Labels.csv'
INTO TABLE Labels
FIELDS TERMINATED BY ',' 
LINES TERMINATED BY '\n'
IGNORE 1 LINES;

LOAD DATA LOCAL INFILE 'Boxes.csv'
INTO TABLE Boxes
FIELDS TERMINATED BY ',' LINES TERMINATED BY '\n'
IGNORE 1 LINES;

LOAD DATA LOCAL INFILE 'BoxContents.csv'
INTO TABLE LabelContents
CHARSET utf8
FIELDS TERMINATED BY ',' 
LINES TERMINATED BY '\n'
IGNORE 1 ROWS;

LOAD DATA LOCAL INFILE 'BoxLabels.csv'
INTO TABLE BoxLabels
FIELDS TERMINATED BY ',' LINES TERMINATED BY '\n'
IGNORE 1 LINES;

LOAD DATA LOCAL INFILE 'AuditLog.csv'
INTO TABLE AuditLog
FIELDS TERMINATED BY ',' LINES TERMINATED BY '\n'
IGNORE 1 LINES;

LOAD DATA LOCAL INFILE 'Sessions.csv'
INTO TABLE Sessions
FIELDS TERMINATED BY ',' LINES TERMINATED BY '\n'
IGNORE 1 LINES;