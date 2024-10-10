const mysql = require('mysql2/promise');
const fs = require('fs');
const path = require('path');

// Load MySQL configuration from config.json
const configPath = path.join(__dirname, 'config.json');  // Adjust if config.json is in a different directory
const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));

// Create MySQL connection pool using config.json
const pool = mysql.createPool({
    host: config.host,
    user: config.user,
    password: config.password,
    database: config.database,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
    multipleStatements: config.multipleStatements || false
});

module.exports = pool;
