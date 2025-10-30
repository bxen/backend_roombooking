const mysql = require('mysql2');
const con = mysql.createConnection({
    host:'localhost',
    user:'root',
    password:'',
    database:'room_booking',
    port:3306
});
con.connect((err) => {
    if (err) {
        console.error("Database connection failed:", err);
        return;
    }
    console.log("Connected to MySQL database");
});

module.exports =con;