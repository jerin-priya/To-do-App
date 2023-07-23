require("dotenv").config();
const express = require("express");
const mysql = require("mysql");

const app = express();
app.use(express.json());
app.use(
  express.urlencoded({
    extended: true,
  })
);

// include middleware for serving static files (css/images folder and error pages folder)
app.use(express.static(__dirname + "/public/views"));
app.use(express.static(__dirname + "/public/error-pages"));

// set view engine to ejs, allows us to use ejs in the public folder
app.set("views", __dirname + "/public");
app.set("view engine", "ejs");

// declare connection pool to MySQL database
var connectionPool = mysql.createPool({
    connectionLimit: 100,
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
  });
  
  // middleware to catch all other undefined routes, sends a 404 not found error and its error page
app.use((req, res, next) => {
    res.status(404).sendFile(__dirname + "/public/error-pages/not-found.html");
  });
  
  // app listens on the port
  app.listen(process.env.PORT);