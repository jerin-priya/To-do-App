require("dotenv").config();
const express = require("express");
const session = require("express-session");
const mySQlStore = require("express-mysql-session")(session);
const mysql = require("mysql");
const bcrypt = require("bcryptjs");
const flash = require("connect-flash");

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

  // initiailize the sessionStore, which will allow express-mysql-session to store session data into the database
const sessionStore = new mySQlStore(
    {
      createDatabaseTable: false,
    },
    connectionPool
  );

  /******************** FUNCTIONS *********************/

// registers a user in the database and gives them default settings
function register(username, password, confirmPassword) {
    return new Promise((resolve, reject) => {
      if (password != confirmPassword) {
        reject(new Error("Passwords need to match."));
      } else {
        userExists(username)
          .then((response) => {
            if (response) {
              reject(new Error(`This user already exists.`));
            } else {
              insertUser(username, password)
                .then((response) => {
                  insertSettings(response.user_id)
                    .then(() => {
                      resolve({
                        body: {
                          message: `Successfully registered.`,
                        },
                      });
                    })
                    .catch((error) => {
                      reject(new Error(error.message));
                    });
                })
                .catch((error) => {
                  reject(new Error(error.message));
                });
            }
          })
          .catch((error) => {
            reject(new Error(error.message));
          });
      }
    });
  }


  // check if a user already exists in the database
function userExists(username) {
    return new Promise((resolve, reject) => {
      findUser(username)
        .then((response) => {
          if (response.length > 0) {
            resolve(true);
          } else {
            resolve(false);
          }
        })
        .catch((error) => {
          reject(new Error(error.message));
        });
    });
  }
  
  
  
  // middleware to catch all other undefined routes, sends a 404 not found error and its error page
app.use((req, res, next) => {
    res.status(404).sendFile(__dirname + "/public/error-pages/not-found.html");
  });
  
  // app listens on the port
  app.listen(process.env.PORT);