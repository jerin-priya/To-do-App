require("dotenv").config();
const express = require("express");
const session = require("express-session");
const mySQlStore = require("express-mysql-session")(session);
const mysql = require("mysql");
const bcrypt = require("bcryptjs");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const jwt = require("jsonwebtoken");
const passportJWT = require("passport-jwt");
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

  // retrieves user data by username, returns empty array if user does not exist
function findUser(username) {
    return new Promise((resolve, reject) => {
      connectionPool.getConnection((err, connection) => {
        if (err) {
          connection.release();
          reject(new Error(err.message));
        } else {
          connection.query(
            "SELECT * FROM users WHERE USERNAME=?",
            username,
            function (error, results, fields) {
              if (error) {
                reject(new Error(error.message));
              } else {
                resolve(results);
              }
  
              connection.release();
            }
          );
        }
      });
    });
  }

  // inserts a user into the database
function insertUser(username, password) {
    return new Promise((resolve, reject) => {
      genPassword(password)
        .then((response) => {
          const salt = response.salt;
          const hash = response.hash;
  
          connectionPool.getConnection((err, connection) => {
            if (err) {
              connection.release();
              reject(new Error(err.message));
            } else {
              connection.query(
                "INSERT INTO users (USERNAME, HASH, SALT, IS_ADMIN) VALUES (?, ?, ?, 0)",
                [username, hash, salt],
                function (error, results, fields) {
                  if (error) {
                    reject(new Error(error.message));
                  } else {
                    resolve({
                      message: "User successfully inserted",
                      user_id: results.insertId,
                    });
                  }
  
                  connection.release();
                }
              );
            }
          });
        })
        .catch((error) => {
          reject(new Error(error.message));
        });
    });
  }

  // generates a random salt to hash a user password, returns the salt and the hashed password
async function genPassword(password) {
    let salt = await bcrypt.genSalt();
    let hash = await bcrypt.hash(password, salt);
  
    return {
      salt: salt,
      hash: hash,
    };
  }

  // inserts default settings into the database for a new user
function insertSettings(user_id) {
    return new Promise((resolve, reject) => {
      connectionPool.getConnection((err, connection) => {
        if (err) {
          connection.release();
          reject(new Error(err.message));
        } else {
          connection.query(
            `INSERT INTO settings (USER_ID, SHOW_DELETE_LIST_POPUP, FONT_FAMILY, THEME) VALUES (?, 1, "\'Trebuchet MS\'\, \'Lucida Sans Unicode\'\, \'Lucida Grande'\, \'Lucida Sans\'\, Arial\, sans-serif", "Standard")`,
            [user_id],
            function (error, results, fields) {
              if (error) {
                reject(new Error(error.message));
              } else {
                resolve({
                  message: "Setting successfully inserted",
                  setting_id: results.insertId,
                });
              }
  
              connection.release();
            }
          );
        }
      });
    });
  }
  
  // verifies the login credentials of a user
function verifyUser(username, password, callback) {
    findUser(username)
      .then((response) => {
        if (response.length === 0) {
          return callback(null, false, {
            message: "Incorrect username or password.",
          });
        } else {
          verifyPassword(password, response[0].SALT, response[0].HASH)
            .then((verified) => {
              if (verified) {
                const user = {
                  id: response[0].ID,
                  username: response[0].USERNAME,
                  hash: response[0].HASH,
                  salt: response[0].SALT,
                };
  
                return callback(null, user);
              } else {
                return callback(null, false, {
                  message: "Incorrect username or password.",
                });
              }
            })
            .catch((error) => {
              return callback(error);
            });
        }
      })
      .catch((error) => {
        return callback(error);
      });
  }
  
  // compares the hash stored in the database to the hash generated with the user-entered password
  async function verifyPassword(password, salt, hash) {
    const hashVerify = await bcrypt.hash(password, salt);
    return hash === hashVerify;
  }

  // middleware that checks if the user session is authenticated, sends a 401 unauthorized error and its error page if not
function isAuth(req, res, next) {
    if (req.isAuthenticated()) {
      next();
    } else {
      req.flash(
        "error",
        "You are not currently logged in. Please login first to access and edit your lists."
      );
      return res
        .status(401)
        .sendFile(__dirname + "/public/error-pages/not-authorized.html");
    }
  }
  /***************** PASSPORT.JS and WebToken *************************/

// use the verifyUser function as a LocalStrategy for Passport.js authentication
const strategy = new LocalStrategy(verifyUser);
passport.use(strategy);
const ExtractJwt = passportJWT.ExtractJwt;
const JwtStrategy = passportJWT.Strategy;

const jwtOptions = {
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  secretOrKey: "process.env.SECRET_KEY", // Replace with your own secret key
};

// serialize user into browser's session
passport.serializeUser((user, callback) => {
  process.nextTick(() => {
    return callback(null, { id: user.id, username: user.username });
  });
});

// retrieve user from browser's session
passport.deserializeUser((user, callback) => {
    process.nextTick(() => {
      return callback(null, user);
    });
  });

  /************** MIDDLEWARE *********************/

// stores session data into the database
app.use(
    session({
      key: "myKey",
      secret: "session_cookie_secret",
      name: "mycookie",
      store: sessionStore,
      resave: false,
      saveUninitialized: true,
      cookie: {
        maxAge: 6000000,
      },
    })
  );
  
  // initializes Passport.js
  app.use(passport.initialize());
  // replaces session id in request object with user data pulled from deserialize user
  app.use(passport.session());
  // enable flash message system
  app.use(flash());
  

  /******************** ROUTES *******************/

// displays app home page
app.get("/", (req, res, next) => {
    res.sendFile(__dirname + "/public/index.html");
  });

  // renders login page
app.get("/login", (req, res, next) => {
    let flashError = req.flash("error");
    let flashMessage = req.flash("message");
    res.render("login.ejs", {
      flashError: flashError,
      flashMessage: flashMessage,
    });
  });

  // renders login page
app.get("/login", (req, res, next) => {
  let flashError = req.flash("error");
  let flashMessage = req.flash("message");
  res.render("login.ejs", {
    flashError: flashError,
    flashMessage: flashMessage,
  });
});

// displays register page
app.get("/register", (req, res, next) => {
    res.sendFile(__dirname + "/public/register.html");
  });

  // renders user landing page (protected route)
app.get("/landing", isAuth, (req, res, next) => {
    getUserToDos(req.user.id, "␜", "␝")
      .then((response) => {
        return res.render("landing.ejs", {
          flashError: [],
          userToDos: response,
          username: req.user.username,
        });
      })
      .catch((error) => {
        return res.render("landing.ejs", {
          flashError: [error.message],
          userToDos: [],
          username: req.user.username,
        });
      });
  });

  app.get("/logout", (req, res, next) => {
    req.logout((err) => {
      if (err) {
        next(err);
      }
      req.flash("message", "You are now logged out.");
      res.redirect("/login");
    });
  });

  app.post(
    "/login",
    passport.authenticate("local", {
      failureRedirect: "/login",
      failureFlash: true,
      successRedirect: "/landing",
    })
  );

  // registers a user
app.post("/register", (req, res) => {
    register(req.body.username, req.body.password, req.body.confirmPassword)
      .then((response) => {
        return res.send({
          success: true,
          body: response.body,
        });
      })
      .catch((error) => {
        return res.send({
          success: false,
          body: {
            message: error.message,
          },
        });
      });
  });
  
  
  
  
  
  
  
  // middleware to catch all other undefined routes, sends a 404 not found error and its error page
app.use((req, res, next) => {
    res.status(404).sendFile(__dirname + "/public/error-pages/not-found.html");
  });
  
  // app listens on the port
  app.listen(process.env.PORT);