const LocalStrategy = require("passport-local").Strategy,
  mysql = require("mysql"),
  bcrypt = require("bcrypt"),
  util = require("util");

require("dotenv").config();
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
});
db.connect((err) => {
  if (err) {
    throw err;
  }
  console.log("Connecté au serveur MySQL");
});
const query = util.promisify(db.query).bind(db);
global.querySQL = query;

module.exports = function (passport) {
  passport.serializeUser(function (user, done) {
    done(null, user.id);
  });
  passport.deserializeUser(async function (id, done) {
    await querySQL(
      "SELECT id, email, password FROM users WHERE id = ?",
      [id],
      (err, result) => {
        done(err, result[0]);
      }
    );
  });

  passport.use(
    "local-signup",
    new LocalStrategy(
      {
        usernameField: "email",
        passwordField: "password",
        passReqToCallback: true,
      },

      async function (req, username, password, done) {
        await querySQL(
          "SELECT * FROM users WHERE email = ?",
          [username],
          function (err, rows) {
            if (err) return done(err);
            if (rows.length) {
              return done(
                null,
                false,
                req.flash(
                  "signupMessage",
                  "Désolé cette email est déjà utilisé."
                )
              );
            } else {
              var newUserMysql = {
                username: username,
              };
              bcrypt.hash(password, 10, (err, hash) => {
                var insertQuery =
                  "INSERT INTO users ( email, password ) values (?,?)";
                querySQL(insertQuery, [newUserMysql.username, hash], function (
                  err,
                  result
                ) {
                  newUserMysql.id = result.insertId;
                  return done(null, newUserMysql);
                });
              });
            }
          }
        );
      }
    )
  );

  passport.use(
    "local-login",
    new LocalStrategy(
      {
        usernameField: "email",
        passwordField: "password",
        passReqToCallback: true,
      },
      async (req, username, password, done) => {
        await querySQL(
          "SELECT * FROM users WHERE email = ?",
          [username],
          function (err, result) {
            if (err) return done(err);
            if (!result.length) {
              return done(
                null,
                false,
                req.flash("loginMessage", "Désolé, cet email n'existe pas.")
              ); // req.flash is the way to set flashdata using connect-flash
            }
            bcrypt.compare(password, result[0].password, function (
              err,
              success
            ) {
              if (err) {
                console.log(err);
              }
              if (success) {
                return done(null, result[0]);
              } else {
                return done(
                  null,
                  false,
                  req.flash("loginMessage", "Désolé, mauvais mot de passe")
                );
              }
            });
          }
        );
      }
    )
  );
};
