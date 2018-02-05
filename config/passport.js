const passport = require('passport');
const request = require('request');
const LocalStrategy = require('passport-local').Strategy;
const StravaStrategy = require('passport-strava').Strategy; // VV
const OpenIDStrategy = require('passport-openid').Strategy;
const OAuthStrategy = require('passport-oauth').OAuthStrategy;
const OAuth2Strategy = require('passport-oauth').OAuth2Strategy;

const User = require('../models/User');

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser((id, done) => {
  User.findById(id, (err, user) => {
    done(err, user);
  });
});

/**
 * Sign in using Email and Password.
 */
passport.use(new LocalStrategy({ usernameField: 'email' }, (email, password, done) => {
  User.findOne({ email: email.toLowerCase() }, (err, user) => {
    if (err) { return done(err); }
    if (!user) {
      return done(null, false, { msg: `Email ${email} not found.` });
    }
    user.comparePassword(password, (err, isMatch) => {
      if (err) { return done(err); }
      if (isMatch) {
        return done(null, user);
      }
      return done(null, false, { msg: 'Invalid email or password.' });
    });
  });
}));

/**
 * OAuth Strategy Overview
 *
 * - User is already logged in.
 *   - Check if there is an existing account with a provider id.
 *     - If there is, return an error message. (Account merging not supported)
 *     - Else link new OAuth account with currently logged-in user.
 * - User is not logged in.
 *   - Check if it's a returning user.
 *     - If returning user, sign in and we are done.
 *     - Else check if there is an existing account with user's email.
 *       - If there is, return an error message.
 *       - Else create a new account.
 */


// callbackURL: '/auth/strava/callback',
//   callbackURL: "http://127.0.0.1:8080/auth/strava/callback",

/**
 * Sign in with Strava
 */
passport.use(new StravaStrategy({
  clientID: process.env.STRAVA_CLIENT_ID,
  clientSecret: process.env.STRAVA_CLIENT_SECRET,
  callbackURL: "/auth/strava/callback",
  passReqToCallback: true
}, 
(req, accessToken, refreshToken, profile, done) => {
if (req.user) {  // logged-in user 
  User.findOne({ strava: profile.id }, (err, existingUser) => {  // Strava user already known
    if (existingUser) {
      req.flash('errors', { msg: 'There is already a Strava account that belongs to you. Sign in with that account or delete it, then link it with your current account.' });
      done(err);
    } else {
        User.findById(req.user.id, (err, user) => { 
        if (err) { return done(err); }
        user.strava = profile.id;
        user.tokens.push({ kind: 'strava', accessToken });
        user.profile.name = user.profile.name || profile.displayName;
        user.profile.picture = user.profile.picture || profile._json.avatar_url;
        user.profile.location = user.profile.location || profile._json.location;
        user.profile.website = user.profile.website || profile._json.blog;
        user.save((err) => {
          req.flash('info', { msg: 'Strava account has been linked.' });
          done(err, user);
        });
      });
    }
  });
} else {  // unauthenticated user
  User.findOne({ strava: profile.id }, (err, existingUser) => {
    if (err) { return done(err); }
    if (existingUser) {
      return done(null, existingUser);
    }  // not working MM
    User.findOne({ email: profile._json.email }, (err, existingEmailUser) => {   // email already exists
      if (err) { return done(err); }
      if (existingEmailUser) {
        req.flash('errors', { msg: 'There is already an account using this email address. Sign in to that account and link it with Strava manually from Account Settings.' });
        done(err);
      } else {
        const user = new User();
        user.email = profile._json.email;
        user.strava = profile.id;
        user.tokens.push({ kind: 'strava', accessToken });
        user.profile.name = profile.displayName;
        user.profile.picture = profile._json.avatar_url;
        user.profile.location = profile._json.location;
        user.profile.website = profile._json.blog;
        user.save((err) => {
          done(err, user);
        });
      }
    });
  });
}
}));

/**
 * Login Required middleware.
 */
exports.isAuthenticated = (req, res, next) => {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect('/login');
};

/**
 * Authorization Required middleware.
 */
exports.isAuthorized = (req, res, next) => {
  const provider = req.path.split('/').slice(-1)[0];
  const token = req.user.tokens.find(token => token.kind === provider);
  if (token) {
    next();
  } else {
    res.redirect(`/auth/${provider}`);
  }
};
