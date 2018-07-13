const passport = require('passport');
const UserModel = require('../models/user_model');
const config = require('../config');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const LocalStrategy = require('passport-local');

//create local strategy  - login, password -> returns token
const localOptions = { usernameField: 'email' };
const localLogin = new LocalStrategy(localOptions, function (email, password, done) {
    // verify email and password, call done withe the user
    // if it is the correct email and password
    // otherwise, call done with false
    UserModel.findOne({ email: email }, function(e, user) {
        if (e) return done(e, false);
        if(!user) return done(null, false);

        // compare passwords - req.password to db.password
        // check if -> db (hashed password) === hashed(req.password) + salt
        user.comparePassword(password, function(e, isMatch) {
            if(e) return done(e, false); // some error
            if(!isMatch) return done(null, false); // user not found

            return done(null, user);
        })
    });
});


// setup options for JWT Strategy
const jwtOptions = {
    jwtFromRequest: ExtractJwt.fromHeader('authorization'),
    secretOrKey: config.secret
};

// cretae JWT strategy
const jwtLogin = new JwtStrategy(jwtOptions, function (payload, done) {
    // payload === decoded JWT

    // see ifthe user id exists in our DB
    UserModel.findById(payload.sub, function (e, user) {
        if (e) return done(e, false); // false  - no user, searching failed

        // if it does call 'done' with that user
        if (user) return done(null, user);
        // otherwise call done without user object
        else done(null, false); // user not found , serching process ok
    });
});

// tell passport to use this strategy
passport.use(jwtLogin);
passport.use(localLogin);