const jwt = require('jwt-simple');
const config = require('../config');
const UserModel = require('../models/user_model');

function tokenForUser(user) {
    const timestamp = new Date().getTime();

    return jwt.encode({ sub: user.id, iat: timestamp }, config.secret);
}

module.exports = {
    signup: function (req, res, next) {
        const { email, password } = req.body;

        if (!email || !password) res.status(422).send({ error: 'You must provide email and password' });

        // see if a user with given email exists
        UserModel.findOne({ email: email }, (e, user) => {
            if (e) return next(e);
            // if user exists return an error
            if (user) {
                return res.status(422).send({ error: 'Email is already taken' });
            }
            // if user does not exist, create and save user record
            const newUser = new UserModel({ email: email, password: password });

            newUser.save((e) => {
                if (e) return next(e);

                // return res.json(newUser);
                return res.json({ token: tokenForUser(newUser) });
            });

        });



        // respond to request indicating the user was created
    },
    signin: function (req, res, next) {
        // user has already had their email and password
        // we need just give him a token
        // from passport service middleware return done(null, user)
        // then assign it to req.user
        return res.json({ token: tokenForUser(req.user) });
    }
};