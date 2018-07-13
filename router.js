const authenticationController = require('./controllers/authentication_controller');
const passportService = require('./services/passport_service');
const passport = require('passport');

const requireAuth = passport.authenticate('jwt', { session: false }); // middleware
const requireSignin = passport.authenticate('local', { session: false }); // middleware

module.exports = (app) => {
    app.get('/', requireAuth, function (req, res) {
        res.send({ hi: 'there' });
    });
    app.post('/signin', requireSignin, authenticationController.signin);
    app.post('/signup', authenticationController.signup);
}