const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const bcrypt = require('bcrypt-nodejs');

// define our model
const userSchema  = new Schema({
    email: {
        type: String,
        unique: true,
        lowercase: true
    },
    password: String
});

// on save hook, encrypt password
userSchema.pre('save', function(next) {
    // get access to user model
    const user = this;

    // generate a salt
    bcrypt.genSalt(10, function(e, salt) {
        if (e) return next(e);

        // hash our password with salt
        bcrypt.hash(user.password, salt, null, function(e , hash) {
            if (e) return next(e);

            user.password = hash;
            next();
        });
    });
});

// compare passwords - req.password to db.password
// check if -> db (hashed password) === hashed(req.password) + salt
userSchema.methods.comparePassword = function(requestPassword, callback) {
    bcrypt.compare(requestPassword, this.password, function(e, isMatch) {
       if(e) return callback(e, false);
        
       return callback(null, isMatch);
    }); 
};

// create the model class
const UserModel = mongoose.model('user', userSchema);

// export the model
module.exports = UserModel;