var mongoose = require('mongoose'),
    application = require('./application');
    responses = require('../responses');
var Schema = mongoose.Schema;

module.exports = function()
{
    var UserToken = new Schema(
    {
        token       : String,
        expiration  : String,
        createDate  : Date
    });
    UserToken.methods.verify = function(token)
    {
        if (token != this.token)
        {
            application.emitter.error(responses.userUnauthorizedBadIP);
            return false;
        }
        else if (this.expiration < new Date().valueOf())
        {
            application.emitter.error(responses.userUnauthorizedExpiredToken);
            return false;
        }
        return true;
    };

    mongoose.model("UserToken", UserToken);
};
