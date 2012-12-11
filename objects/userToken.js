var mongoose = require('mongoose'),
    emitter = require('../application/events');
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
            emitter.error(responses.userUnauthorizedBadIP);
            return false;
        }
        else if (this.expiration < new Date().valueOf())
        {
            emitter.error(responses.userUnauthorizedExpiredToken);
            return false;
        }
        return true;
    };

    mongoose.model("UserToken", UserToken);
};
