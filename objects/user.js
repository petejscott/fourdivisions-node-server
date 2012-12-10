var mongoose = require('mongoose');
var Schema = mongoose.Schema;

module.exports = function()
{
    var User = new Schema(
    {
        name        : String,
        password    : String,
        email       : String,
        salt        : String,
        createDate  : Date
    });
    User.methods.createSalt = function()
    {
        try
        {
            // synchronous.
            console.log('creating new salt');
            var buf = crypto.randomBytes(64);
            this.salt = buf.toString('hex');
        }
        catch (ex)
        {
            //TODO handle error
        }
    }
    mongoose.model("User", User);
};
