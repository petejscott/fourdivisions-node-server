var mongoose = require('mongoose');
var Schema = mongoose.Schema;

module.exports = function()
{
    var UserToken = new Schema(
    {
        token       : String,
        expiration  : String,
        createDate  : Date
    });
    mongoose.model("UserToken", UserToken);
};
