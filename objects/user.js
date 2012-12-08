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
    mongoose.model("User", User);
};
