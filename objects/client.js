var mongoose = require('mongoose');
var Schema = mongoose.Schema;

module.exports = function()
{
    var Client = new Schema(
    {
        clientId     : String,
        privateKey   : String,
        createDate   : Date
    });
    mongoose.model("Client", Client);
};
