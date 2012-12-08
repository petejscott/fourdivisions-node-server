var models = ['./client.js', './user.js','./userToken.js'];

// rather brilliant way to initialize all the models, taken from
// http://stackoverflow.com/questions/10081611/mongoose-schema-creation/10083152#10083152
exports.initialize = function()
{
    var l = models.length;
    for (var i = 0; i < l; i++)
    {
        require(models[i])();
    }
};
