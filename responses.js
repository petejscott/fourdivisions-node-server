module.exports = 
{
    allOkay : {statuscode:200,message:"everything is okay"},
    databaseError : {statuscode:500,message:"an error occurred"},
    clientUnknown : {statuscode:401,message:"client unauthorized 1000"},
    clientUnauthorizedBadHash : {statuscode:401,message:"client unauthorized 1001"},
    userUnauthorizedNullToken : {statuscode:401,message:"user unauthorized 1002"},
    userUnauthorizedBadIP : {statuscode:401,message:"user unauthorized 1003"},
    userUnauthorizedExpiredToken : {statuscode:401,message:"user unauthorized 1004"},
    badRequest : {statuscode:404,message:"invalid url"},
    missingRequiredInput : {statuscode:400,message:"missing required input"},
    successfulLogin : function(token)
    {
        return {statuscode:200,userToken:token};
    }
};
// exports.clientUnauthorized = {statuscode:401,message:"client unauthorized"};
// exports.userUnauthorizedNullToken = {statuscode:401,message:"user unauthorized 1002"};
// exports.userUnauthorizedBadIP = {statuscode:401,message:"user unauthorized 1003"};
// exports.userUnauthorizedExpiredToken = {statuscode:401,message:"user unauthorized 1004"};
// exports.badRequest = {statuscode:404,message:"bad request"};
// exports.loginSuccessful = function(token) {statuscode:200,userToken:token};