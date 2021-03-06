module.exports =
{
    allOkay : {statuscode:200,message:"everything is okay"},
    databaseError : {statuscode:500,message:"an error occurred"},
    clientUnknown : {statuscode:401,message:"client unauthorized 1000"},
    clientUnauthorizedBadHash : {statuscode:401,message:"client unauthorized 1001"},
    userUnauthorizedNullToken : {statuscode:401,message:"user unauthorized 1002"},
    userUnauthorizedBadIP : {statuscode:401,message:"user unauthorized 1003"},
    userUnauthorizedExpiredToken : {statuscode:401,message:"user unauthorized 1004"},
    userUnauthorizedBadToken : {statuscode:401,message:"invalid token 1005"},
    userUnauthorizedInvalidCredentials : {statuscode:402,message:"invalid username/password 1006"},
    badRequest : {statuscode:404,message:"invalid url"},
    missingRequiredInput : {statuscode:400,message:"missing required input"},
    successfulLogin : function(token)
    {
        return {statuscode:200,userToken:token};
    }
};
