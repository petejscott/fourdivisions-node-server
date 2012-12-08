var http = require('http'),
    url = require('url'),
    util = require('util'),
    events = require('events'),
    crypto = require('crypto'),
    mongoose = require('mongoose'),
    responses = require('./responses');

var db = mongoose.createConnection('mongodb://localhost/4d_data');
var currentConnection = {};
var Application = {};
Application.hasErrors = false;
Application.privatekey = 'asdfasfasdfasdfasdfasdf'; //example
Application.userTokenTTL = 30;  // minutes
Application.port = 8080;

Emitter = function()
{
    events.EventEmitter.call(this);
    this.success = function(data)
    {
        this.emit('event:request_success',data);
    }
    this.error = function(data)
    {
        this.emit('event:request_error',data);
    }
    this.authenticated = function(data)
    {
        this.emit('event:authenticated',data);
    }
    this.validatedRequest = function(data)
    {
        this.emit('event:validatedRequest',data);
    }
}
util.inherits(Emitter,events.EventEmitter);

db.on('error', console.error.bind(console, 'db connection error:'));
db.once('open', function callback () 
{
    console.log('database connected');
});

var appKeySchema = new mongoose.Schema(
{
    appId : String,
    privateKey : String
});
var AppKeyModel = db.model('AppKey',appKeySchema);

function appStatus(data)
{
    Application.emitter.success(responses.allOkay);
}
function doLogin(data)
{
    // verify data.username, data.password
    
    // create userToken and return it to the user
    userToken = createUserToken();    
    Application.emitter.success(responses.successfulLogin(userToken));
}

function mTest(data)
{
	appStatus(data);
}
function mLogin(data)
{
    doLogin(data);
}
function mStatus(data)
{
    appStatus(data);
}

function authorizeApplication(appId,privateKey)
{
    var appKey = new AppKeyModel({ appId:appId,privateKey:privateKey });
    appKey.save(function(err,appKey){ if (err) console.log('could not save appKey '+JSON.stringify(appKey)); });
    console.log(appKey);
}
function validateHash(data,privateKey)
{    
    // hash data.payload with private key
    var hmac = crypto.createHmac('sha256',privateKey).update(JSON.stringify(data.payload)).digest('hex');
    // ensure hash matches data.hash
    if (hmac != data.hash)
    {
        return false;
    }
    return true;
}
function validateRequest(data)
{
	if (typeof(data.client) == 'undefined' || 
	    typeof(data.payload) == 'undefined' || 
	    typeof(data.hash) == 'undefined')
	{
		Application.emitter.error(responses.missingRequiredInput);
	}
    
	// look up private key matching data.client (401 (client unauthorized) on failure)
	AppKeyModel.findOne({ appId:data.client },function(err,appKey)
    {
        if (err)
        {
            console.log(err);
            Application.emitter.error(responses.databaseError);
        }
        else if (appKey == null)
        {
            Application.emitter.error(responses.clientUnknown);
        }
        else if (!validateHash(data,appKey.privateKey))
        {
            Application.emitter.error(responses.clientUnauthorizedBadHash);
        }
        else
        {
            Application.emitter.validatedRequest(data);
        }
    });
}
function authenticateUser(data)
{
    // verify they passed a userToken
	if (data.userToken == null)
	{
		Application.emitter.error(responses.userUnauthorizedNullToken);
        return;
	}
	
	// look up data.parameters.userToken in token table (not found: 1003)
	// TEST
	//console.log('user token: '+crypto.createHmac('sha256',application.privatekey).update('1000').update(currentConnection.remoteAddress).digest('hex'));
	server_userToken = {token:'c05f1ca39c2448977ebecde12da92bedfe4511a6e8a1a4c75a5fb137c0c77771',expires:1354886936952};
    
	// if found, verify ip matches ip of requestor
	if (data.userToken != server_userToken.token)
    {
        Application.emitter.error(responses.userUnauthorizedBadIP);
        return;
    }
    
	// if it does, verify createtime is not too old
	if (server_userToken.expires < new Date().valueOf())
    {
        Application.emitter.error(responses.userUnauthorizedExpiredToken);
        return;
    }
	
	// if it isn't we're OK!
	Application.emitter.authenticated(data);
}
function createUserToken()
{
    // create userToken
    userToken = crypto.createHmac('sha256',Application.privatekey).update('1000').update(currentConnection.remoteAddress).digest('hex');
    // create expiration
    var date = new Date();
    date.setMinutes(date.getMinutes() + Application.userTokenTTL);
    var expires = date.valueOf();
    
    var server_userToken = {token: userToken,expires:expires};
    console.log(server_userToken);
    //TODO save to db 'userTokens' along with utctime + application.userTokenTTL
    
    return server_userToken;
}
function writeOut(res,responsedata)
{
    console.log(JSON.stringify(responsedata));
	writeResponseHeader(res,responsedata.statuscode);
	res.end(JSON.stringify(responsedata));
}
function writeResponseHeader(res,statuscode)
{
	res.writeHead(statuscode, {'content-type':'application/json'});
}

var mapping = {}
mapping['/'] = mStatus;
mapping['/test'] = mTest;
mapping['/login'] = mLogin;
function routeRequest(data)
{
    var doMethod = mapping[data.parameters.pathname];
    if (doMethod)
    {
        doMethod(data);
    }
    else
    {
        events.emit('event:request_error',responses.badRequest);
    }
}
function onRequest(req,res)
{
    //TODO create a listener for request_error event that ends the response and breaks out of this workflow
    
    var urlParameters = url.parse(req.url, true);

    // TEST POST
    var data = 
    { 
        userToken: 'c05f1ca39c2448977ebecde12da92bedfe4511a6e8a1a4c75a5fb137c0c77771', 
        payload: {'hello':'hello'}, 
        hash: '93eccb8d5dc0a896b094d326d40f5a266b944fe74ba9b11d3b2b6bf502264cd7', 
        client: 'testApplication',
        parameters: urlParameters // add url parameters to data
    }
    // NON-TEST: data.parameters = urlParameters;
    
    // TEST calculate the hash here (this should be calculated and passed by the client)
    data.hash = crypto.createHmac('sha256','this is my private key').update(JSON.stringify(data.payload)).digest('hex');
    
    currentConnection = req.connection;
        
    Application.emitter = new Emitter();
    Application.emitter.on('event:request_error',function(status){writeOut(res,status)});
    Application.emitter.on('event:request_success',function(status){writeOut(res,status)});
    Application.emitter.on('event:validatedRequest',function(data){authenticateUser(data)});
    Application.emitter.on('event:authenticated',function(data){routeRequest(data)});
    
    validateRequest(data);
}

http.createServer(onRequest).listen(Application.port);
console.log('listening on port %d',Application.port);

