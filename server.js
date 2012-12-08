var http = require('http'),
    url = require('url'),
    util = require('util'),
    events = require('events'),
    crypto = require('crypto'),
    mongoose = require('mongoose'),
    responses = require('./responses');

var db = mongoose.createConnection('mongodb://localhost/4d_data');

// ought to move Application to a module. I can see it growing a bit more.
var Application = {};
Application.userTokenTTL = 30;  // minutes
Application.port = 8080;

// Should probably move this to a module (or application?)
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

// Need a better way to organize db crap. recommendations?
db.on('error', console.error.bind(console, 'db connection error:'));
db.once('open', function callback () 
{
    console.log('database connected');
});

// Move schemas and models to modules.
var appKeySchema = new mongoose.Schema(
{
    appId : String,
    privateKey : String
});
var AppKeyModel = db.model('AppKey',appKeySchema);

// Methods that actually do stuff that has been requested of the API
function appStatus(data)
{
    Application.emitter.success(responses.allOkay);
}
function doLogin(data)
{
    // verify data.username, data.password
    
    // create userToken and return it to the user
    userToken = createUserToken(data);
    Application.emitter.success(responses.successfulLogin(userToken));
}

// Methods that are called from the primary handler. 
// I feel like this is over-organized.
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

// add a new app ("client") id and private key to the datastore
function authorizeApplication(appId,privateKey)
{
    var appKey = new AppKeyModel({ appId:appId,privateKey:privateKey });
    appKey.save(function(err,appKey)
    { 
        if (err) console.log('could not save appKey '+JSON.stringify(appKey)); 
    });
    console.log(appKey);
}
// quick hash validation. should add data.payload as an argument and return the
// value so I can reuse it for other hashes as well... and rename "getHash()"
function validateHash(data,privateKey)
{    
    // hash data.payload with private key
    var hmac = crypto.createHmac('sha256',privateKey)
                .update(JSON.stringify(data.payload))
                .digest('hex');
    // ensure hash matches data.hash
    if (hmac != data.hash)
    {
        return false;
    }
    return true;
}

// this does a number of general preliminary checks:
// * verify required data is present in the post
// * verifies the application sending us the data is known 
//   and trusted.
// * verifies the data in the posted payload matches the hash
//   it was sent along with.
function validateRequest(data)
{
    if (typeof(data.client) == 'undefined' || 
        typeof(data.payload) == 'undefined' || 
        typeof(data.hash) == 'undefined')
    {
    	Application.emitter.error(responses.missingRequiredInput);
    }
    
    // look up private key matching data.client 
    //(401 (client unauthorized) on failure)
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
	    // let the app know we've validated the request.
            Application.emitter.validatedRequest(data);
        }
    });
}

// this verifies that we know who the user is and (theoretically) makes
// it a pain to fake that information.
// the data contains a userToken, which we generated and stored in the db and 
// gave back to the user when they first logged in. they pass this on 
// subsequent calls to the API. the token is a hash of the user's ID and their 
// remote address (hashed with the app's private key). NOTE: ENDANGERS THE 
// PRIVATE KEY. NEEDS TO BE SALTED WITH SOMETHING ELSE MORE RANDOM.
// Using the remote address helps prevent hijacking, and the tokens expire 
// periodically.
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
    server_userToken = 
    {
        token:'c05f1ca39c2448977ebecde12da92bedfe4511a6e8a1a4c75a5fb137c0c77771',
        expires:1354886936952
    };
    
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

// create a userToken. (note: don't forget to salt this. just stick a random 
// in the user's db record).
function createUserToken(data)
{
    // create userToken
    userToken = crypto.createHmac('sha256',Application.privatekey)
                      .update('1000')
                      .update(data.ipAddress)
                      .digest('hex');
                      
    // create expiration
    var date = new Date();
    date.setMinutes(date.getMinutes() + Application.userTokenTTL);
    var expires = date.valueOf();
    
    var server_userToken = {token: userToken,expires:expires};
    console.log(server_userToken);
    //TODO save to db 'userTokens' along with utctime + application.userTokenTTL
    
    return server_userToken;
}

// write a response (to both server for testing and to client).
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

// handles the mapping of pathname to methods.
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
    
    var urlParameters = url.parse(req.url, true);

    // THIS IS TEST DATA
    var data = 
    { 
        userToken: 'c05f1ca39c2448977ebecde12da92bedfe4511a6e8a1a4c75a5fb137c0c77771', 
        payload: {'hello':'hello'}, 
        hash: '93eccb8d5dc0a896b094d326d40f5a266b944fe74ba9b11d3b2b6bf502264cd7', 
        client: 'testApplication',
        parameters: urlParameters, // add url parameters to data
        ipAddress: req.connection.remoteAddress // add ip address to data
    }
    // In real-world, data object will be passed to us from the client. We want to ADD 
    // data to it, though (overwrite if already exists!). 
    // Add to existing data object: set data.parameters = urlParameters;
    // Add to existing data object: set ipAddress to req.connection.remoteAddress
    
    // TEST DATA calculate the hash here (this should be calculated 
    // and passed by the client)
    data.hash = crypto.createHmac('sha256','this is my private key')
                      .update(JSON.stringify(data.payload))
                      .digest('hex');
    
    // here's our flow control. I'm not sure how PRACTICAL this approach is.
    // * any emitted request_error or request_success simply write the provided 
    //   status object to the client (with appropriate http statuscode.
    // * the only method we directly call is validateRequest. If that method 
    //   succeeds it emits a "validatedRequest" event, which we detect. We 
    //   then call authenticateUser().
    // * if authenticateUser() succeeds, it emits an "authenticated" event, and we 
    //   then call the method the user actually requested. 
    Application.emitter = new Emitter();
    Application.emitter.on('event:request_error',
	function(status){writeOut(res,status)});
    Application.emitter.on('event:request_success',
	function(status){writeOut(res,status)});
    Application.emitter.on('event:validatedRequest',
	function(data){authenticateUser(data)});
    Application.emitter.on('event:authenticated',
	function(data){routeRequest(data)});
    
    validateRequest(data);
}

http.createServer(onRequest).listen(Application.port);
console.log('listening on port %d',Application.port);

