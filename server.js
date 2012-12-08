var http = require('http'),
    url = require('url'),
    util = require('util'),
    events = require('events'),
    crypto = require('crypto'),
    mongoose = require('mongoose');

var responses = require('./responses');
var models = require('./objects/models').initialize();

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

// Methods that actually do stuff that has been requested of the API
function appStatus(data)
{
    Application.emitter.success(responses.allOkay);
}
function doLogin(data)
{
    // verify data.username, data.password
    var User = db.model('User');
    User.findOne({ name:data.username , password:data.password },
                 function(err,user)
    {
        if (err)
        {
            // return invalid username/password status
        }
        else
        {
            // we found the user. create a random salt
            try
            {
                // synchronous.
                var buf = crypto.randomBytes(256);
                user.salt = buf.toString('hex');
            }
            catch (ex)
            {
                // handle error
            }

            // TODO: wrong, idiot. userToken is its own schema and object.
            user.userToken = createUserToken(data,user);

            // TODO save BOTH the user and the userToken records
            user.save(function(err,user)
            {
                if (err)
                {
                    // handle this. in SOME fashion.
                    return;
                }
                Application.emitter.success(
                    responses.successfulLogin(user.userToken));
                return;
            }

        }
    });
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


// not sure how best to handle this. if we leave encryption up to the CLIENT,
// it won't be shared across multiple clients using the same API.
// I think we just made SSL a requirement. *sigh*
function encrypt(plain)
{
    var cipher = crypto.createCipher('aes-256-cbc','InmbuvP6Z8')
    var e = cipher.update(plain,'utf8','hex');
    e += cipher.final('hex');
    return e;
}
// add a new user to the datastore (note: this takes a plaintext password
// for testing purposes
function addUser(username,password)
{
    var User = db.model('User');
    var user = new User(
    {
        name:username,
        password:encrypt(password),
        email:'pete.j.scott@gmail.com',
        createDate:new Date()
    });
    user.save(function(err,user)
    {
        if (err)
        {
            console.log('could not save user %s',
                        JSON.stringify(user));
        }
        console.log(user);
    });
}
// add a new client id and private key to the datastore
function authorizeClient(clientId,privateKey)
{
    var Client = db.model('Client');
    var client = new Client(
    {
        clientId:clientId,
        privateKey:privateKey,
        createDate:new Date()
    });
    client.save(function(err,client)
    {
        if (err)
        {
            console.log('could not save client authentication %s',
                        JSON.stringify(client));
        }
        console.log(client);
    });
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
// * verifies the client (api consumer) sending us the data is known
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
    var Client = db.model('Client');
    Client.findOne({ clientId:data.client },function(err,client)
    {
        if (err)
        {
            console.log(err);
            Application.emitter.error(responses.databaseError);
        }
        else if (client == null)
        {
            Application.emitter.error(responses.clientUnknown);
        }
        else if (!validateHash(data,client.privateKey))
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
        // if we have no userToken, they need to be trying to log in.
        if (data.parameters.pathname == '/login' &&
            data.username != null &&
            data.password != null)
        {
            // login (is this right? make sure we don't end up running
            // back through mLogin after we exit here
            mLogin(data);
        }
        else
        {
            Application.emitter.error(responses.userUnauthorizedNullToken);
            return;
        }
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
function createUserToken(data,user)
{
    // get the privatekey for the client in use
    var Client = db.model('Client');
    Client.findOne({ clientId:data.client },function(err,client)
    {
        if (err)
        {
            // handle error (same when we can't find the client id elsewhere,
            // though we should never get here, really).
            return;
        }

        // create userToken
        userToken = crypto.createHmac('sha256',client.privateKey)
                        .update(user.name)
                        .update(user.salt)
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
    });
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
        username:'test',
        password:'16679162a9f9fc74ed65ded077651f51',
        userTokenx: 'c05f1ca39c2448977ebecde12da92bedfe4511a6e8a1a4c75a5fb137c0c77771',
        payload: {'hello':'hello'},
        hash: '93eccb8d5dc0a896b094d326d40f5a266b944fe74ba9b11d3b2b6bf502264cd7',
        client: 'testClient',
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

