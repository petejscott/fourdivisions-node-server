var http = require('http'),
    url = require('url'),
    crypto = require('crypto'),
    mongoose = require('mongoose');

// custom modules
var responses = require('./responses'),
    logger = require('./application/logger'),
    config = require('./application/config'),
    emitter = require('./application/events');

// intialize the mongoose schemas/models.
var models = require('./objects/models').initialize();

/* ########################################################################## */
// Need a better way to organize db crap. PLEASE GIMME RECOMMENDATIONS

var db = mongoose.createConnection('mongodb://localhost/4d_data');

db.on('error', console.error.bind(console, 'db connection error:'));
db.once('open', function callback ()
{
    console.log('database connected');
});

/* ########################################################################## */

// Methods that are called from the primary handler.
// Any method that requires an authenticated user be present
// should call authenticateUser() and provide the next method as
// the second parameter.

function mTest(data)
{
 	authenticateUser(data,appStatus);
}
function mLogin(data)
{
    doLogin(data);
}
function mStatus(data)
{
    appStatus(data);
}
function mToken(data)
{
    authenticateUser(data,getToken);
}

/* ########################################################################## */

// Methods that *actually* do stuff. With luck, most of these will ultimately
// wind up being significantly smaller or exist in their entirety in external
// files.

function getToken(data)
{
    emitter.success(responses.successfulLogin(data.userToken));
}
function appStatus(data)
{
    logger.debug('appStatus');
    emitter.success(responses.allOkay);
}
function doLogin(data)
{
    logger.debug('doLogin');

    if (data.username == null ||
        data.password == null)
    {
        emitter.error(responses.userUnauthorizedInvalidCredentials);
        return;
    }

    var User = db.model('User');
    userObject = { name:data.username , password:data.password };
    User.findOne(userObject,function(err,user)
    {
        if (err)
        {
            // db error of some sort (NOTE: figure out what will actually
            // cause err to be populated.
        }
        else if (user == null)
        {
            // return invalid username/password status
        }
        else
        {
            // we found the user. create a random salt
            user.createSalt();

            user.save(function(err,user)
            {
                console.log('saving user');
                if (err)
                {
                    console.log('error');
                    // handle this. in SOME fashion.
                    return;
                }
                createUserToken(data,user);
            });
        }
    });
}

// not sure how best to handle this. if we leave encryption up to the CLIENT,
// it won't be shared across multiple clients using the same API.
// I think we just made SSL a requirement. *sigh*
function encrypt(plain)
{
    logger.debug('encrypt(%s)',plain);
    var cipher = crypto.createCipher('aes-256-cbc','InmbuvP6Z8')
    var e = cipher.update(plain,'utf8','hex');
    e += cipher.final('hex');
    return e;
}

// add a new user to the datastore (note: this takes a plaintext password
// for testing purposes. in practice, client should send encrypted password
// and we should JUST add it)
function addUser(username,password)
{
    logger.debug('addUser(%s,%s)',username,password);
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
    logger.debug('authorizeClient(%s,%s)',clientId,privateKey);
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
    logger.debug('validateHash');
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
    logger.debug('validateRequest');
    if (typeof(data.client) == 'undefined' ||
        typeof(data.payload) == 'undefined' ||
        typeof(data.hash) == 'undefined')
    {
    	emitter.error(responses.missingRequiredInput);
    }

    var Client = db.model('Client');
    Client.findOne({ clientId:data.client },function(err,client)
    {
        if (err)
        {
            console.log(err);
            emitter.error(responses.databaseError);
        }
        else if (client == null)
        {
            emitter.error(responses.clientUnknown);
        }
        else if (!validateHash(data,client.privateKey))
        {
            emitter.error(responses.clientUnauthorizedBadHash);
        }
        else
        {
            // let the app know we've validated the request.
            emitter.validatedRequest(data);
        }
    });
}

// this verifies that we know who the user is and (theoretically) makes
// it a pain to fake that information.
// the data contains a userToken, which we generated and stored in the db and
// gave back to the user when they first logged in. they pass this on
// subsequent calls to the API. the token is a hash of the user's ID, a random
// salt generated when they logged in, and their remote address (hashed with the
// app's private key).
// Using the remote address helps prevent hijacking, and the tokens expire
// periodically (config.userTokenTTL).
function authenticateUser(data,nextMethod)
{
    logger.debug('authenticateUser');

    // verify they passed a userToken
    if (data.userToken == null)
    {
        emitter.error(responses.userUnauthorizedNullToken);
        return;
    }

    var UserToken = db.model('UserToken');
    UserToken.findOne({ token:data.userToken },function(err,userToken)
    {
        if (err)
        {
            console.log(err);
            emitter.error(responses.databaseError);
            return;
        }
        else if (userToken == null)
        {
            emitter.error(responses.userUnauthorizedBadToken);
            return false;
        }
        else if (userToken.verify(data.userToken))
        {
            emitter.authenticated(data);
            nextMethod(data);
        }
        return;
    });
}

// create a userToken.
function createUserToken(data,user)
{
    logger.debug('createUserToken');
    // get the privatekey for the client in use
    var Client = db.model('Client');
    Client.findOne({ clientId:data.client },function(err,client)
    {
        if (err)
        {
            // handle error,
            // though we should never get here, really).
            return;
        }

        // create userToken hash
        tokenHash = crypto.createHmac('sha256',client.privateKey)
                        .update(user.name)
                        .update(user.salt)
                        .update(data.ipAddress)
                        .digest('hex');

        // create expiration
        var date = new Date();
        date.setMinutes(date.getMinutes() + config.userTokenTTL);
        var expires = date.valueOf();

        data.userToken = tokenHash;

        var UserToken = db.model('UserToken');
        userToken = new UserToken(
        {
            token:      tokenHash,
            expiration: expires,
            createDate: new Date()
        });

        console.log('added token %s to data from createUserToken',userToken);

        userToken.save(function(err,userToken)
        {
            if (err)
            {
                // handle this somehow
                console.log(err);
                return;
            }
            data.parameters.path = '/token';
            authenticateUser(data,getToken);
        });

    });
}

/* ########################################################################## */

// Response output. Maybe move these to Application object? Haven't decided yet.

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

/* ########################################################################## */

// The basics: mapping url to actual methods, handling the requests, and a TON
// of test data.

// handles the mapping of pathname to methods.
var mapping = {}
mapping['/'] = mStatus;
mapping['/test'] = mTest;
mapping['/login'] = mLogin;
mapping['/token'] = mToken;

function routeRequest(data)
{
    var doMethod = mapping[data.parameters.pathname];
    if (doMethod)
    {
        doMethod(data);
    }
    else
    {
        emitter.error(responses.badRequest);
    }
}

function onRequest(req,res)
{
    logger.debug('---------- NEW REQUEST');
    logger.debug('onRequest');
    var urlParameters = url.parse(req.url, true);

    // THIS IS TEST DATA
    var data =
    {
        username:'test',
        password:'16679162a9f9fc74ed65ded077651f51',
        userToken: '842c08cc227201f9a9800f93eb5385ff0ee56adf54eefd4caf19ecb14340f04e',
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

    emitter.on('event:request_error',
        function(status){writeOut(res,status)});
    emitter.on('event:request_success',
        function(status){writeOut(res,status)});
    emitter.on('event:validatedRequest',
        function(data){routeRequest(data)});

    validateRequest(data);
}

http.createServer(onRequest).listen(config.port);
console.log('listening on port %d',config.port);

