var util = require('util'),
    events = require('events');

var Application = {}
Application.userTokenTTL = 30;  // minutes
Application.port = 8080;
Application.debug = true;

Application.writeDebug = function(debugdata)
{
    if (this.debug) console.log(debugdata);
}

Emitter = function()
{
    events.EventEmitter.call(this);
    this.success = function(data)
    {
        Application.writeDebug('event:request_success');
        this.emit('event:request_success',data);
    }
    this.error = function(data)
    {
        Application.writeDebug('event:request_error');
        this.emit('event:request_error',data);
    }
    this.authenticated = function(data)
    {
        Application.writeDebug('event:authenticated');
        this.emit('event:authenticated',data);
    }
    this.validatedRequest = function(data)
    {
        Application.writeDebug('event:validatedRequest');
        this.emit('event:validatedRequest',data);
    }
}
util.inherits(Emitter,events.EventEmitter);
Application.emitter = new Emitter();

module.exports = Application;
