var util = require('util'),
    events = require('events');
var logger = require('./logger');

Emitter = function()
{
    events.EventEmitter.call(this);
    this.doEmit = function(event,data)
    {
        logger.debug(event);
        this.emit(event,data);
    }
    this.success = function(data)
    {
        this.doEmit('event:request_success',data);
    }
    this.error = function(data)
    {
        this.doEmit('event:request_error',data);
    }
    this.authenticated = function(data)
    {
        this.doEmit('event:authenticated',data);
    }
    this.validatedRequest = function(data)
    {
        this.doEmit('event:validatedRequest',data);
    }
}
util.inherits(Emitter,events.EventEmitter);
module.exports = new Emitter();
