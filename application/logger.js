var config = require('./config');

Logger =
{
    level: config.logLevel,

    // 0==no logging
    // 1==error only
    // 2==warnings + errors
    // 3==warnings + errors + info
    // 4==warnings + errors + info + debug.

    debug:  function(msg) { if (this.level>3) console.log("[DEBUG] %s",msg); },
    info:   function(msg) { if (this.level>2) console.log("[INFO] %s",msg); },
    warn:   function(msg) { if (this.level>1) console.log("[WARN] %s",msg); },
    error:  function(msg) { if (this.level>0) console.log("[ERROR] %s",msg); }
};

module.exports = Logger;
