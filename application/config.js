var Config = {}
Config.userTokenTTL = 30;  // minutes
Config.port = 8080;

// 0==no logging
// 1==error only
// 2==warnings + errors
// 3==warnings + errors + info
// 4==warnings + errors + info + debug.
Config.logLevel = 4;

module.exports = Config;
