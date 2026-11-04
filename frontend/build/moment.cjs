"use strict";

// @splunk/moment is published as { default: moment } while react-ui's
// Calendar/Date CommonJS bundles expect require("moment") to be callable.
const loaded = require("@splunk/moment");
module.exports = loaded && loaded.default ? loaded.default : loaded;
