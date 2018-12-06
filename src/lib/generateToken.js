const jwt = require('jsonwebtoken');

module.exports = userId => jwt.sign({ userId }, process.env.APP_SECRET);
