const { DataTypes } = require('sequelize');
const sequelize = require('../config/db');

const BlacklistToken = sequelize.define('BlacklistToken', {
  token: {
    type: DataTypes.STRING,
    allowNull: false,
  },
});

module.exports = BlacklistToken;
