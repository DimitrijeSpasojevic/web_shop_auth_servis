'use strict';
const {
  Model
} = require('sequelize');
module.exports = (sequelize, DataTypes) => {
  class Users extends Model {
    /**
     * Helper method for defining associations.
     * This method is not a part of Sequelize lifecycle.
     * The `models/index` file will call this method automatically.
     */
    static associate({Orders, Messages}) {
      this.hasMany(Orders, { foreignKey: 'userId', as: 'orders' });
      this.hasMany(Messages, { foreignKey: 'userId', as: 'messages', onDelete: 'cascade', hooks: true });
    }
  };
  Users.init({
    role: {
      allowNull: false,
      type: DataTypes.STRING
    },
    first_name: {
      type: DataTypes.STRING,
      allowNull: false
    },
    last_name: {
      type: DataTypes.STRING,
      allowNull: false
    },
    email: {
      type: DataTypes.STRING,
      allowNull: false,
      unique: true
    },
    password: {
      type: DataTypes.STRING,
      allowNull: false
    },
    quantity_of_money: {
      type: DataTypes.INTEGER
    } 
  }, {
    sequelize,
    modelName: 'Users',
  });
  return Users;
};