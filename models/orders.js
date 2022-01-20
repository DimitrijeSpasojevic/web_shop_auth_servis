'use strict';
const {
  Model
} = require('sequelize');
module.exports = (sequelize, DataTypes) => {
  class Oreders extends Model {
    /**
     * Helper method for defining associations.
     * This method is not a part of Sequelize lifecycle.
     * The `models/index` file will call this method automatically.
     */
    static associate({Users,Products}) {
      // define association here
      this.belongsTo(Users, {foreignKey: 'userId', as: 'user'});
    }
  };
  Oreders.init({
    current_value: DataTypes.INTEGER,
    discount: DataTypes.INTEGER,
    type_of_delivery: DataTypes.STRING,
    urgent: DataTypes.BOOLEAN
  }, {
    sequelize,
    modelName: 'Orders',
  });
  return Oreders;
};