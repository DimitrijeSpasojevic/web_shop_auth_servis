'use strict';
const {
  Model
} = require('sequelize');
module.exports = (sequelize, DataTypes) => {
  class Categories extends Model {
    /**
     * Helper method for defining associations.
     * This method is not a part of Sequelize lifecycle.
     * The `models/index` file will call this method automatically.
     */
    static associate({Products}) {
      this.hasMany(Products, { foreignKey: 'categoryId', as: 'products', onDelete: 'cascade', hooks: true });
    }
  };
  Categories.init({
    name: DataTypes.STRING,
    description: DataTypes.STRING,
    popularity: DataTypes.STRING,
    quantity_of_product: DataTypes.INTEGER,
  }, {
    sequelize,
    modelName: 'Categories',
  });
  return Categories;
};