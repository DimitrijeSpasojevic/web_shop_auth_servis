const express = require('express');
const { sequelize, Users } = require('./models');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();
const Joi = require('joi');

const app = express();

var corsOptions = {
    "origin": "*",
    "methods": "GET,HEAD,PUT,PATCH,POST,DELETE",
    "preflightContinue": false,
    "optionsSuccessStatus": 204
  }

app.use(express.json());
app.use(cors(corsOptions));



app.post('/login', (req, res) => {
 
    const sema = Joi.object().keys({
        name: Joi.string().required(),
        email: Joi.string().trim().email().required(),
        password: Joi.string().min(4).max(12).required()
    });
    
    Joi.validate(req.body, sema, (err, result) => {
        if (err){
            res.send({msg : err.details[0].message});
        }
        else {
            Users.findOne({ where: { email: req.body.email} })
            .then( row => {
                if (bcrypt.compareSync(req.body.password, row.password)) {
                    const usr = {
                        userId: row.id,
                        role: row.role
                    };
            
                    const token = jwt.sign(usr, process.env.ACCESS_TOKEN_SECRET); 
                    
                    res.json({ token: token });
                } else {
                    res.status(400).json({ msg: "Invalid credentials"});
                }
            })
            .catch( err => {    
                res.status(400).json({ msg: "User ne postoji"});
            } );
        }
    });


});

app.listen({ port: 9000 }, async () => {
    await sequelize.authenticate();
    console.log(`Pokrenut na portu 9000 auth servis`)
});