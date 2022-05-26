const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { expressjwt: expressJwt } = require('express-jwt')
const User = require('./user')
require('dotenv').config();

console.log(`${process.env.MONGO_USER}, ${process.env.MONGO_PW}, ${process.env.MONGO_URI}`);


mongoose.connect(process.env.MONGO_URI.replace('MONGO_USER', process.env.MONGO_USER).replace('MONGO_PW', process.env.MONGO_PW))
const app = express();

app.use(express.json());

// FIXME:
// De momento lo hacemos de esta forma, solo sirve para local (export key=valor)
// en caso de querer exportar configuraciones de ambiente en produccion
// Va a ser necesario usar archivos de configuracion de ambiente.
// DONE: Ahora con dotenv no es necesario exportar ninguna propertie de ambiente.
// las leemos del .env
console.log(process.env.SECRET);

const validateJWT = expressJwt({ secret: process.env.SECRET, algorithms: ["HS256"] })
const signToken = _id => jwt.sign({ _id }, process.env.SECRET);

const findAndAsignUser = async (req, res, next) => {
    try {
        const user = await User.findById(req.auth._id);
        if (!user) {
            return res.status(401).end();
        }
        req.user = user;
        next()
    } catch (err) {
        next(err);
    }
}

app.post('/register', async (req, res) => {
    const { body } = req;
    console.log({ body })
    try {
        const isUser = await User.findOne({ email: body.email })
        if (isUser) {
            return res.status(403).send('The user already exists!')
        }
        const salt = await bcrypt.genSalt();
        const hashed = await bcrypt.hash(body.password, salt);
        const user = await User.create({ email: body.email, password: hashed, salt })
        // FIXME:
        // res.send({ _id: user._id })
        // Esto no deberia ser asi, de hecho deberiamos estar devolviendo un JWT encriptado.
        // Lo corregimos en las siguientes lineas :D

        // Este segundo parametro seria la clave o key secreta para encryptar, y no deberia estar expuesta en codigo. pero YA LO RESOLVEREMOS :D
        const signedJWT = signToken(user._id);
        res.status(201).send(signedJWT);


    } catch (err) {
        console.log(err);
        res.status(500).send(err.message);
    }
})

app.post('/login', async (req, res) => {
    const { body } = req;
    try {
        const user = await User.findOne({ email: body.email })
        if (!user) {
            res.status(403).send('Usuario y/o contraseña invalidos.')
        } else {
            const isMatch = await bcrypt.compare(body.password, user.password)
            if (isMatch) {
                const signedToken = signToken(user._id)
                res.status(200).send(signedToken);
            } else {
                res.status(403).send('Usuario y/o contraseña invalidos.')
            }
        }
    } catch (err) {
        res.status(500).send(err.message);
    }
})

const isAuthenticated = express.Router().use(validateJWT, findAndAsignUser)

app.get('/something', isAuthenticated, (req, res) => {
    // FIXME: Prueba de manejo de errores con Middleware
    // throw new Error('new error')
    res.send(req.user);
})

app.use((err, req, res, next) => {
    console.error('My new error', err.stack);
    res.send('An error has taken place.')
    next(err);
})

app.listen(3000, () => {
    console.log(`I'm listening on port 3000 :D`)
})

