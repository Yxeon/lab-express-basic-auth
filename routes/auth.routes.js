const mongoose = require("mongoose");
const router = require("express").Router();
const User = require("../models/User.model");
const bcryptjs = require("bcryptjs");
const saltRounds = 10;

///Rutas aqui
router.get("/signup", (req, res, next) => {
    res.render("../views/auth/signup.hbs")
})

router.post("/signup", (req, res, next) => {
    const { username, password } = req.body;
    bcryptjs
    .genSalt(saltRounds)
    .then(salt => {
        return bcryptjs.hash(password, salt)
    })
    .then(hashedPassword => {
        return User.create({
            username,
            password: hashedPassword
        })
    })
    .then((userFromDB) => {
        res.redirect("/profile")
    })
    .catch((error) => {
        next(error)
    })
});

router.get("/profile", (req, res, next) => {
    res.render("../views/users/profile.hbs")
});

module.exports = router;