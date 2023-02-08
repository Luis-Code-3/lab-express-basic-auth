var express = require('express');
var router = express.Router();

const bcryptjs = require('bcryptjs')
const saltRounds = 10;

const User = require('../models/User.model')

/* GET users listing. */
router.get('/', (req, res, next) => {
  res.render('login/user-login');
});

router.post('/', (req,res) => {
  const {username, password} = req.body;

  bcryptjs
  .genSalt(saltRounds)
  .then((salt) => {
    return bcryptjs.hash(password, salt)
  })
  .then((hashedPassword) => {
    return User.create({
      username,
      password: hashedPassword
    })
  })
  .then((createdUser) => {
    console.log(createdUser);
    res.send('Login Successful')
  })
  .catch((err) => {
    console.log(err);
  })
})

module.exports = router;
