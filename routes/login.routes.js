var express = require('express');
var router = express.Router();

const bcryptjs = require('bcryptjs')
const saltRounds = 10;

const User = require('../models/User.model')

const {isLoggedIn, isLoggedOut} = require('../middleware/route-guard')

/* GET users listing. */
router.get('/',isLoggedOut, (req, res, next) => {
  res.render('login/user-login');
});

router.post('/',isLoggedOut, (req,res) => {
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
    res.redirect('/login/userLogin')
  })
  .catch((err) => {
    console.log(err);
  })
})


router.get('/userLogin',isLoggedOut, (req,res) => {
  res.render('login/user-real-login.hbs')
})


router.post('/userLogin',isLoggedOut, (req,res) => {
  const {username, password} = req.body

  if(!username || !password) {
    res.render('login/user-real-login.hbs', { errorMessage: "Please enter both username and password to login"})
    return;
  }

  User.findOne({username})
  .then((user) => {
    if(!user) {
      res.render('login/user-real-login.hbs', { errorMessage: 'Username is not registered. Try with other username.' })
      return;
    } else if (bcryptjs.compareSync(password, user.password)) {
      req.session.user = user;
      console.log('SESSION =====> ', req.session);
      res.redirect('/login/userProfile')
    } else {
      res.render('login/user-real-login.hbs', { errorMessage: 'Password incorrect, Try Again' })
    }
  })
  .catch((err) => {
    console.log(err);
  })
})


router.get('/userProfile',isLoggedIn, (req,res) => {
  const user = req.session.user;
  res.render('login/user-profile.hbs', {user})
})



module.exports = router;
