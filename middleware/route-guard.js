const isLoggedIn = (req,res,next) => {
    if(!req.session.user) {
        return res.redirect('/login/userLogin');
    }
    next();
}


const isLoggedOut = (req,res,next) => {
    if(req.session.user) {
        return res.redirect('/')
    }
    next();
}


module.exports = {
    isLoggedIn,
    isLoggedOut
}