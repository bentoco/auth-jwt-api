const router = require('express').Router();
const User = require('../model/User');
const bcrypt = require('bcrypt');
const { registerValidation, loginValidation } = require('../validation');

router.post('/register', async (req, res) => {
    const {error} = registerValidation(req.body);
    if(error) return res.status(400).send(error.details[0].message);
    
    const emailExist = await User.findOne({email: req.body.email});
    if(emailExist) return res.status(400).send('email already exists.');

    const salt = await bcrypt.genSalt(10);
    const hashPassword = await bcrypt.hash(req.body.password, salt);

    const user = new User({
        name: req.body.name,
        email: req.body.email,
        password: hashPassword 
    });
    try{
        const savedUser = await user.save();
        res.send({ user: user._id });
    }catch(err){
        res.status(400).send(err);
    }
});

router.post('/login', (req, res) => {
    const {error} = loginValidation(req.body);
    if (error) return res.status(400).send(error.details[0].message);
});


module.exports = router;