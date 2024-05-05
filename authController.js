const User = require('../models/User')
const jwt = require("jsonwebtoken")
const bcrypt = require('bcrypt')

const register = async (req, res) => {
    console.log('hha')
    try {
        const isEmpty = Object.values(req.body).some((v) => !v) //to check if values are empty (objects are stored in key value pair)
        if(isEmpty){
            throw new Error("Fill all fields!")
        }

        const isExisting = await User.findOne({username: req.body.username}) //to check if acc already exists (username is specified as unique constraint in schema)
        if(isExisting){
            throw new Error("Account is already registered")
        }

        console.log(req.body)
        const hashedPassword = await bcrypt.hash(req.body.password, 10) //encrypting password , 10 is for salting
        const user = new User({...req.body, password: hashedPassword}) //...req.body -> considers all parameters (username,email,password  )
        await user.save()

        const payload = {id: user._id, username: user.username}
        const {password, ...others} = user._doc

        const token = jwt.sign(payload, process.env.JWT_SECRET) // passing payload to Json web token for authentication

        return res.status(201).json({token, others})
    } catch (error) {
        return res.status(500).json(error.message)
    }
}


const login = async (req, res) => {
    try {
        const isEmpty = Object.values(req.body).some((v) => !v) //empty values
        if(isEmpty){
            throw new Error("Fill all fields!")
        }

        const user = await User.findOne({email: req.body.email}) //login via email, username is only required for registering
        if(!user){
            throw new Error("Wrong credentials") // so if user doesn't exist -> wrong credentials
        }

        const comparePass = await bcrypt.compare(req.body.password, user.password) //password check with the encrypted password
        if(!comparePass){
            throw new Error("Wrong credentials") 
        }

        const payload = {id: user._id, username: user.username}
        const {password, ...others} = user._doc // others doesn't have the password

        const token = jwt.sign(payload, process.env.JWT_SECRET)

        return res.status(200).json({token, others}) // printing others, because it has all details except the password 
    } catch (error) {
        return res.status(500).json(error.message)
    }
}


module.exports = {
    register,
    login
}