require('dotenv').config()
const express = require('express')
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

const app = express()

//config json response

app.use(express.json())

// Models
const User = require('./models/User')

//public route
app.get('/', (req, res) => {
    res.status(200).json({msg: "Teste"})
})

//private route
app.get('/user/:id', checkToken, async (req, res) => {
    const id = req.params.id

    //check if user exists
    const user = await User.findById(id, '-password')

    if(!user) {
        return res.status(404).json({msg: "User not Found"})
    }

    res.status(200).json({user})
})

function checkToken(req, res, next) {
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(" ")[1]

    if(!token) {
        return res.status(401).json({msg: 'Unauthorized'})
    }

    try {
        const secret = process.env.SECRET

        jwt.verify(token, secret)

        next()
    } catch(error) {
        res.status(400).json({msg: 'Invalid token'})
    }
}

//register user

app.post('/auth/register', async(req, res) => {
    const {name, password} = req.body

    //validations
    if(!name) {
        return res.status(422).json({msg:'O nome é obrigatório'})
    }
    if(!password) {
        return res.status(422).json({msg:'A senha é obrigatório'})
    }

    //check if user exists
    const userExists = await User.findOne({name : name})

    if(userExists) {
        return res.status(422).json({msg: "Usuário já existe"})
    }

    //create password
    const salt = await bcrypt.genSalt(12)
    const passwordHash = await bcrypt.hash(password, salt)

    //create user
    const user = new User ({
        name,
        password: passwordHash,
    
    })

    try {

    await user.save()
    res.status(201).json({msg: "User created"})

    } catch(error) {
        res.status(500).json({msg: error})
    }
})

//credencials
const dbUser = process.env.DB_USER
const dbPass = process.env.DB_PASS

//Login User

app.post('/auth/login', async (req, res) => {
    const {name, password} = req.body

//validations

if(!name) {
    return res.status(422).json({msg:'O nome é obrigatório'})
}
if(!password) {
    return res.status(422).json({msg:'A senha é obrigatório'})
}

//check if user exists
const user = await User.findOne({name : name})

if(!user) {
    return res.status(404).json({msg: "User not found"})
}

//check if password match
const checkPassword = await bcrypt.compare(password, user.password)

if (!checkPassword) {
    return res.status(402).json({msg: "Invalid password"})
}

try {
    const secret = process.env.SECRET

    const token = jwt.sign({
        id: user._id,
    },
    secret,
    )
    res.status(200).json({msg: "Auth sucessfuly", token})
}
catch(err) {
    console.log(error)
    res.status(500).json({msg: error})
}

})

mongoose.connect(`mongodb+srv://${dbUser}:${dbPass}@auth1.jx0hlcx.mongodb.net/?retryWrites=true&w=majority&appName=auth1`
).then(() => {

    app.listen(3000)
    console.log("Connected to Database")
}).catch((err) => console.log(err))

