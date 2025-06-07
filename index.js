const express = require("express");
const {userModel, todoModel} = require("./db");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const {z} = require("zod")
require('dotenv').config();

const jwt_secret = process.env.JWT_SECRET;
mongoose.connect(process.env.MONGO_URI);

const app = express();
app.use(express.json());
app.use(express.static(__dirname+ '/public'));

app.get("/", function(req, res){
    res.sendFile(__dirname+"/public/index.html")
})

app.post("/signup", async function(req, res){
    const requiredBody = z.object({
        email: z.string().min(3).max(100).email(),
        name:z.string().min(3).max(100),
        password: z.string().min(3).max(100)
    })
    const parsedData = requiredBody.safeParse(req.body);
    if(!parsedData.success){
        return res.status(403).json({
            msg:"Incorrect Format",
            error: parsedData.error
        })
    }

    const email = req.body.email;
    const password = req.body.password;
    const name = req.body.name;

    try{
        const hashedPassword =await bcrypt.hash(password, 5)
        await userModel.create({
            email,
            password:hashedPassword,
            name
        })
    }catch(e){
        return res.status(403).json({
            msg:"User already exists"
        })
    }

    res.json({
        msg:"You are signed up"
    })
})

app.post("/signin",async function(req, res){
    const email = req.body.email;
    const password = req.body.password;

    const user =await userModel.findOne({
        email
    })
    if(!user){
        return res.status(403).json({
            msg:"User not found"
        })
    }

    const passwordMatch = await bcrypt.compare(password, user.password)
    if(passwordMatch){
        const token = jwt.sign({
            id:user._id
        }, jwt_secret);
        
        res.json({
            token
        })
    }else{
        res.status(403).json({
            msg:"incorrect credentials"
        })
    }
})

app.post("/todo",auth,async function(req, res){
    const userId = req.userId;
    const title = req.body.title;
    const done = false

    await todoModel.create({
        title,
        userId,
        done
    })
    res.json({
        msg:"Todo Created"
    })
})

app.get("/todos",auth,async function(req, res){
    const userId = req.userId;

    const todos = await todoModel.find({
        userId
    })
    res.json({
        todos
    })
})

app.delete("/todo/:id", auth, async function(req, res){
    try{
        const id = req.params.id;
        await todoModel.findByIdAndDelete(id);
        res.json({
            msg:"Todo Deleted"
        })
    }catch(e){
        res.status(403).json({
            msg:"Error Deleting Todo"
        })
    }
})

function auth(req, res, next){
    try {
        const token = req.headers.token;
        const decodedData = jwt.verify(token, jwt_secret);
        req.userId = decodedData.id;
        next();
    } catch (e) {
        res.status(403).json({ msg: "Invalid token" });
    }
}

app.listen(3000);