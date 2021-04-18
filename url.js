const express = require("express");
const cors = require("cors");
const { nanoid } = require("nanoid");
const bcrypt = require("bcryptjs");

const mongodb = require("mongodb");
const URL = "mongodb+srv://mallika:hemasundari@cluster0.bl042.mongodb.net/myFirstDatabase?retryWrites=true&w=majority";

const jwt = require("jsonwebtoken");
require("dotenv").config();

const app = express();
app.use(cors());
app.use(express.json());

//Registration
app.post("/register", async (req, res) => {
    try {
        let connection = await mongodb.connect(URL);
        let db = connection.db("shorturl");
        req.body.links = [];
        let isEmailUnique = await db.collection("register").findOne({ email: req.body.email });
        if (isEmailUnique) {
            res.status(401).json({
                message: "Email already exists"
            })
        }
        else {
            //Generate a salt
            let salt = await bcrypt.genSalt(10);
            //Hash the password with salt
            let hash = await bcrypt.hash(req.body.password, salt);
            //Store it in the db
            req.body.password = hash;
            let users = await db.collection("register").insertOne(req.body);
            // console.log(hash);
            // console.log(users.ops);
            res.json({
                message: "User Registered"
            })
        }

    } catch (error) {
        console.log(error);
    }
})

//Login
app.post("/login", async (req, res) => {
    try {
        let connection = await mongodb.connect(URL);
        let db = connection.db("shorturl");

        //Find the user with the emailID
        let user = await db.collection("register").findOne({ email: req.body.email });
        //Hash the password
        //Check the hashed password with users
        if (user) {
            let isPasswordCorrect = await bcrypt.compare(req.body.password, user.password);
            if (isPasswordCorrect) {
                //Generate Token
                let token = jwt.sign({ _id: user._id }, process.env.SECRET)
                //Pass token
                res.json({
                    message: "Allow",
                    token: token,
                    id: user._id
                })
            }
            else {
                res.json({
                    message: "Email or Password is Incorrect"
                })
            }
        }
        else {
            res.status(404).json({
                message: "Email or Password is Incorrect"
            })
        }
        //If correct -- Allow the user

    } catch (error) {
        console.log(error);
    }
})



//This API can be accesses by anyone with token
app.get("/common", authenticate, (req, res) => {
    console.log(req.userId);
    res.json({
        message: "common place"
    })
})

//Dashboard

//middleware for common place
function authenticate(req, res, next) {
    //Check if there is a Token
    if (req.headers.authorization) {
        //Token is present
        //Check if the token is valid or expired
        try {
            let jwtValid = jwt.verify(req.headers.authorization, process.env.SECRET);
            if (jwtValid) {
                req.userId = jwtValid._id;
                next();
            }
        } catch (error) {
            res.status(401).json({
                message: "Invalid Token"
            })
        }
    }
    else {
        res.status(401).json({
            message: "No Token Present"
        })
    }
}

// Application

app.get("/urls/:id", authenticate, async (req, res) => {
    try {
        let connection = await mongodb.connect(URL);
        let db = connection.db("shorturl");
        let user = await db.collection("register").findOne({ _id: mongodb.ObjectID(req.params.id) });
        await connection.close();
        res.json(user);
    } catch (error) {
        console.log(error);
    }
})

app.post("/:id", authenticate, async (req, res) => {
    try {
        let connection = await mongodb.connect(URL);
        let db = connection.db("shorturl");
        // await db.collection("register").insertOne(req.body);
        await db.collection("register").updateOne({ _id: mongodb.ObjectID(req.params.id) }, { $push: { links: { $each: [{ longURL: req.body.longURL, shortURL: nanoid(6) }] } } });
        await connection.close();
        res.json({
            message: "URL recieved"
        })
    } catch (error) {
        console.log(error);
    }
});


app.get("/:id", async (req, res) => {
    try {
        let connection = await mongodb.connect(URL);
        let db = connection.db("shorturl");
        let index = req.params.id.substr(0, 1);
        let short = req.params.id.substr(2, 6);
        let response = await db.collection("register").find({ "links.shortURL": short }).toArray();
        res.redirect(response[0].links[index].longURL);

    } catch (error) {
        console.log(error);
    }
});

app.listen(process.env.PORT || 7000);
