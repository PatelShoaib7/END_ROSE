const  argon2 = require("argon2");
const jwt = require("jsonwebtoken");

const userModel = require("../Models/User");
require('dotenv').config();



const AuthentiCation =async (req, res, next)=>{
    const { password , email}= req.body;
      const user =  await   userModel.findOne({email});
      console.log(user)
      const password_Verification =user ? await argon2.verify(user.password , password) : false
      if(password_Verification== false){
        res.send({msg:"Ooops Wrong Crentials Check Email & Password Again"})
     }else{
        req.body.userID =user._id;
        next()
     }
}
const AuthoRization =(req , res , next)=>{
      const token =  req.headers.authorization
    if(token){
        const authorization_token = req.headers.authorization.split(" ")[1];
       jwt.verify(authorization_token , process.env.JWT_SECRET_KEY,(err , decode)=>{
        if(err){
            res.send({msg :"Error In Varifying Token"})
        }else{
             req.body.userID =decode.user.userID;
            next();
        }
    })
}else{
    res.status(401).send({msg:"Access Denied Invalid Token Not Authorized "})
}
      
}

module.exports ={AuthoRization, AuthentiCation }
