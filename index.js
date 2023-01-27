const express  = require('express');
require("dotenv").config();
const cors = require('cors');
const app = express();
const jwt = require("jsonwebtoken");
const argon2 = require('argon2')
const JWT_SECRET_KEY=process.env.JWT_JWT_SECRET_KEY;
const PORT = process.env.PORT|| 7000;
const connection = require("./DataBase");
const userModel = require('./Models/User');
const {AuthoRization ,AuthentiCation } = require("./MiddleWare/AuthentiCation")
app.use(express.json())
app.use(cors())
app.use(express.urlencoded({extended:true}))



app.post("/signup", async (req, res)=>{ 
             const  {name , email , mob_num ,password} = req.body;
             const hashPassword = await argon2.hash(password);
             const chek_For_User = await  userModel.findOne({$and:[{email},{mob_num}]});
             if(chek_For_User != null){
                   res.send({msg:"ooops user already present", sucess:false})
             }else{
                const user =  await   userModel({name ,email, mob_num , password:hashPassword})
                user.save((err , sucess)=>{
                    if(err){
                      res.status(401).send({message:'oops something went wrong try again', sucess:false})
                    }
                    res.status(200).send({message : "data savavd to data bases" , sucess:true})
                  })
                }
      })

app.post("/login", AuthentiCation, async (req, res)=>{
          const user =  req.body;
          jwt_token = jwt.sign({user}, process.env.JWT_SECRET_KEY,{expiresIn:'24 hr'});
          res.send({message :"login sucessful",jwt_token, sucess:true , userId:req.body.userID})
  })

 app.use(AuthoRization);

  app.patch("/pass/edit/:id",async (req, res)=>{
    const {userID} = req.params
     //console.log(req.body)
      let {curr_password , new_password} = req.body;
      if(curr_password){
         const  Curr_USER_Data = await userModel.findOne({userID});
         const old_PASS_Verfication = await argon2.verify(Curr_USER_Data.password,curr_password);
         const hash_NEW_Pass = await argon2.hash(new_password)
         const save_new_pass = await userModel.findOneAndUpdate({curr_password},{ password:hash_NEW_Pass});
         res.send({msg:"saved to data Base "})
    }
    else{
      res.send({msg:"Bad Request 404 InValid Credientials "})
    }
   })
 
app.patch("/details/edit/:paramId",async (req, res)=>{
    const {userID} = req.body;
    const {paramId} = req.params
   if(`:${userID}` === paramId){
      const {email , name, mob_num}= req.body;
      const chek_For_User = await  userModel.find({userID});
     if(chek_For_User){
      const save_User_Details = await userModel.findOneAndUpdate({userID},{...chek_For_User,mob_num:mob_num ,name:name, email:email})
      console.log(save_User_Details )
      res.send({msg:"Sucess Fully changed Details "})
    }
  }
  else{
      res.send({msg:"Error In Updating Details "})
    }
 })
app.get("/getuser/:id",async (req, res)=>{
    const userId= req.params;
    const user = req.body;
    const findUser  = await userModel.findOne({userId})
    let {name , email , mob_num , userID}= findUser._doc
      if(findUser){
        const User= { name , email , mob_num , userID}
        res.send({msg:"user data", User })
      }else{
        res.send({msg:"ooops not a verifide User "})
      }
   })


app.listen(PORT, async ()=>{
    try{ await connection;
          console.log('connected to dataBase Suceefully');
          console.log(`running on port  ${PORT}`)
    }catch{
          console.log("data base connection errro")
    }
})
