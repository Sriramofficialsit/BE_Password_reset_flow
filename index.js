const Express = require('express');
const { default: mongoose } = require('mongoose');
const cors = require('cors');

const API_SERVER = Express();
const home = require("./controllers/home.controlller");

require('dotenv').config()

API_SERVER.use(Express.json());
API_SERVER.use(cors());
API_SERVER.use("/auth",home);




async function dbconnect(){
    const mongodb_uri = process.env.MONGODB_URI;
    try{
        await mongoose.connect(mongodb_uri);
        console.log("Db connected")
    }catch(error){
        console.log(error.message)
    }
}

API_SERVER.listen(process.env.PORT,process.env.HOSTNAME,()=>{
    console.log("Server Started");
    console.log(`http://${process.env.HOSTNAME}:${process.env.PORT}`);
})
dbconnect();
