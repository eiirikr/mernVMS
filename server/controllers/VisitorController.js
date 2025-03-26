const { mongoose } = require("mongoose");
const visitorRegistrationModel =require("../models/VisitorModel.js");

function GenerateVisitorID()
  {
    var visitor_id="V";
    let i=0;
    var chars="0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    while(i<5){
        visitor_id+= chars.charAt(Math.floor(Math.random() * chars.length));
        i++;
    }
    return visitor_id;

  }
   
const registerVisitor = async(req,res)=>{
    const formData= req.body;

    if(formData.email && formData.email!==''){
        const visitorEmail = await visitorRegistrationModel.findOne({email:formData.email})
        if(visitorEmail){
           return  res.status(200).json("Account Already Exist with this Email");
         }
    }

    const visitorMobile = await visitorRegistrationModel.findOne({mobile_no:formData.mobileNo})

    if(visitorMobile){
        return  res.status(200).json("Account Already Exist with this Mobile number");
    }
    else{
    try{
        const visitor_info = await visitorRegistrationModel.create({
            admin: req.admin._id,
            visitor_id:GenerateVisitorID(),
            name:formData.firstName+" "+formData.lastName,
            gender:formData.gender,
            age:formData.age,
            designation:formData.designation,
            mobile_no:formData.mobileNo,
            email:formData.email,
            address:formData.address

        });
        res.status(200).json(visitor_info);
    }
    catch(e)
    {
        console.log(e);
        res.status(400).json({error: e.message});
    }
    }
};


const getVisitorsDetails = async(req,res)=>{
    try{
        const visitors_details = await visitorRegistrationModel.find({admin:req.admin._id});
        res.status(200).json(visitors_details);
    }
    catch(e)
    {
        res.status(400).json({error: e.message});
    }
};


const getSingleVisitorData = async(req,res)=>{
    const {id}=req.params;

    if(!mongoose.Types.ObjectId.isValid(id))
    {
        return res.status(400).json({message: "visitor not found"});
    }
    try{

        const visitor_data = await visitorRegistrationModel.findById(id);

        if (!visitor_data) {
            return res.status(404).json({ message: "Visitor not found" });
        }

        if(visitor_data.admin.toString() != req.admin._id.toString()){
              return  res.status(401).json({message: "Admin not Authorized"});
        }
       
        res.status(200).json(visitor_data);
    }
    catch(e)
    {
        res.status(400).json({error: e.message});
    }
};

const updateSingleVisitorData = async(req,res)=>{
    const {id}=req.params;

    if(!mongoose.Types.ObjectId.isValid(id))
    {
       return res.status(400).json({message: "visitor not found"});
    }
    try{

        const visitor = await visitorRegistrationModel.findById(id);

        if(!visitor){
            return res.status(404).json({ message: "visitor not found" });
        }

        if(visitor.admin.toString() != req.admin._id.toString()){
              return  res.status(401).json({message: "Admin not Authorized"});
        }

        if(req.body.email!=='' && visitor.email!==req.body.email)
        {
            const visitorEmail = await visitorRegistrationModel.findOne({email:req.body.email})
        
            if(visitorEmail){
                return  res.status(200).json("Email Already Exist");
            }
        }
        
         if(visitor.mobile_no!==req.body.mobile_no)
         {
            const visitorMobile = await visitorRegistrationModel.findOne({mobile_no:req.body.mobile_no})

             if(visitorMobile){
                return  res.status(200).json("Mobile Number Already Exist");
             }
        }   

        const visitor_data = await visitorRegistrationModel.findByIdAndUpdate({
            _id:id
        }, 
        {
            ...req.body
         });
       
        res.status(200).json(visitor_data);
    }
    catch(e)
    {
        console.log(e);
        res.status(400).json({error: e.message});
    }
};

const deleteSingleVisitorData = async(req,res)=>{
    const {id}=req.params;

    if(!mongoose.Types.ObjectId.isValid(id))
    {
        return res.status(400).json({message: "visitor not found"});
    }
    try{

        const visitor = await visitorRegistrationModel.findById(id);

        if(!visitor){
            return res.status(404).json({ message: "visitor not found" });
        }

        if(visitor.admin.toString() != req.admin._id.toString()){
              return  res.status(401).json({message: "Admin not Authorized"});
        }

        await visitorRegistrationModel.findByIdAndDelete(id);      
       
        res.status(200).json("visitor data deleted successfully");
    }
    catch(e)
    {
        res.status(400).json({error: e.message});
    }
};


module.exports = { registerVisitor, getVisitorsDetails, getSingleVisitorData,
      updateSingleVisitorData,  deleteSingleVisitorData };