const { mongoose } = require("mongoose");
const moment=require('moment')
const meetingRegistrationModel =require("../models/MeetingModel.js");
const preRegistrationModel =require("../models/PreRegistrationModel.js");
const checkInOutModel  =require("../models/CheckInOutModel.js");
   
const checkInOutVisitor = async(req,res)=>{

    const formData= req.body;
    
    // check visitor pass id exist
    const checkInOutData= await checkInOutModel.findOne({visitPass_id:formData.visitPassID})

    // validate visitor pass status
    if(checkInOutData && checkInOutData.visitPass_status==="Invalid"){
        return res.status(200).json("Visit Pass Invalid");
    }

    const checkTime = moment().format("hh:mm A")

    if(formData.visitPassID[0]==='M'){

    const meetingData = await meetingRegistrationModel.findOne({meeting_id:formData.visitPassID})

    if(!meetingData){
        return res.status(200).json("Visit Pass Invalid");
    }

    const meetEndTime = moment(checkTime,"hh:mm A").add(meetingData.meeting_duration, 'minutes').format("hh:mm A");

    
    if(new Date(meetingData.meeting_date).setHours(0,0,0,0) < new Date().setHours(0,0,0,0)){
        return res.status(200).json("Visit Date Expired");
    }
    else if(new Date(meetingData.meeting_date).setHours(0,0,0,0) > new Date().setHours(0,0,0,0))
    {
          return res.status(200).json("Visit Date Not Arrive");
    }


       if(checkInOutData && checkInOutData.visitor_status==="In"){
            
        try{

        const check_data = await checkInOutModel.findOneAndUpdate({
            visitPass_id:formData.visitPassID
         }, 
        {
            ...req.body,
            checkOut:checkTime,
            visitor_status:"Out",
            visitPass_status:"Invalid"
         });
       
        return res.status(200).json("Visitor Check Out Success");
    }
    catch(e)
    {
        console.log(e);
        return res.status(400).json({error: e.message});
    }
  }
    else if(!checkInOutData){

       try{

        const check_info = await checkInOutModel.create({
            admin: req.admin._id,
            visitPass_id:meetingData.meeting_id,
            visitor_id:meetingData.visitor_id,
            visitor_name:meetingData.visitor_name,
            visitor_designation:meetingData.visitor_designation,
            visitor_mobileNo:meetingData.visitor_mobileNo,
            employee_id:meetingData.employee_id,
            employee_email:meetingData.employee_email,
            visit_purpose:meetingData.meeting_purpose,
            visit_date:new Date().setHours(0,0,0,0),
            visit_startTime:checkTime,
            visit_endTime:meetEndTime,
            allotted_visit_duration:meetingData.meeting_duration,
            checkIn:checkTime,
            checkOut:'',
            visitor_status:"In",
            visitPass_status:"Valid"

        });
        return res.status(200).json("Visitor Check In Success");
    }
    catch(e){
        console.log(e);
        return res.status(400).json({error: e.message});
      } 
    }
  }
  else if(formData.visitPassID[0]==='P'){


    const preregistrationData = await preRegistrationModel.findOne({meeting_id:formData.visitPassID})

     if(!preregistrationData){
        return res.status(200).json("Visit Pass Invalid");
    }

    
    const today=new Date().setHours(0,0,0,0);

    if(new Date(preregistrationData.meeting_date).setHours(0,0,0,0) < today){
        return res.status(200).json("Visit Date Expired");
    }
    else if(new Date(preregistrationData.meeting_date).setHours(0,0,0,0) > today)
    {
          return res.status(200).json("Visit Date Not Arrive");
    }

    if(checkInOutData && checkInOutData.visitor_status==="In"){

        try{

        const check_data = await checkInOutModel.findOneAndUpdate({
          visitPass_id:formData.visitPassID
         }, 
        {
            ...req.body,
            checkOut:checkTime,
            visitor_status:"Out",
            visitPass_status:"Invalid"

         });
       
        return res.status(200).json("Visitor Check Out Success");
    }
    catch(e)
    {
        console.log(e);
        return res.status(400).json({error: e.message});
    }

    }
    else{
       try{
        const visitor_info = await checkInOutModel.create({
            
            admin: req.admin._id,
            visitPass_id:preregistrationData.meeting_id,
            visitor_id:preregistrationData.visitor_id,
            visitor_name:preregistrationData.visitor_name,
            visitor_designation:preregistrationData.visitor_designation,
            visitor_mobileNo:preregistrationData.visitor_mobileNo,
            employee_id:preregistrationData.employee_id,
            employee_email:preregistrationData.employee_email,
            visit_purpose:preregistrationData.meeting_purpose,
            visit_date:new Date().setHours(0,0,0,0),
            visit_startTime:preregistrationData.meeting_startTime,
            visit_endTime:preregistrationData.meeting_endTime,
            allotted_visit_duration:moment(preregistrationData.meeting_endTime, 'HH:mm').diff(moment(preregistrationData.meeting_startTime,'HH:mm'), 'minutes'),
            checkIn:checkTime,
            checkOut:'',
            visitor_status:"In",
            visitPass_status:"Valid"

        });
        return res.status(200).json("Visitor Check In Success");
     }
     catch(e)
     {
        console.log(e);
        return res.status(400).json({error: e.message});
      }
    }
  }else{
    return res.status(200).json("Invalid Visitor Pass ID");
  }

    
};


const getCheckInOutDetails = async(req,res)=>{
    try{
        const checkInOut_details = await checkInOutModel.find({admin:req.admin._id});
        res.status(200).json(checkInOut_details);
    }
    catch(e)
    {
        console.log(e);
        res.status(400).json({error: e.message});
    }
};


const getSingleCheckInOutData = async(req,res)=>{
    const {id}=req.params;

    if(!mongoose.Types.ObjectId.isValid(id))
    {
        return res.status(400).json({message: "Check In Out Data not found"});
    }
    try{

        const checkInOut_data = await checkInOutModel.findById(id);

        if (!checkInOut_data) {
            return res.status(404).json({ message: "Check In Out Data not found" });
        }

        if(checkInOut_data.admin.toString() != req.admin._id.toString()){
              return  res.status(401).json({message: "Admin not Authorized"});
        }
       
        res.status(200).json(checkInOut_data);
    }
    catch(e)
    {
        res.status(400).json({error: e.message});
    }
};


const getCheckInOutPass = async(req,res)=>{
    const {id}=req.params;

    try{

        if(id[0]==='M'){
            const meetingData = await meetingRegistrationModel.findOne({meeting_id:id})

            if(meetingData){
                res.status(200).json(meetingData);
            }else{
                return  res.status(200).json("Invalid Visit Pass ID");
            }

            if(meetingData && (meetingData.admin.toString() != req.admin._id.toString())){
              return  res.status(401).json("Admin not Authorized");
            }
        }else if(id[0]==='P'){
           
          const preregistrationData = await preRegistrationModel.findOne({meeting_id:id})
          
          if(preregistrationData){
                res.status(200).json(preregistrationData);
            }else{
                return  res.status(200).json("Invalid Visit Pass ID");
            }

          if(preregistrationData && (preregistrationData.admin.toString() != req.admin._id.toString())){
              return  res.status(401).json("Admin not Authorized");
        }
        }else{
            res.status(200).json("Invalid Visit Pass ID");
        }
       
    }
    catch(e)
    {
        res.status(400).json({error: e.message});
    }
};

const updateSingleCheckInOutData = async(req,res)=>{
    const {id}=req.params;

    if(!mongoose.Types.ObjectId.isValid(id))
    {
       return res.status(400).json({message: "Check In Out Data not found"});
    }
    try{

        const checkInOut = await checkInOutModel.findById(id);

        if(!checkInOut){
            return res.status(404).json({ message: "Check In Out Data not found" });
        }

        if(checkInOut.admin.toString() != req.admin._id.toString()){
              return  res.status(401).json({message: "Admin not Authorized"});
        }

        const checkInOut_data = await checkInOutModel.findByIdAndUpdate({
            _id:id
        }, 
        {
            ...req.body
         });
       
        res.status(200).json(checkInOut_data);
    }
    catch(e)
    {
        res.status(400).json({error: e.message});
    }
};

const deleteSingleCheckInOutData = async(req,res)=>{
    const {id}=req.params;

    if(!mongoose.Types.ObjectId.isValid(id))
    {
        return res.status(400).json({message: "Check In Out Data not found"});
    }
    try{

        const checkInOut = await checkInOutModel.findById(id);

        if(!checkInOut){
            return res.status(404).json({ message: "Check In Out Data not found" });
        }

        if(checkInOut.admin.toString() != req.admin._id.toString()){
              return  res.status(401).json({message: "Admin not Authorized"});
        }

        await checkInOutModel.findByIdAndDelete(id);
                
        res.status(200).json("Check In Out Data deleted successfully");
    }
    catch(e)
    {
        res.status(400).json({error: e.message});
    }
};


module.exports = { checkInOutVisitor,
    getCheckInOutDetails, 
    getSingleCheckInOutData, 
    updateSingleCheckInOutData,
    deleteSingleCheckInOutData,
    getCheckInOutPass };