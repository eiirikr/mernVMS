const { mongoose } = require("mongoose");
const meetingRegistrationModel =require("../models/MeetingModel.js");
const visitorRegistrationModel =require("../models/VisitorModel.js");
const employeeRegistrationModel =require("../models/EmployeeModel.js");
const checkInOutModel  =require("../models/CheckInOutModel.js");
const PreRegistrationModel =require("../models/PreRegistrationModel.js");
const {sendEmail} =require("../modules/SendEmail.js");
const {ObjectId}=require('mongodb')
const moment=require('moment')

function GenerateVisitorPassID()
  {
    var pass_id="MVP";
    let i=0;
    var chars="0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    while(i<5){
        pass_id+= chars.charAt(Math.floor(Math.random() * chars.length));
        i++;
    }
    return pass_id;

  }

const sendConfirmationMail=async(req,res)=>{
    const formData= req.body;
    console.log(formData);

    try{
        var AlreadyMeet=false;
        var AlreadyPreregister=false;
        const formStartTime=moment(new Date(), 'hh:mm A');

        // check employee already in meeting
        const checkDB = await checkInOutModel.find({employee_email:formData.employeeEmail, visit_date:new Date().setHours(0,0,0,0) });
         console.log("preregisterDB length:", checkDB.length);
        if((checkDB && checkDB.length > 0 ) && !AlreadyPreregister)
        {
            
           checkDB.forEach(checkData => {

            if(checkData.checkIn  && checkData.checkOut===''){
                const checkInTime=moment(checkData.checkIn, 'hh:mm A');

                if(formStartTime.isSameOrAfter(checkInTime) ) {
                    AlreadyMeet = true;
                    return; 
                } }   
         })
        }

        // check employee have already preregistration on that date
        const preregisterDB = await PreRegistrationModel.find({employee_email:formData.employeeEmail, meeting_date:new Date().setHours(0,0,0,0)});
        if(preregisterDB && preregisterDB.length > 0)
        {

           console.log("preregisterDB length:", preregisterDB.length);
    
           preregisterDB.forEach(preregisterData => {
           
            const preregisterStartTime = moment(preregisterData.meeting_startTime, 'hh:mm A');
            const preregisterEndTime = moment(preregisterData.meeting_endTime, 'hh:mm A');
       
            // check employee have already preregistration on that time
            if((formStartTime.isSame(preregisterStartTime) || formStartTime.isBetween(preregisterStartTime, preregisterEndTime)) ) {
                AlreadyPreregister=true;
                return;
            }
        }) } 

          console.log(AlreadyPreregister);

          // sent meeting confirmation mail if employee does not have meeting and preregistrations
          if(AlreadyMeet)
          {
              console.log("Already have meet");
               AlreadyMeet=false
               return res.status(200).json("Employee Already in meeting"); 

          }  else if(AlreadyPreregister){
               console.log("Already have meet");
                AlreadyPreregister=false
               return res.status(200).json("Employee Already have meeting"); 

            }else{
                const messageText="Are you Available Now? sent response immediately"+"\n"+"Form ID: "+formData.formID+
                "\n"+"Link: "+"http://localhost:3000/availability/form"

                const Subject="Meeting Confirmation"
                sendEmail(formData.employeeEmail, Subject, messageText);
                AlreadyMeet=false
                AlreadyPreregister=false
                res.status(200).json("Meeting Confirmation Mail Sent to Employee, wait for response...");
            } 
    }
    catch(e){
        console.log(e);
        res.status(400).json({error: e.message});
    }
}

   
const registerMeeting = async(req,res)=>{
    const formData= req.body;
    
    try{

        const meetingID=GenerateVisitorPassID();
        const meeting_info = await meetingRegistrationModel.create({
            admin: req.admin._id,
            meeting_id: meetingID,
            visitor_id:formData.visitorID,
            visitor_name:formData.visitorName,
            visitor_designation:formData.visitorDesignation,
            visitor_mobileNo:formData.visitorMobileNo,
            visitor_address:formData.visitorAddress,

            employee_id:formData.employeeID,
            employee_name:formData.employeeName,
            employee_designation:formData.employeeDesignation,
            employee_department:formData.employeeDepartment,
            employee_mobileNo:formData.employeeMobileNo,
            employee_email:formData.employeeEmail,

            meeting_date:new Date().setHours(0,0,0,0),
            meeting_duration:formData.meetingDuration,
            meeting_purpose:formData.meetingPurpose
            
        });

        const messageText="Meeting id: "+meetingID+"\n"+"Visitor name: "+formData.visitorName+"\n"+"Visitor designation: "+formData.visitorDesignation+"\n"+"Visitor mobileNo: "+formData.visitorMobileNo+"\n"+"Visitor Address :"+formData.visitorAddress
      
        const Subject="Meeting Registered"
        // notify employee about meeting
        sendEmail(formData.employeeEmail, Subject, messageText);
        res.status(200).json(meeting_info);
    }
    catch(e)
    {
        console.log(e);
        res.status(400).json({error: e.message});
    }
};


const autofillMeetingDetails = async(req,res)=>{

    const {vid,eid}=req.params;
    try{

    var visitor_data;
    var employee_data;
    var meeting_details;

    if(vid[0]==='V' || eid[0]==='E'){
        visitor_data = await visitorRegistrationModel.findOne({visitor_id:vid});
        employee_data = await employeeRegistrationModel.findOne({employee_id:eid});
    }else{
        visitor_data = await visitorRegistrationModel.findOne({mobile_no:vid});
        employee_data = await employeeRegistrationModel.findOne({mobile_no:eid});
    }

    if(!visitor_data && !employee_data){
        return res.status(200).json({ message: "Visitor & Employee not found" });
    }

    if(visitor_data  && (visitor_data.admin.toString() != req.admin._id.toString())){
        return  res.status(401).json({message: "Admin not Authorized"});
    }

    if(!employee_data){

        meeting_details = {
            visitor_data: visitor_data,
            employee_data: employee_data,
            profile_img_data: ''
         };    

      return res.status(200).json(meeting_details); 
    }
    
    if(employee_data){

    if(employee_data.admin.toString() != req.admin._id.toString()){
         return  res.status(401).json({message: "Admin not Authorized"});
    }

     const db=mongoose.connections[0].db;
     const gridBucket=new mongoose.mongo.GridFSBucket(db,{
            bucketName:"employee_profiles"
    });

    if (!mongoose.Types.ObjectId.isValid(employee_data.profileImgId)) {
       return res.status(400).json({ message: "Invalid profile image ID" });
    }
     
    // download profile image from gridbucket
    const readImg= gridBucket.openDownloadStream(new ObjectId(employee_data.profileImgId))

    const imageDataChunks = [];

    // read profile image
    readImg.on('data', (chunk) => {
        imageDataChunks.push(chunk);
    });

    // combine profile image
    readImg.on('end', () => {
      const imageData = Buffer.concat(imageDataChunks).toString('base64')

      meeting_details = {
        visitor_data: visitor_data,
        employee_data: employee_data,
        profile_img_data: imageData 
      };

      res.status(200).json(meeting_details); 

     })  }


    } 
    catch(e)
    {
        console.log(e)
        res.status(400).json({error: e.message});
    }
};

const getMeetingsDetails = async(req,res)=>{
    try{
        const meeting_details = await meetingRegistrationModel.find({admin:req.admin._id});
        res.status(200).json(meeting_details);
    }
    catch(e)
    {
        res.status(400).json({error: e.message});
    }
};


const getSingleMeetingData = async(req,res)=>{
    const {id}=req.params;

    if(!mongoose.Types.ObjectId.isValid(id))
    {
        return res.status(400).json({message: "meeting not found"});
    }
    try{

        const meeting_data = await meetingRegistrationModel.findById(id);

        if (!meeting_data) {
            return res.status(404).json({ message: "meeting data not found" });
         }

        if(meeting_data.admin.toString() != req.admin._id.toString()){
              return  res.status(401).json({message: "Admin not Authorized"});
        }

        res.status(200).json(meeting_data);
    }
    catch(e)
    {
        res.status(400).json({error: e.message});
    }
};

const updateSingleMeetingData = async(req,res)=>{

    const {id}=req.params;

    if(!mongoose.Types.ObjectId.isValid(id))
    {
        return res.status(400).json({message: "meeting data not found"});
    }
    try{

        const meeting = await meetingRegistrationModel.findById(id);

        if (!meeting) {
            return res.status(404).json({ message: "meeting data not found" });
         }

        if(meeting.admin.toString() != req.admin._id.toString()){
              return  res.status(401).json({message: "Admin not Authorized"});
        }
       
        const meeting_data = await meetingRegistrationModel.findByIdAndUpdate({
            _id:id
        }, 
        {
            ...req.body
         });
       
        res.status(200).json(meeting_data);
    }
    catch(e)
    {
        res.status(400).json({error: e.message});
    }
};

const deleteSingleMeetingData = async(req,res)=>{
    const {id}=req.params;

    if(!mongoose.Types.ObjectId.isValid(id))
    {
        return res.status(200).json({message: "meeting not found"});
    }
    try{

        const meeting_data = await meetingRegistrationModel.findById(id);

        if (!meeting_data) {
            return res.status(404).json({ message: "meeting data not found" });
         }

        if(meeting_data.admin.toString() != req.admin._id.toString()){
              return  res.status(401).json({message: "Admin not Authorized"});
        }

        await meetingRegistrationModel.findByIdAndDelete(id);
       
        res.status(200).json("Meeting details deleted successfully");
    }
    catch(e)
    {
        console.log(e);
        res.status(400).json({error: e.message});
    }
};

module.exports = { 
    registerMeeting,
    autofillMeetingDetails,
    getMeetingsDetails,
    getSingleMeetingData,
    updateSingleMeetingData,
    deleteSingleMeetingData,
    sendConfirmationMail
};


