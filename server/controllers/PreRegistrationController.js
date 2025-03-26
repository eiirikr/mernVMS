const { mongoose } = require("mongoose");
const PreRegistrationModel =require("../models/PreRegistrationModel.js");
const {sendEmail} =require("../modules/SendEmail.js");
const {sendSMS} =require("../modules/SendSMS.js");
const moment=require('moment')

function GenerateVisitorPassID()
  {
    var pass_id="PVP";
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

        // check employee already have preregitrations on that date
        const preregisterDB = await PreRegistrationModel.find({employee_email:formData.employeeEmail, meeting_date:new Date(formData.meetingDate).setHours(0,0,0,0) });
        if(preregisterDB && preregisterDB.length > 0)
        {
            const formStartTime=moment(formData.meetingStartTime, 'hh:mm A');
            const formEndTime=moment(formData.meetingEndTime, 'hh:mm A');

            preregisterDB.forEach(preregisterData => {

            const preregisterStartTime=moment(preregisterData.meeting_startTime, 'hh:mm A');
            const preregisterEndTime=moment(preregisterData.meeting_endTime, 'hh:mm A');
        
            // check employee already have preregitrations on that time
            if(( formStartTime.isSame(preregisterStartTime) || formStartTime.isBetween(preregisterStartTime,preregisterEndTime) ) || formEndTime.isBetween(preregisterStartTime,preregisterEndTime)) {
                AlreadyMeet=true;
                return; 
            } })  }

            console.log(AlreadyMeet);

            // preregister meet if employee dont have preregistrations on that date and time
            if(AlreadyMeet){
                console.log('Already have meet');
               return res.status(200).json("Employee Already have meeting on that date & time");    
            }
            else{
                console.log("No meet");
                const messageText="Are you Available on "+formData.meetingDate+" "+formData.meetingStartTime+"-"+formData.meetingEndTime+"? sent your response immediately"
                +"\n"+"Form ID: "+formData.formID+"\n"+"Link: "+"http://localhost:3000/availability/form"

               const Subject="Meeting Pre-registration Confirmation"
               sendEmail(formData.employeeEmail, Subject, messageText);
               AlreadyMeet=false;
               return res.status(200).json("Meeting Confirmation Mail Sent to Employee, wait for response...");
            }
        
    }
    catch(e){
        console.log(e);
        return res.status(400).json({error: e.message});
    }
}


   
const preRegisterMeeting = async(req,res)=>{
    const formData= req.body;
    
    try{

        const meetingID=GenerateVisitorPassID();
        const meeting_info = await PreRegistrationModel.create({
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

            registered_date:new Date().setHours(0,0,0,0),
            meeting_date:new Date(formData.meetingDate).setHours(0,0,0,0),
            meeting_startTime:formData.meetingStartTime,
            meeting_endTime:formData.meetingEndTime,
            meeting_purpose:formData.meetingPurpose
            
        });

        const messageText="Meeting id: "+meetingID+"\n"+"Meeting date: "+formData.meetingDate+"\n"+"Meeting Time: "+formData.meetingStartTime+" - "+formData.meetingEndTime+"\n"+"Visitor name: "+formData.visitorName
        +"\n"+"Visitor designation: "+formData.visitorDesignation+"\n"+"Visitor mobileNo: "+formData.visitorMobileNo+"\n"+"Visitor Address :"+formData.visitorAddress+"\n"+"Emergency Report Link: "+"http://localhost:3000/emergency/report"
      
        const Subject="Meeting Pre-Registration"
        sendEmail(formData.employeeEmail, Subject, messageText);
        sendSMS(formData.visitorMobileNo, messageText)
      
        res.status(200).json(meeting_info);
    }
    catch(e)
    {
        console.log(e);
        res.status(400).json({error: e.message});
    }
};


const getPreRegistrationDetails = async(req,res)=>{
    try{
        const meeting_details = await PreRegistrationModel.find({admin:req.admin._id});
        res.status(200).json(meeting_details);
    }
    catch(e)
    {
        res.status(400).json({error: e.message});
    }
};


const getSinglePreRegistrationData = async(req,res)=>{
    const {id}=req.params;

    try{
        
        if(!id){
           return res.status(200).json({ message: "meeting data not found" });
        }

        const meeting_data = await PreRegistrationModel.findOne({meeting_id:id});


        if (!meeting_data) {
            return res.status(200).json({ message: "meeting data not found" });
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


const updateSinglePreRegistrationData = async(req,res)=>{

    const {id}=req.params;

    try{

        const meeting = await PreRegistrationModel.findOne({meeting_id:id});

        if (!meeting) {
            return res.status(404).json({ message: "meeting data not found" });
         }

        if(meeting.admin.toString() != req.admin._id.toString()){
              return  res.status(401).json({message: "Admin not Authorized"});
        }

        const meeting_data = await PreRegistrationModel.findOneAndUpdate({
            meeting_id:id
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

const deleteSinglePreRegistrationData = async(req,res)=>{
    const {id}=req.params;
     
    try{

        if(!id){
            return res.status(200).json({ message: "meeting data not found" });
        }
 
        const meeting_data = await PreRegistrationModel.findOne({meeting_id:id});

        if (!meeting_data) {
            return res.status(200).json({ message: "meeting data not found" });
         }

        if(meeting_data.admin.toString() != req.admin._id.toString()){
              return  res.status(401).json({message: "Admin not Authorized"});
        }

        await PreRegistrationModel.findOneAndDelete({meeting_id:id});
       
        res.status(200).json({message: "Meeting details deleted successfully"});
    }
    catch(e)
    {
        console.log(e);
        res.status(400).json({error: e.message});
    }
};


module.exports = { 
    preRegisterMeeting,
    getPreRegistrationDetails,
    getSinglePreRegistrationData,
    updateSinglePreRegistrationData,
    deleteSinglePreRegistrationData,
    sendConfirmationMail
    };


