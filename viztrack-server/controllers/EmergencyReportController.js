const { mongoose } = require("mongoose");
const emergencyReportModel =require("../models/EmergencyReportModel.js");
const visitorRegistrationModel =require("../models/VisitorModel.js");
const employeeRegistrationModel =require("../models/EmployeeModel.js");
const PreRegistrationModel =require("../models/PreRegistrationModel.js");

const registerEmergencyReport = async(req,res)=>{

    const formData= req.body;

    var reportedID=[]
    var meetID=[]
    console.log(formData.reportPersonID);

    // check if the reported person is an employee or visitor.
    if(formData.reportPersonID[0]==='E')
    {
      reportedID = await employeeRegistrationModel.findOne({employee_id:formData.reportPersonID})
      meetID = await PreRegistrationModel.findOne({meeting_id:formData.meetingID,employee_id:formData.reportPersonID})
    }else if(formData.reportPersonID[0]==='V')
    {
       reportedID = await visitorRegistrationModel.findOne({visitor_id:formData.reportPersonID})
        meetID = await PreRegistrationModel.findOne({meeting_id:formData.meetingID, visitor_id:formData.reportPersonID})
    }else{
         return  res.status(200).json("Your ID is wrong");
    }

    // validate the reported person id and meeting id
    if(!reportedID){
        return  res.status(200).json("Your ID is wrong");
    }else if(!meetID){
        return  res.status(200).json("Meeting ID not found");
    }
    else{
    try{

        let updateDay='';
        if(formData.updateDate){
            updateDay=new Date(formData.updateDate).setHours(0,0,0,0)
        }
        const report_info = await emergencyReportModel.create({
            admin:new mongoose.Types.ObjectId(meetID.admin),
            reported_date:new Date().setHours(0,0,0,0),
            id:formData.reportPersonID,
            name: reportedID.name,
            designation: reportedID.designation,
            mobile_no: reportedID.mobile_no,
            meeting_id:formData.meetingID,
            issue:formData.issue,
            reported_for:formData.reportedFor,
            update_date:updateDay,
            update_time:formData.updateTime
        });
        res.status(200).json(report_info);
    }
    catch(e)
    {
        console.log(e);
        res.status(400).json({error: e.message});
    }
    }
};

const getEmergencyReports = async(req,res)=>{
    try{
        const emergency_reports = await emergencyReportModel.find({admin:req.admin._id});
        res.status(200).json(emergency_reports);
    }
    catch(e)
    {
        res.status(400).json({error: e.message});
    }
};

const deleteEmergencyReport = async(req,res)=>{
    const {id}=req.params;

    if(!mongoose.Types.ObjectId.isValid(id))
    {
        return res.status(400).json({message: "meeting id not found"});
    }
    try{

        const emergency_report = await emergencyReportModel.findById(id);

        if(!emergency_report){
            return res.status(404).json({ message: "emergency report not found" });
        }

        if(emergency_report.admin.toString() != req.admin._id.toString()){
              return  res.status(401).json({message: "Admin not Authorized"});
        }

        await emergencyReportModel.findByIdAndDelete(id);
        res.status(200).json("emergency report deleted successfully");
    }
    catch(e)
    {
        console.log(e);
        res.status(400).json({error: e.message});
    }
};


module.exports = { registerEmergencyReport, getEmergencyReports, deleteEmergencyReport};