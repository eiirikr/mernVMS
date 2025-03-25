const { mongoose } = require("mongoose");
const employeeRegistrationModel =require("../models/EmployeeModel.js");
const gridFsStorage = require("../middlewares/multerGridFsStorage.js")
const {ObjectId}=require('mongodb')

function GenerateEmployeeID()
  {
    var employee_id="E";
    let i=0;
    var chars="0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    while(i<5){
        employee_id+= chars.charAt(Math.floor(Math.random() * chars.length));
        i++;
    }
    return employee_id;

  }

   
const registerEmployee =async(req,res)=>{
    // setup grid Bucket
    const db=mongoose.connections[0].db;
    const gridBucket=new mongoose.mongo.GridFSBucket(db,{
                bucketName:"employee_profiles"
    });
    
 try{
    // upload profile image to mongodb
    gridFsStorage().single('profileImg')(req, res, async (error) => {

        if(error)
        {
            console.log(error);
             return  res.status(200).json("profile img not found");
        }

         const formData= req.body;
        try{
            const employeeEmail = await employeeRegistrationModel.findOne({email:formData.email})
            const employeeMobile = await employeeRegistrationModel.findOne({mobile_no:formData.mobileNo})
            let employee_info;
            if(employeeEmail)
            { 
                // delete profile image
                gridBucket.delete(new ObjectId(req.file.id))
                return  res.status(200).json("Account Already Exist with this Email");
            }else if(employeeMobile){
                 // delete profile image
                gridBucket.delete(new ObjectId(req.file.id))
               return  res.status(200).json("Account Already Exist with this Mobile number");
            }else{

            employee_info = await employeeRegistrationModel.create({
            admin:req.admin._id,
            employee_id:GenerateEmployeeID(),
            profileImgId:req.file.id,
            name:formData.name,
            gender:formData.gender,
            age:formData.age,
            designation:formData.designation,
            department:formData.department,
            mobile_no:formData.mobileNo,
            email:formData.email,
            address:formData.address,
            applied_leave:formData.appliedLeave,
            leave_status:formData.leaveStatus,
            leave_start:formData.leaveStart,
            leave_end:formData.leaveEnd,
            onsite:formData.onsite,
            onsite_start:formData.onsiteStart,
            onsite_end:formData.onsiteEnd
        });}
        return res.status(200).json(employee_info);
      
        }catch(e)
        {   
            console.log(e);
            // delete profile imagage
            gridBucket.delete(new ObjectId(req.file.id))
            return res.status(400).json({error: e.message});
        }; }); }
        catch(e){
            console.log(e);
            return res.status(400).json({error: e.message});
        }
   
};


const getEmployeesDetails = async(req,res)=>{
    try{
        const employee_details = await employeeRegistrationModel.find({admin:req.admin._id});
        res.status(200).json(employee_details);
    }
    catch(e)
    {
        res.status(400).json({error: e.message});
    }
};


const getSingleEmployeeData = async(req,res)=>{
    const {id}=req.params;

    try{

      if(!mongoose.Types.ObjectId.isValid(id))
        {
         res.status(400).json({message: "Employee not found"});
        }
      
    const employee_data = await employeeRegistrationModel.findById(id);

        if (!employee_data) {
           return res.status(404).json({ message: "Employee not found" })
        }

        if(employee_data.admin.toString() != req.admin._id.toString()){
              return  res.status(401).json({message: "Admin not Authorized"});
        }

    console.log(employee_data.profileImgId);

     if (!mongoose.Types.ObjectId.isValid(employee_data.profileImgId)) {
      return res.status(400).json({ message: "Invalid profile image ID" });
    }

    // setup grid Bucket
    const db=mongoose.connections[0].db;
    const gridBucket=new mongoose.mongo.GridFSBucket(db,{
                bucketName:"employee_profiles"
    });
    
    // download image form gridbucket based on id
    const readImg=gridBucket.openDownloadStream(new ObjectId(employee_data.profileImgId))
   

    const imageDataChunks = [];

    // read image chunks
    readImg.on('data', (chunk) => {
        imageDataChunks.push(chunk);
    });

    // combine image chunks
    readImg.on('end', () => {
    const imageData = Buffer.concat(imageDataChunks).toString('base64');

     const employee_details = {
      employee_data: employee_data,
      profile_img_data: imageData };

      res.status(200).json(employee_details);
   }) }
    catch(e)
    {
        res.status(400).json({error: e.message});
    }
};


const updateSingleEmployeeData = async(req,res)=>{

    const {id}=req.params;

    if(!mongoose.Types.ObjectId.isValid(id))
    {
        res.status(400).json({message: "employee not found"});
    }
    try{

        const employee = await employeeRegistrationModel.findById(id);

        if(!employee){
            return res.status(404).json({ message: "employee not found" });
        }

        if(employee.admin.toString() != req.admin._id.toString()){
              return  res.status(401).json({message: "Admin not Authorized"});
        }

         if(employee.email!==req.body.email)
        {
            const employeeEmail = await employeeRegistrationModel.findOne({email:req.body.email})
        
            if(employeeEmail){
                return  res.status(200).json("Email Already Exist");
            }
        }
        
         if(employee.mobile_no!==req.body.mobile_no)
         {
            const employeeMobile = await employeeRegistrationModel.findOne({mobile_no:req.body.mobile_no})

             if(employeeMobile){
                return  res.status(200).json("Mobile Number Already Exist");
             }
        }

        const employee_data = await employeeRegistrationModel.findByIdAndUpdate({
            _id:id
        }, 
        {
            ...req.body
         });
       
        res.status(200).json(employee_data);
    }
    catch(e)
    {
        res.status(400).json({error: e.message});
    }
};

const updateSingleEmployeeDataWithProfile = async(req,res)=>{
    // setup grid Bucket
    const db=mongoose.connections[0].db;
    const gridBucket=new mongoose.mongo.GridFSBucket(db,{
                bucketName:"employee_profiles"
    });

   try{

    // upload profile image to mongodb
    gridFsStorage().single('profileImg')(req, res, async (error) => {
    if (error) {
         return res.status(400).json({ error: error.message });
     }

    const {id}=req.params;

    if(!mongoose.Types.ObjectId.isValid(id))
    {
        return res.status(400).json({message: "Employee Data not found"});
    }
    
    const employee_data = await employeeRegistrationModel.findById(id);


        if(!employee_data ){
            return res.status(404).json({ message: "employee not found" });
        }

        if(employee_data.admin.toString() != req.admin._id.toString()){
              return  res.status(401).json({message: "Admin not Authorized"});
        }


        if(employee_data.email!==req.body.email)
        {
            const employeeEmail = await employeeRegistrationModel.findOne({email:req.body.email})
        
            if(employeeEmail){
                return  res.status(200).json("Email Already Exist");
            }
        }
        
         if(employee_data.mobile_no!==req.body.mobile_no)
         {
            const employeeMobile = await employeeRegistrationModel.findOne({mobile_no:req.body.mobile_no})

             if(employeeMobile){
                return  res.status(200).json("Mobile Number Already Exist");
             }
        }
         

        let imgStatus="" 

         if(!mongoose.Types.ObjectId.isValid(employee_data.profileImgId)){
            imgStatus="Employee Profile Image Not Found"
         }
         else{

            try{
              // delete profile image
              gridBucket.delete(new ObjectId(employee_data.profileImgId))
            }
            catch(e){
                imgStatus="Error while delete Profile Image"
                console.log(e);
            }

        try{

        await employeeRegistrationModel.findByIdAndUpdate({
            _id:id
        }, 
        {
            ...req.body,
              profileImgId: req.file.id,
         });
        
         imgStatus="Employee Profile Image Updated Successfully"
        }
        catch(e){
            imgStatus="Error while update employee data";
            console.log(e);
        }

    } 
     res.status(200).json("Employee Data Updated Successfully"+"\n"+imgStatus);
  })

    }catch(e)
    {
        res.status(400).json({error: e.message});
    }
};


const deleteSingleEmployeeData = async(req,res)=>{
    const {id}=req.params;
    // setup grid Bucket
    const db=mongoose.connections[0].db;
    const gridBucket=new mongoose.mongo.GridFSBucket(db,{
                bucketName:"employee_profiles"
    });

    if(!mongoose.Types.ObjectId.isValid(id))
    {
        return res.status(400).json({message: "Employee Data not found"});
    }
    try{

        let imgStatus=""
        const employee_data = await employeeRegistrationModel.findById(id);

        if (!employee_data.profileImgId) {
            return res.status(404).json({ message: "Employee Profile Image not found" });
         }

        if(employee_data.admin.toString() != req.admin._id.toString()){
              return  res.status(401).json({message: "Admin not Authorized"});
        }

        await employeeRegistrationModel.findByIdAndDelete(id);

        try{
           // delete profile image
           gridBucket.delete(new ObjectId(employee_data.profileImgId)) 
           imgStatus="Employee Profile Image deleted successfully"}
        catch(e){
            imgStatus="Error while delete employee profile image"
        }
       
        res.status(200).json("Employee Data Deleted Successfully"+"\n"+imgStatus);
    }
    catch(e)
    {
        res.status(400).json({error: e.message});
    }
};

 

module.exports = { 
    registerEmployee, 
    getEmployeesDetails, 
    getSingleEmployeeData,
    updateSingleEmployeeData,
    updateSingleEmployeeDataWithProfile, 
    deleteSingleEmployeeData, 
    };