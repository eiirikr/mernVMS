const adminRegistrationModel =require("../models/AdminModel.js");
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken')
const {sendEmail} =require("../modules/SendEmail.js");

function generateOTP()
{
    let i=0;
    var otp=''
    var chars="0123456789";
    while(i<6){
        otp+=chars.charAt(Math.floor(Math.random() * chars.length));
        i++;
    }
    return otp;
}

function GenerateAdminID()
  {
    var admin_id="A";
    let i=0;
    var chars="0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    while(i<5){
        admin_id+= chars.charAt(Math.floor(Math.random() * chars.length));
        i++;
    }
    return admin_id;

  }

const adminExist = async(req,res)=>{
    const formData= req.body;

    try{

        const adminEmail = await adminRegistrationModel.findOne({email:formData.email})
        const adminMobile = await adminRegistrationModel.findOne({mobile_no:formData.mobileNo})

        if(adminEmail){
            return  res.status(200).json("Account Already Exist with this Email");
        }else if(adminMobile){
            return  res.status(200).json("Account Already Exist with this Mobile number");
        }else{
            return  res.status(200).json("Not Already Exist!");
        }
        
    }catch(e){
        console.log(e);
        res.status(400).json({error: e.message});
    }
}

const registerAdmin = async (req, res) => {
    const formData = req.body;

    // Validate required fields
    const requiredFields = ['full_name', 'user_name', 'mobile_no', 'email', 'office', 'password'];
    for (const field of requiredFields) {
        if (!formData[field]) {
            return res.status(400).json({ error: `${field} is required` });
        }
    }

    try {
        // Generate salt for bcrypt
        const salt = await bcrypt.genSalt(10);
        // Hash the password with the generated salt
        const hashPassword = await bcrypt.hash(formData.password, salt);

        // Create admin record in the database
        const admin_info = await adminRegistrationModel.create({
            admin_id: GenerateAdminID(),
            full_name: formData.full_name,
            user_name: formData.user_name,
            mobile_no: formData.mobile_no,
            email: formData.email,
            office: `${formData.officeName}-${formData.officeLocation}`,
            password: hashPassword, // Store the hashed password
        });

        // Respond with the created admin information
        res.status(200).json(admin_info);
    } catch (e) {
        // Log error and send error response
        console.error('Error during admin registration:', e);
        res.status(400).json({ error: e.message });
    }
};




const adminLogin = async(req,res)=>{
    const formData= req.body;

    try{
        
        const admin = await adminRegistrationModel.findOne({email:formData.email});
        
        if(admin){
            const matchPassword= await bcrypt.compare(formData.password, admin.password)
            
            if(matchPassword){

                res.status(200).json({
                    id:admin.admin_id,
                    user_name:admin.user_name,
                    email:admin.email,
                    token: generateToken(admin._id)
                });
            }
            else{
                return  res.status(200).json("Invalid Password");
            }
        }
        else{
            return  res.status(200).json("Invalid Admin");
        }
    }
    catch(e)
    {
        console.log(e);
        res.status(400).json({error: e.message});
    }
};


const generateToken= (id)=>{
    return jwt.sign({id},process.env.JWT_SECRET_KEY,{
        expiresIn:'10d'
    })
}

const sendOTP=async(req,res)=>{
    
    const formData= req.body;

    try{

        if(formData.field==="forgot"){
          
            const admin = await adminRegistrationModel.findOne({email:formData.email});
        
            if(!admin)
            {
                return res.status(200).json("Email Not Found!");    
            }

        }

        const OTP=generateOTP()
        const messageText='Your OTP is '+OTP+"\n"+"valid only 2 minutes"
        const Subject="Time Admin Verification"

        sendEmail(formData.email, Subject, messageText);
           
        return res.status(200).json({otp:OTP});     
        
    }
    catch(e){
        console.log(e);
        return res.status(400).json({error: e.message});
    }
}

const updateAdminPassword = async(req,res)=>{
    
    const formData= req.body;
    const salt= await bcrypt.genSalt(10);
    const hashPassword=await bcrypt.hash(formData.password, salt)


    try{

        const admin = await adminRegistrationModel.findOne({email:formData.email});

        if(!admin){
            return res.status(404).json({ message: "admin account not found" });
        }

        const admin_data = await adminRegistrationModel.findOneAndUpdate({email:formData.email}, 
        { $set: {password: hashPassword} }, 
        { new: true }  );
       
        res.status(200).json(admin_data);
    }
    catch(e)
    {
        console.log(e);
        res.status(400).json({error: e.message});
    }
};


module.exports = { 
    adminExist, registerAdmin, adminLogin, sendOTP, updateAdminPassword
};