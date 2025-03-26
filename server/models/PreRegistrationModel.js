const mongoose = require("mongoose");
const Schema = mongoose.Schema;

const PreRegistrationDetailsSchema= new Schema(
    {     
          admin:{
            type:mongoose.Schema.Types.ObjectId,
            required:true,
            ref:'admin_details'
          },

          visitor_id:{
            type:String,
            required:true
          },

          visitor_name:{
            type:String,
            required:true
          },

          visitor_designation:{
            type:String,
            required:true
          },

           visitor_mobileNo:{
            type:String,
            required:true
          },

          visitor_address:{
            type:String,
            required:true
          },

           employee_id:{
            type:String,
            required:true
          },

           employee_name:{
            type:String,
            required:true
          },

          employee_designation:{
            type:String,
            required:true
          },

          employee_department:{
            type:String,
            required:true
          },

          employee_email:{
            type:String,
            required:true
          },

          employee_mobileNo:{
            type:String,
            required:true
          },

          registered_date:{
            type:Date,
            required:true
          },

          meeting_id:{
            type:String,
            required:true
          },
          
          meeting_date:{
            type:Date,
            required:true
         },

         meeting_startTime:{
            type:String,
            required:true
         },

        meeting_endTime:{
            type:String,
            required:true
         },

        meeting_purpose:{
            type:String,
            required:true
        }
    },
    {timestamps:true}
);

const PreRegistrationModel = mongoose.model("preRegistration_details",PreRegistrationDetailsSchema);

module.exports = PreRegistrationModel;