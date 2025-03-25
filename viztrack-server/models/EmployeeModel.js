const mongoose = require("mongoose");
const Schema = mongoose.Schema;

const EmployeeDetailsSchema= new Schema(
    {
          admin:{
            type:mongoose.Schema.Types.ObjectId,
            required:true,
            ref:'admin_details'
          },

          employee_id:{
            type:String,
            required:true
          },

          profileImgId:{
            type:String,
            required:true
          },

          name:{
            type:String,
            required:true
          },

          gender:{
            type:String,
            required:true
          },

          age:{
            type:Number,
            required:true
          },

          designation:{
            type:String,
            required:true
          },

          department:{
            type:String,
            required:true
          },

          mobile_no:{
            type:String,
            required:true,
            unique:true
          },

          email:{
            type:String,
            required:true,
            unique:true
          },

          address:{
            type:String,
            required:true
          },

          applied_leave:{
            type:String,
            required:true
          },

           leave_status:{
            type:String
          },

           leave_start:{
            type:String
          },

          leave_end:{
            type:String
          },

          onsite:{
            type:String,
            required:true
          },

          onsite_start:{
            type:String
          },

          onsite_end:{
            type:String
          }
    },
    {timestamps:true}
);

const EmployeeRegistrationModel = mongoose.model("employee_details",EmployeeDetailsSchema);

module.exports = EmployeeRegistrationModel;