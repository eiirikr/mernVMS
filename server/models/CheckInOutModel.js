const mongoose = require("mongoose");
const Schema = mongoose.Schema;

const CheckInOutSchema= new Schema(
    {    
          admin:{
            type:mongoose.Schema.Types.ObjectId,
            required:true,
            ref:'admin_details'
          },

          visitPass_id:{
            type:String,
            required:true
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

          employee_id:{
            type:String,
            required:true
          },

          employee_email:{
            type:String,
            required:true
          },

          visit_purpose:{
            type:String,
            required:true
          },

          visit_date:{
            type:Date,
            required:true
          },

          visit_startTime:{
            type:String,
            required:true
          },

          visit_endTime:{
            type:String,
            required:true
          },
          
          allotted_visit_duration:{
            type:String,
            required:true
          },

          visitor_status:{
            type:String,
            required:true
          },

          checkIn:{
            type:String
          },

          checkOut:{
            type:String
          },

          visitPass_status:{
            type:String,
            required:true
          }

    },
    {timestamps:true}
);

const CheckInOutModel = mongoose.model("checkinout_details",CheckInOutSchema);

module.exports = CheckInOutModel;