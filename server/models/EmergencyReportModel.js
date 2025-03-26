const mongoose = require("mongoose");
const Schema = mongoose.Schema;

const EmergencyReportSchema= new Schema(
    {    

        admin:{
            type:mongoose.Schema.Types.ObjectId,
            required:true,
            ref:'admin_details'
          },
         
         reported_date:{
            type:Date,
            required:true
         },
         
          id:{
            type:String,
            required:true
          },

          name:{
            type:String,
            required:true
          },

          designation:{
            type:String,
            required:true
          },

          mobile_no:{
            type:String,
            required:true,
          },

          meeting_id:{
            type:String,
            required:true
         },

          issue:{
            type:String,
            required:true,
          },

          reported_for:{
            type:String,
            required:true,
          },

          update_date:{
            type:Date
          },

           update_time:{
            type:String
          }
    },
    {timestamps:true}
);

const EmergencyReportModel = mongoose.model("emergency_report",EmergencyReportSchema);

module.exports = EmergencyReportModel;