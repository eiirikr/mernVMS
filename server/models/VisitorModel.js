const mongoose = require("mongoose");
const Schema = mongoose.Schema;

const VisitorDetailsSchema= new Schema(
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

          mobile_no:{
            type:String,
            required:true,
            unique:true
          },

          email:{
            type:String,
            unique:false
          },

          address:{
            type:String,
            required:true
          }
    },
    {timestamps:true}
);

const VisitorRegistrationModel = mongoose.model("visitor_details",VisitorDetailsSchema);

module.exports = VisitorRegistrationModel;