const mongoose = require("mongoose");
const Schema = mongoose.Schema;

const AdminDetailsSchema= new Schema(
    {
          admin_id:{
            type:String,
            required:true
          },

          full_name:{
            type:String,
            required:true
          },

          user_name:{
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


        office:{
            type:String,
            required:true
          },

        
        password:{
            type:String,
            required:true
          }

    },
    {timestamps:true}
);

const AdminRegistrationModel = mongoose.model("admin_details", AdminDetailsSchema);

module.exports = AdminRegistrationModel;