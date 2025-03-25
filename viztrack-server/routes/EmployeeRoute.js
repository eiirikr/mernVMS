const express=require("express")
const router=express.Router();
const {auth} = require("../middlewares/Auth.js")


const { 
     registerEmployee, getEmployeesDetails, getSingleEmployeeData, 
    updateSingleEmployeeData, updateSingleEmployeeDataWithProfile, deleteSingleEmployeeData
}=require("../controllers/EmployeeController.js");

router.post("/",auth, registerEmployee);
router.get("/", auth, getEmployeesDetails);
router.get("/:id", auth, getSingleEmployeeData);
router.patch("/:id", auth, updateSingleEmployeeData);
router.patch("/and/profile/:id", auth, updateSingleEmployeeDataWithProfile);
router.delete("/:id", auth, deleteSingleEmployeeData);



module.exports=router;