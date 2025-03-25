const express=require("express")
const router=express.Router();

const { 
    adminExist, registerAdmin, adminLogin, sendOTP, updateAdminPassword
}=require("../controllers/AdminController.js");

router.post("/email/exist", adminExist);
router.post("/signup", registerAdmin);
router.post("/login", adminLogin);
router.post("/forgot/password", sendOTP);
router.post("/change/password", updateAdminPassword);

module.exports=router;