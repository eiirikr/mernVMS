const express=require("express")
const router=express.Router();
const {auth} =require("../middlewares/Auth.js")

const { 
    preRegisterMeeting, getPreRegistrationDetails, getSinglePreRegistrationData, 
    updateSinglePreRegistrationData, deleteSinglePreRegistrationData,sendConfirmationMail
}=require("../controllers/PreRegistrationController.js");

router.post("/", auth, preRegisterMeeting);
router.get("/", auth, getPreRegistrationDetails);
router.get("/:id", auth, getSinglePreRegistrationData);
router.patch("/:id", auth, updateSinglePreRegistrationData);
router.delete("/:id", auth, deleteSinglePreRegistrationData);
router.post("/mail", auth, sendConfirmationMail);


module.exports=router;