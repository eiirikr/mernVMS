const express=require("express")
const router=express.Router();
const {auth} =require("../middlewares/Auth.js")

const { 
    registerMeeting, autofillMeetingDetails, getMeetingsDetails, getSingleMeetingData, 
    updateSingleMeetingData, deleteSingleMeetingData,sendConfirmationMail
}=require("../controllers/MeetingController.js");

router.post("/", auth, registerMeeting);
router.get("/:vid/:eid", auth, autofillMeetingDetails);
router.get("/",  auth, getMeetingsDetails);
router.get("/:id", auth, getSingleMeetingData);
router.patch("/:id", auth, updateSingleMeetingData);
router.delete("/:id",  auth, deleteSingleMeetingData);
router.post("/mail", auth, sendConfirmationMail);


module.exports=router;