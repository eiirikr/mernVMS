const express=require("express")
const router=express.Router();
const {auth} =require("../middlewares/Auth.js")

const { 
    registerEmergencyReport, getEmergencyReports, deleteEmergencyReport
}=require("../controllers/EmergencyReportController.js");

router.post("/", registerEmergencyReport);
router.get("/", auth, getEmergencyReports);
router.delete("/:id", auth, deleteEmergencyReport);

module.exports=router;