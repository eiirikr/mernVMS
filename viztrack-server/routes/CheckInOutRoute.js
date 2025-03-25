const express=require("express")
const router=express.Router();
const {auth} =require("../middlewares/Auth.js")

const { 
    checkInOutVisitor, getCheckInOutDetails, getSingleCheckInOutData, 
    updateSingleCheckInOutData, deleteSingleCheckInOutData, getCheckInOutPass
}=require("../controllers/CheckInOutController.js");

router.post("/", auth, checkInOutVisitor);
router.get("/", auth, getCheckInOutDetails);
router.get("/:id", auth, getSingleCheckInOutData);
router.get("/pass/:id", auth, getCheckInOutPass);
router.patch("/:id", auth, updateSingleCheckInOutData);
router.delete("/:id", auth,  deleteSingleCheckInOutData);

module.exports=router;