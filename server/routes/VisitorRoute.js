const express=require("express")
const router=express.Router();
const {auth} =require("../middlewares/Auth.js")

const { 
    registerVisitor, getVisitorsDetails, getSingleVisitorData, updateSingleVisitorData, deleteSingleVisitorData
}=require("../controllers/VisitorController.js");

router.post("/", auth, registerVisitor);
router.get("/", auth, getVisitorsDetails);
router.get("/:id", auth, getSingleVisitorData);
router.patch("/:id", auth, updateSingleVisitorData);
router.delete("/:id", auth, deleteSingleVisitorData);

module.exports=router;