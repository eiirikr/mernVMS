const express = require('express');
const mongoose =require('mongoose');
require('dotenv').config();
const app = express();
const cors=require('cors');
const bodyParser = require('body-parser');
const admin_route=require("./routes/AdminRoute.js");
const visitor_route=require("./routes/VisitorRoute.js");
const employee_route=require("./routes/EmployeeRoute.js");
const meeting_route=require("./routes/MeetingRoute.js");
const preregister_route=require("./routes/PreRegistrationRoute.js");
const checkinout_route=require("./routes/CheckInOutRoute.js");
const emergencyReport_route=require("./routes/EmergencyReportRoute.js");

// middleware
/*app.use((req,res,next)=>{
    console.log("path: "+req.path+ " method: "+ req.method);
    next();
});*/

app.use(cors());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

// setup server
const server=app.listen(process.env.PORT,()=>{
    console.log("Server is running on port "+process.env.PORT);
});

// setup socket.io
io = require('socket.io')(server,{
    cors:{
        origin:"*"
    }
})

// setup socket.io connection
io.on("connection", (socket)=>{
    //console.log("Socket connected & Socket id is: ", socket.id)

// socket connect
socket.on('availabilityFormData', (formData) => {
    io.emit('meetingAvailability', formData);
    io.emit('preRegistrationAvailability', formData);
  });

// socket disconnect
socket.on('disconnect', () => {
    //console.log('Socket disconnected.');
});

})

// setup mongoDB
mongoose.connect(process.env.MONGODB_URI,{
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const connection=mongoose.connection

connection.once("open",()=>{
    console.log(".........MongoDB Connected Successfully.........")
});


app.use("/api/admin", admin_route);

app.use("/api/register/visitor", visitor_route);
app.use("/api/get/visitors/details", visitor_route);
app.use("/api/update/visitors/details", visitor_route);
app.use("/api/delete/visitors/details", visitor_route);

app.use("/api/register/employee", employee_route);
app.use("/api/get/employees/profiles", employee_route);
app.use("/api/get/employees/details", employee_route);
app.use("/api/update/employees/details", employee_route);
app.use("/api/delete/employees/details", employee_route);

app.use("/api/register/meeting", meeting_route);
app.use("/api/get/autofill/meeting/details", meeting_route);
app.use("/api/get/meetings/details", meeting_route);
app.use("/api/update/meetings/details", meeting_route);
app.use("/api/delete/meetings/details", meeting_route);
app.use("/api/send/meeting/confirmation", meeting_route);

app.use("/api/preregister/meeting", preregister_route);
app.use("/api/get/preregister/meetings/details", preregister_route);
app.use("/api/update/preregister/meetings/details", preregister_route);
app.use("/api/delete/preregister/meetings/details", preregister_route);
app.use("/api/send/preregister/meeting/confirmation", preregister_route);

app.use("/api/check/in/out", checkinout_route);
app.use("/api/get/all/check/in/out/details", checkinout_route);
app.use("/api/get/check/in/out/details", checkinout_route);
app.use("/api/get/check/in/out", checkinout_route);
app.use("/api/update/check/in/out/details", checkinout_route);
app.use("/api/delete/check/in/out/details", checkinout_route);

app.use("/api/register/emergency/report", emergencyReport_route);
app.use("/api/get/emergency/reports",  emergencyReport_route);
app.use("/api/delete/emergency/reports",  emergencyReport_route);





