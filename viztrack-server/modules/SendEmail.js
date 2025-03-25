const nodemailer = require('nodemailer')

const sendEmail=(To,Sub,Message)=>{

const transpoter = nodemailer.createTransport({
    host: 'smtp.office365.com', 
    port: 587,
    service:"hotmail",
    auth:{
        user:process.env.EMAIL,
        pass:process.env.EMAIL_PASSWORD
    }
});

const mailOptions={
    from:"viztrack@outlook.com",
    to:To,
    subject:Sub,
    text:Message
}

transpoter.sendMail(mailOptions, function(err,info){
    if(err){
        console.log(err);
    } else{
     console.log(info.response);
    }
})

}

module.exports = {sendEmail};