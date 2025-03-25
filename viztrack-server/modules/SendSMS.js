const twilio = require('twilio')

const sendSMS= (receiver, messageText)=> {

      const client = new twilio(process.env.TWILIO_SID, process.env.TWILIO_AUTH);

       client.messages.create({
            from: process.env.TWILIO_MOBILE_NO,
            to: '+91'+receiver,
            body:messageText
        })
    .then(message => {
        console.log("Message Sent Successfully");
        console.log("Twilio",message.sid);})
    .catch(err=>console.log("Twilio",err))
  
}

module.exports = {sendSMS};