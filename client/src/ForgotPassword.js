import React,{ useState, useEffect } from 'react';
import axios from 'axios';
import "./css/CheckInOut.css";
import { useNavigate } from "react-router-dom";

function ForgotPassword({onChangeAdminEmail, AdminEmailID}){
    
    const[adminEmail, setAdminEmail]= useState(AdminEmailID);
    const[genOTP, setGenOTP]= useState('');
    const[OTP, setOTP]= useState('');
    const[timeout, setTimeout]= useState(120);
    const[displayTimeout, setDisplayTimeout]= useState('');
    const [onTimer, setOnTimer] = useState(false);
    const[formErrors, setFormErrors]= useState({});

    const navigate = useNavigate();
   
    // handle change visitorPass ID
    const handleChangeEmail=(e)=>{
       setAdminEmail(e.target.value)
    };

    // handle change OTP
    const handleChangeOTP=(e)=>{
       setOTP(e.target.value)
    };

    // OTP Timer
    useEffect(() => {

      if(onTimer){
      
      let timer=''
      if(timeout >= -1){
       timer = setInterval(() => {
       
          const minutes = Math.floor(timeout / 60);
          const seconds = timeout % 60;
          setDisplayTimeout(`${minutes}:${seconds}`);
          setTimeout(timeout-1)
          console.log(timeout);
      }, 1000);

    }else{
      alert('Session Expired try again!')
      setOnTimer(false)
      setDisplayTimeout('')
      setOTP('')
      setGenOTP('')
    }
      
    return ()=> clearInterval(timer)

    }
    }, [timeout, onTimer]);

   
    // validate admin email and OTP
    const validation=(name, value)=>{
        const errors={}
        const otp_pattern=/^[0-9\b]+$/;
        const email_pattern=/^[^\s@]+@[^\s@]+\.[^\s@]{2,4}$/;
        
        if(name==="adminEmail"){
            if(value.length<1){
             errors.adminEmail="email is required"
            }else if(!email_pattern.test(value)){
               errors.adminEmail="invalid email"
            } 
        }

        if(name==="OTP"){
            if(value.length<1){
                errors.OTP="otp is required"
            }else if(!otp_pattern.test(value)){
                errors.OTP="otp must be numeric"
            }else if(value.length!==6){
                errors.OTP="otp must be 6 digits"
            }
        }
         return errors
    }

     // validate admin email and OTP during submit
     const onSubmitValid=(setter)=>(name, value)=>{ 
         setter((formErrors)=>{
            return{
                ...formErrors,
                ...validation(name, value)
            }
        })
     }
    
    // validate admin email and OTP during blur
    const onChangeBlur=(setter)=>(e)=>{
      setter((formErrors)=>{
        return{
            ...formErrors,
            ...validation(e.target.name, e.target.value)
        }
      })
    }

    // remove error during focus
    const onChangeFocus=(setter)=>(e)=>{
        
        setter((formErrors)=>{
        delete formErrors[e.target.name]
         return{
             ...formErrors
         }
      })
    }
    
    // post visitorPass ID
    const sentOTP =() => {

       onSubmitValid(setFormErrors)("adminEmail",adminEmail)
       console.log(formErrors);

      if(!formErrors.adminEmail && adminEmail!==''){
        axios.post("http://localhost:4000/api/admin/forgot/password",{email:adminEmail, field:"forgot"})
        .then(res=> {
            console.log(res.data);
            setGenOTP(res.data.otp)
            alert("OTP Sent to Your Email")
            setOnTimer(true); 
        })
        .catch(err=>console.log(err))
     } };


 // verify OTP to route change password component
 const handleSubmit=() => {

      onSubmitValid(setFormErrors)("adminEmail",adminEmail)
      onSubmitValid(setFormErrors)("OTP",OTP)
      onChangeAdminEmail(adminEmail)

      console.log(formErrors);

    if(!formErrors.OTP && (genOTP!=='' && OTP!=='')){ 

      console.log(OTP+" : "+genOTP);
      if(OTP===genOTP){ 
            setFormErrors({})
            setOTP('') 
            setGenOTP('')
            setOnTimer(false)
            setAdminEmail('')
            navigate('/admin/change/password')  
      }else if(OTP!==genOTP){
          alert("Invalid OTP!");
      }
     
    }

}


    return(
        <div>
         <div className="checkInOut">
          <div className="checkInOut-container">
            <div className="title">
                <h2>Email Verification</h2>
            </div>
            <div className="checkInOut-form">
             <div className="checkInOut-details">
                <div className="input-container">
                    <label  htmlFor="Admin_Email">Email</label>
                    <input className={formErrors.adminEmail ? 'inputError' : 'AdminEmail'} id="Admin_Email" name="adminEmail" type="email" onChange={handleChangeEmail} 
                     onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} value={adminEmail} />
                     <div onClick={()=>{setOnTimer(true); setTimeout(120); sentOTP()}} className='sent-otp-btn'>
                        <p>Send OTP</p>
                     </div>
                      {(formErrors.adminEmail && <p>{formErrors.adminEmail}</p>)}
                </div>
                <div className="input-container">
                 <label  htmlFor="OTP">Enter OTP</label>
                 <input className={formErrors.OTP ? 'inputError' : 'OTP'} id="OTP" name="OTP" type="text" onChange={handleChangeOTP} 
                  onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} value={OTP} />
                  {displayTimeout!=='' && <p className='otp-timeout' id="otp-timeout">{displayTimeout}</p>}
                  {(formErrors.OTP && <p>{formErrors.OTP}</p>)}
                </div>
                <div>
                 <button id="otp-submit-btn" onClick={handleSubmit}  type="submit">Submit</button>
                </div>
              </div>
            </div>
               <small>( check spam if you haven't got the OTP )</small>
            </div>    
        </div>
    </div>);
 };

export default ForgotPassword;