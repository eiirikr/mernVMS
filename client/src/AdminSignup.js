import  { useState, useEffect } from 'react';
import axios from 'axios';
import "./css/AdminSignup.css";
import { useNavigate } from "react-router-dom";
import { PiEyeLight } from 'react-icons/pi';
import { PiEyeSlashLight } from 'react-icons/pi';
import { Link } from 'react-router-dom';
import {AiOutlineClose } from 'react-icons/ai';

function AdminSignup(){

    const navigate = useNavigate();

    const initialFormData = {
        fullName: '',
        userName: '',
        mobileNo: '',
        email: '',
        officeName: '',
        officeLocation: '',
        password: '',
        confirmPassword: '',
    };

    const[formData, setFormData]= useState(initialFormData);
    const[formErrors, setFormErrors]= useState({});
    const[passwordShow, setPasswordShow]= useState(false);
    const[confirmPasswordShow, setConfirmPasswordShow]= useState(false);
    const [isSubmit, setIsSubmit] = useState(false);
    const[alreadyExist, setAlreadyExist]= useState('');
    const[genOTP, setGenOTP]= useState('');
    const[OTP, setOTP]= useState('');
    const[timeout, setTimeout]= useState(120);
    const[displayTimeout, setDisplayTimeout]= useState('');
    const [onTimer, setOnTimer] = useState(false);
    
    // handle change admin signup details
    const handleChange=(event)=>{
       
        setFormData({
            ...formData,
            [event.target.name]:event.target.value
        });
    };

    // handle change OTP
    const handleChangeOTP=(e)=>{
       setOTP(e.target.value)
    };
  
    // validate admin signup details
     const validation=(name, value)=>{
        const errors={};
        const email_pattern=/^[^\s@]+@[^\s@]+\.[^\s@]{2,4}$/;
        const mobileNo_pattern=/^[0-9\b]+$/;
        const name_pattern=/^[a-zA-Z\s]+$/;

        if(name==="OTP" && (onTimer && genOTP!=='')){
            if(value.length<1){
                errors.OTP="otp is required"
            }else if(!mobileNo_pattern.test(value)){
                errors.OTP="otp must be numeric"
            }else if(value.length!==6){
                errors.OTP="otp must be 6 digits"
            }
        }

        if(name==="fullName"){
            if(value.length<1){
                 errors.fullName="full name is required"
            }else if(!name_pattern.test(value)) {
                 errors.fullName = "full name only contain letters";
           } }


        if(name==="userName"){
            if(value.length<1){
                console.log('user');
                errors.userName="user name is required"
            }else if(!name_pattern.test(value)) {
                errors.userName = "user name only contain letters";
        }  }

        if(name==="email"){

        if(value.length<1){
            errors.email="email is required"
        }else if(!email_pattern.test(value)){
            errors.email="invalid email"
        } }


        if(name==="mobileNo"){
      
         if(value.length<1){
            errors.mobileNo="mobile number is required"
         }else if(!mobileNo_pattern.test(value)){
            errors.mobileNo="mobile number must be numeric"
         }else if(value.length!==10){
            errors.mobileNo="mobile number must have 10 digits"
         } 
      }
        
        if(name==="officeName"){
        if(value.length<1){
            errors.officeName="office name is required"
        } }


        if(name==="officeLocation"){
            if(value.length<1){
                errors.officeLocation="office location is required"
            } 
       }

        if(name==="password"){
        if(value.length<1){
            errors.password="password is required"
        }else if(value.length<6){
             errors.password="password must have 6 characters"
        } }

        if(name==="confirmPassword"){
        if(value.length<1){
            errors.confirmPassword="confirm password is required"
        }else if(value.length<6){
             errors.confirmPassword=" confirm password must have 6 characters"
        }else if((formData.password !=='' && formData.confirmPassword!=='') && (formData.password !== formData.confirmPassword)){
            errors.confirmPassword="password & confirm password not match"
        } }

        return errors
    }

    // validate admin signup details during submit
    const onSubmitValid=(setter)=>(formdata)=>{
      for(const field in formdata) { 
         setter((formErrors)=>{
            return{
                ...formErrors,
                ...validation(field, formdata[field])
            }
        })
    } }

    // validate admin signup details during blur
    const onChangeBlur=(setter)=>(e)=>{
      setter((formErrors)=>{
        return{
            ...formErrors,
            ...validation(e.target.name, e.target.value),
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

    // check email already exist
    const handleSubmit = async(e) => {
        e.preventDefault();

        console.log(formData); 
        console.log(formErrors); 
        
        if((Object.keys(formErrors).length<1) && isSubmit){

        axios.post("http://localhost:4000/api/admin/email/exist",{email:formData.email,mobileNo:formData.mobileNo})
        .then(res=> {
            if(res.data==="Account Already Exist with this Email" || res.data==="Account Already Exist with this Mobile number"){
                alert(res.data);
                setAlreadyExist("yes")
            }else{
                setAlreadyExist("no")
            } })
        .catch(err=>console.log(err)) 

         }else{
            setIsSubmit(false)
         }
  };

  // sent OTP if email not exist
  useEffect(()=>{

    if(alreadyExist==="no" && isSubmit)
      axios.post("http://localhost:4000/api/admin/forgot/password",{email:formData.email, field:"signup"})
        .then(res=> {
            console.log(res.data);
            setGenOTP(res.data.otp)
            alert("OTP Sent to Your Email")
            setOnTimer(true); 
            setTimeout(120)
            setAlreadyExist('')
            setIsSubmit(false)
        })
        .catch(err=>console.log(err))
  },[alreadyExist, isSubmit, genOTP])


   // OTP timer
   useEffect(() => {

      let timer=''

      if(onTimer){
      
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


   // OTP verification for admin account creation
   const handleVerify=async()=>{

     console.log(genOTP);
     console.log(OTP);

    if(OTP!==''){

    if((genOTP!=='' && OTP!=='') && (OTP===genOTP)){


       await axios.post("http://localhost:4000/api/admin/signup", formData)
        .then(res=> {
            alert("Admin Account Created Successfully!");
            console.log(res); 
            setFormErrors({});
            setOTP('') 
            setGenOTP('')
            setOnTimer(false)
            setFormData(initialFormData);
            navigate("/admin/login") })
        .catch(err=>console.log(err))

     }
     else if(OTP!==genOTP){
           alert("Invalid OTP")
     }

    }

  }
    return(
         <div>
         <div className="admin-signup">
          <div className="admin-container">
            <div className="title">
                <h2>Admin Signup</h2>
            </div>
            <form onSubmit={handleSubmit} className="admin-form">
             <div className="admin-details">
                <div className="input-container">
                    <label htmlFor="Full_name">Full name</label>
                    <input className={formErrors.fullName ? 'inputError' : 'Full_Name'} id="Full_name" name="fullName" type="text" onChange={handleChange} 
                    onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} value={formData.fullName} />
                     {(formErrors.fullName && <p>{formErrors.fullName}</p>)}
                </div>
                <div className="input-container">
                    <label htmlFor="User_name">User name</label>
                    <input className={formErrors.userName ? 'inputError' : 'User_Name'} id="User_name" name="userName" type="text" onChange={handleChange}
                     onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} value={formData.userName} />
                     {(formErrors.userName && <p>{formErrors.userName}</p>)}
                </div>
                 <div className="input-container">
                    <label  htmlFor="Email">Email</label>
                    <input className={formErrors.email ? 'inputError' : 'Email'} id="Email" name="email" type="email" onChange={handleChange} 
                    onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} value={formData.email} />
                    {(formErrors.email && <p>{formErrors.email}</p>)}
                </div>
                <div className="input-container">
                    <label  htmlFor="Mobile_no">Mobile number</label>
                    <input className={ formErrors.mobileNo ? 'inputError' : 'Mobile_Number'} id="Mobile_no" name="mobileNo" type="text" onChange={handleChange} 
                    onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} value={formData.mobileNo} />
                     {(formErrors.mobileNo && <p>{formErrors.mobileNo}</p>)}
                </div>
                <div className="input-container">
                    <label htmlFor="OfficeName">Office Name</label>
                    <input className={ formErrors.officeName ? 'inputError' : 'Office_Name'} id="OfficeName" name="officeName" type="text" onChange={handleChange} 
                    onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} value={formData.officeName} />
                     {(formErrors.officeName && <p>{formErrors.officeName}</p>)}
                </div>
                <div className="input-container">
                    <label htmlFor="OfficeLocation">Office Location</label>
                    <input className={ formErrors.officeLocation ? 'inputError' : 'Office_Location' } id="OfficeLocation" name="officeLocation" type="text" onChange={handleChange} 
                    onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} value={formData.officeLocation} />
                     {(formErrors.officeLocation && <p>{formErrors.officeLocation}</p>)}
                </div>
                <div className="input-container">
                    <label htmlFor="Password">Password</label>
                    <div>
                    <input className={ formErrors.password  ? 'inputError' : '_Password' } id="Password" name="password" type={passwordShow ? 'text' : 'password'} onChange={handleChange} 
                    onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} value={formData.password} />
                    <div className='eye-icon' onClick={()=>setPasswordShow(!passwordShow)}>
                        {passwordShow && (<PiEyeLight />)}
                        {!passwordShow && (<PiEyeSlashLight />)}
                    </div>
                    </div>
                     {(formErrors.password && <p>{formErrors.password}</p>)}
                </div>
                <div className="input-container">
                    <label htmlFor="ConfirmPassword">Confirm Password</label>
                    <div>
                    <input className={ formErrors.confirmPassword ? 'inputError' : 'Confirm_Password'} id="ConfirmPassword" name="confirmPassword" type={confirmPasswordShow ? 'text' : 'password'} onChange={handleChange}  
                    onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} value={formData.confirmPassword} />
                    <div className='eye-icon' onClick={()=>setConfirmPasswordShow(!confirmPasswordShow)}>
                        {confirmPasswordShow && (<PiEyeLight />)}
                        {!confirmPasswordShow && (<PiEyeSlashLight />)}
                    </div>
                    </div>
                     {(formErrors.confirmPassword && <p>{formErrors.confirmPassword}</p>)}
                </div>
                <button onClick={()=>{onSubmitValid(setFormErrors)(formData); setIsSubmit(true)}} type="submit">Submit</button>
            </div>
             <div className="Links">
                 <p>Already have an Account?</p>
                 <Link to="/admin/login" className='LoginLink'>Login</Link>
            </div>
            </form>
         </div>    
        </div>
         { (onTimer && genOTP!=='') && (
        <div className="otp-verification">
        <div className="otp-verification-container">
           <div className="single-data-close-icon">
            <AiOutlineClose onClick={()=>{setOTP(''); setGenOTP(''); setOnTimer(false); setTimeout(120); setDisplayTimeout('');  delete formErrors["OTP"]; }} />
          </div>
          <div className="title">
            <h3>Email Verification</h3>
          </div>
          <h5>OTP sent to this email,</h5>
          <h5>{formData.email}</h5>
          <div className="input-container">
            <label htmlFor="OTP">Enter OTP :</label>
            <div>
                <input className={formErrors.OTP ? 'inputError' : 'OTP'} id="OTP" name="OTP" type="text"  onChange={handleChangeOTP} value={OTP}
                 onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} />
                {displayTimeout!=='' && <p className='otp-timeout' id="otp-timeout">{displayTimeout}</p>}
            </div>
            {(formErrors.OTP && <p>{formErrors.OTP}</p>)}
          </div>
          <button onClick={()=>{onSubmitValid(setFormErrors)({OTP:OTP}); handleVerify()}} type="submit">Submit</button>
          <div>
           <small>( check spam if you haven't got the OTP )</small>
          </div>
          </div>
          </div>)}
    </div>
    );
}

export default AdminSignup;