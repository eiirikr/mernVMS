import { useEffect, useState } from 'react';
import axios from 'axios';
import "./css/AdminLogin.css";
import { PiEyeLight } from 'react-icons/pi';
import { PiEyeSlashLight } from 'react-icons/pi';
import { useNavigate } from "react-router-dom";

function ChangePassword({AdminEmailID,onChangeAdminEmail}){
    
    const initialFormData = {
        email:'',
        password: '',
        confirmPassword: ''
    };

    const[formData, setFormData]= useState(initialFormData);
    const[formErrors, setFormErrors]= useState({});
    const[passwordShow, setPasswordShow]= useState(false);
    const[confirmPasswordShow, setConfirmPasswordShow]= useState(false);
    const navigate = useNavigate();

    // handle change password details
    const handleChange=(event)=>{

        setFormData({
            ...formData,
            [event.target.name]:event.target.value
        });
    };

    // validate password and confirm password
    const validation=(name, value)=>{
        const errors={}

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
    
    // validate password and confirm password during submit
    const onSubmitValid=(setter)=>(formdata)=>{
      for(const  field in formdata) { 
         setter((formErrors)=>{
            return{
                ...formErrors,
                ...validation(field, formdata[field])
            }
        })
    } }

    // validate password and confirm password during blur
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


    useEffect(()=>{
         
        if(AdminEmailID!==''){
        setFormData((prevFormData)=>({
             ...prevFormData,
             email:AdminEmailID
        }));}

    },[AdminEmailID])

    // post admin new password
    const handleSubmit = async(e) => {

        e.preventDefault();
        
        console.log(formData); 
        console.log(formErrors);

        if(Object.keys(formErrors).length<1){

        await axios.post("http://localhost:4000/api/admin/change/password", formData)
        .then(res=> {
            console.log(res.data);
            // remove the admin token and username that are currently logged in
            window.localStorage.removeItem('jwtToken'); 
            window.localStorage.removeItem('userName');
            alert("Password Updated Successfully!")
            setFormErrors({});
            onChangeAdminEmail('');
            setFormData(initialFormData);
            navigate("/admin/login")
        })
        .catch(err=>console.log(err))
    }
  };

    return(
         <div className="admin-login">
          <div className="admin-container">
            <div className="title">
                <h2>Change Password</h2>
            </div>
            <form onSubmit={handleSubmit}  className="admin-form">
             <div className="admin-details">
                <div className="input-container">
                    <label htmlFor="Password">Password</label>
                    <div>
                    <input className={ formErrors.password ? 'inputError' : 'Password'} id="Password" name="password" type={passwordShow ? 'text' : 'password'} 
                    onChange={handleChange} onBlur={onChangeBlur(setFormErrors)} onFocus={ onChangeFocus(setFormErrors)} value={formData.password} />
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
                <div>
                 <button onClick={()=>{onSubmitValid(setFormErrors)(formData);}} type="submit">Submit</button>
                </div>
            </div>
         </form>
        </div>    
        </div>
    );
}

export default ChangePassword;