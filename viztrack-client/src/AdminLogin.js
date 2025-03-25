import { useState } from 'react';
import axios from 'axios';
import "./css/AdminLogin.css";
import { PiEyeLight } from 'react-icons/pi';
import { PiEyeSlashLight } from 'react-icons/pi';
import { Link } from 'react-router-dom';

function AdminLogin({onChangeAdminEmail}){
    
    const initialFormData = {
        email: '',
        password: '',
    };

    const[formData, setFormData]= useState(initialFormData);
    const[formErrors, setFormErrors]= useState({});
    const[passwordShow, setPasswordShow]= useState(false);

    // handle change admin login details
    const handleChange=(event)=>{

        setFormData({
            ...formData,
            [event.target.name]:event.target.value
        });
    };

    // validate admin login details
    const validation=(name, value)=>{
        const errors={}

        const email_pattern=/^[^\s@]+@[^\s@]+\.[^\s@]{2,4}$/;
        
        if(name==="email"){
            if(value.length<1){
             errors.email="email is required"
            }else if(!email_pattern.test(value)){
               errors.email="invalid email"
            } 
        }

        if(name==="password"){
            if(value.length<1){
                errors.password="password is required"
            }
        }
         return errors
    }

    // validate admin login details during submit
    const onSubmitValid=(setter)=>(formdata)=>{
      for(const  field in formdata) { 
         setter((formErrors)=>{
            return{
                ...formErrors,
                ...validation(field, formdata[field])
            }
        })
    } }

    // validate admin login details during blur
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

    // post admin login details
    const handleSubmit = async(e) => {

        e.preventDefault();

        console.log(formData); 
        console.log(formErrors);

        if(Object.keys(formErrors).length<1){

        await axios.post("http://localhost:4000/api/admin/login", formData)
        .then(res=> {

            if(res.data==="Invalid Admin" || res.data==="Invalid Password"){
                alert(res.data)
                setFormErrors({});
            }
            else{
            console.log(res.data);

            // set token and user name while successful login
            window.localStorage.setItem('jwtToken', res.data.token);
            window.localStorage.setItem('userName', res.data.user_name);
            alert("Login Successfull!");
            setFormData(initialFormData);
            setFormErrors({});
            window.location.href = '/viztrack/dashboard' }
        })
        .catch(err=>console.log(err))
    }
  };

    return(
         <div className="admin-login">
          <div className="admin-container">
            <div className="title">
                <h2>Admin Login</h2>
            </div>
            <form onSubmit={handleSubmit}  className="admin-form">
             <div className="admin-details">
                <div className="input-container">
                    <label  htmlFor="Email">Email</label>
                    <input className={ formErrors.email ? 'inputError' : 'Email'} id="Email" name="email" type="email" onChange={handleChange} 
                     onBlur={onChangeBlur(setFormErrors)} onFocus={ onChangeFocus(setFormErrors)} value={formData.email} />
                    {(formErrors.email && <p>{formErrors.email}</p>)}
                </div>
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
                <div>
                 <button onClick={()=> onSubmitValid(setFormErrors)(formData)} type="submit">Submit</button>
                </div>
            </div>
            <div className="Links">
                <p id="NewUser">New user?</p>
                <Link to="/admin/signup" className="SignupLink">Signup</Link>
                <Link to="/admin/forgot/password" onClick={()=>onChangeAdminEmail(formData.email)} className="ForgotPassword">Forgot Password</Link>
            </div>
         </form>
        </div>    
        </div>
    );
}

export default AdminLogin;