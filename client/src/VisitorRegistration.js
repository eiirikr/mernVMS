import { useState } from 'react';
import axios from 'axios';
import "./css/VisitorRegistration.css";
import { useNavigate } from "react-router-dom";
import { useFormContext } from './FormContext';

function VisitorRegistration(){

    const { visitorFormData, setVisitorFormData, initialVisitorFormData } = useFormContext(); 
    const[formErrors, setFormErrors]= useState({});

    // handle change visitor data
    const handleChange=(event)=>{

       setVisitorFormData({
            ...visitorFormData,
            [event.target.name]:event.target.value
        });
    };

    // validate visitor data
    const validation=(name, value)=>{
        const errors={};

        const email_pattern=/^[^\s@]+@[^\s@]+\.[^\s@]{2,4}$/;
        const mobileNo_pattern=/^[0-9\b]+$/;
        const name_pattern=/^[a-zA-Z\s]+$/;

        if(name==="firstName"){
            if(value.length<1){
                errors.firstName="first name is required"
            }else if(!name_pattern.test(value)) {
                errors.firstName = "first name only contain letters";
        }}
        
        if(name==="lastName"){
            if(value.length<1){
                errors.lastName="last name is required"
            }else if(!name_pattern.test(value)) {
                errors.lastName = "last name only contain letters";
        }}


         if(name==="gender"){
         if(value.length<1){
            errors.gender="gender is required"
        }}

        if(name==="age"){
            if(value.length<1){
                errors.age="age is required"
            }else if(!((value > 0) && (value <= 100))){
                errors.age="age is between 1 to 100"
            }
        }
        
        if(name==="designation"){
            if(value.length<1){
                errors.designation="designation is required"
            }else if(!name_pattern.test(value)) {
                errors.designation = "designation only contain letters";
        }}

        if(name==="email"){
         if(value.length>1){
            if(!email_pattern.test(value)){
                errors.email="invalid email"
            }
        }}

        if(name==="mobileNo"){
            if(value.length<1){
                errors.mobileNo="mobile number is required"
            }else if(!mobileNo_pattern.test(value)){
                errors.mobileNo="mobile number must be a numeric value"
            }else if(value.length!==10){
                errors.mobileNo="mobile number have 10 digits"
        }}
        
        if(name==="address"){
            if(value.length<1){
                errors.address="address is required"
        }}

        return errors
    }

    // validate visitor data during submit
    const onSubmitValid=(setter)=>(formdata)=>{
      for(const field in formdata) { 
         setter((formErrors)=>{
            return{
                ...formErrors,
                ...validation(field, formdata[field])
            }
        })
    } }

    // validate visitor data during blur
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
    
    const token = localStorage.getItem('jwtToken');
    const headers = {
        'Authorization': `Bearer ${token}`
    };

    // post visitor data
    const handleSubmit = async(e) => {
        
        e.preventDefault();
        console.log(visitorFormData); 
        console.log(formErrors); 

        if(Object.keys(formErrors).length<1){
        
        await axios.post("http://localhost:4000/api/register/visitor", visitorFormData, {headers:headers})
        .then(res=> {

            if(res.data==="Account Already Exist with this Email" || res.data==="Account Already Exist with this Mobile number"){
                alert(res.data);
                setFormErrors({});
            }else{
            console.log(res); 
            alert("Visitor Details Registered Successfully!");
            setVisitorFormData(initialVisitorFormData)
            setFormErrors({})} }) 
        .catch(err=>console.log(err)) } 
  };

    const navigate = useNavigate();

    return(
         <div>
         <div className="visitor-details-registration">
          <div className="visitor-container">
            <div className="title">
                <h2>Visitor Registration</h2>
            </div>
            <form onSubmit={handleSubmit} action="POST" className="visitor-form">
             <div className="visitor-details">
                <div className="input-container">
                    <label htmlFor="First_name">First name</label>
                    <input className={formErrors.firstName ? 'inputError' : 'Full_Name'} id="First_name" name="firstName" type="text" onChange={handleChange} 
                    onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} value={visitorFormData.firstName} />
                     {(formErrors.firstName && <p>{formErrors.firstName}</p>)}
                </div>
                <div className="input-container">
                    <label htmlFor="Last_name">Last name</label>
                    <input className={formErrors.lastName ? 'inputError' : 'Full_Name'} id="Last_name" name="lastName" type="text" onChange={handleChange} 
                    onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} value={visitorFormData.lastName} />
                     {(formErrors.lastName && <p>{formErrors.lastName}</p>)}
                </div>
                <div className="input-container">
                    <label htmlFor="Age">Age</label>
                    <input className={formErrors.age ? 'inputError' : 'Email'} id="Age" name="age" type="number" onChange={handleChange} 
                    onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} value={visitorFormData.age} />
                     {(formErrors.age && <p>{formErrors.age}</p>)}
                </div>
                 <div className="input-container">
                    <label  htmlFor="Email">Email <small>(optional)</small></label>
                    <input className={formErrors.email ? 'inputError' : 'Email'} id="Email" name="email" type="email" onChange={handleChange} 
                    onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} value={visitorFormData.email} />
                     {(formErrors.email && <p>{formErrors.email}</p>)}
                </div>
                <div className="input-container">
                    <label  htmlFor="Mobile_no">Mobile number</label>
                    <input  className={formErrors.mobileNo ? 'inputError' : 'Mobile_Number'} id="Mobile_no" name="mobileNo" type="text" onChange={handleChange} 
                    onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} value={visitorFormData.mobileNo} />
                     {(formErrors.mobileNo && <p>{formErrors.mobileNo}</p>)}
                </div>
                <div className="input-container">
                    <label htmlFor="Designation">Designation</label>
                    <input  className={formErrors.designation ? 'inputError' : 'Designation'} id="Designation" name="designation" type="text" onChange={handleChange} 
                    onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} value={visitorFormData.designation} />
                    {(formErrors.designation && <p>{formErrors.designation}</p>)}
                </div>
                <div className="radio-btn-container">
                    <div className='radio-btn'>

                        <label htmlFor='Male'>Gender</label>
                        
                        <input id="Male" name="gender" type="radio" value="male" onChange={handleChange} checked={visitorFormData.gender === "male"} 
                        onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} />
                        <label htmlFor="Male">Male</label>
                       
                        <input id="Female" name="gender" type="radio" onChange={handleChange} value="female" checked={visitorFormData.gender === "female"} 
                        onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} />
                        <label htmlFor="Female">Female</label>
        
                        <input id="Other" name="gender" type="radio" onChange={handleChange} value="other" checked={visitorFormData.gender === "other"} 
                        onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} />
                        <label htmlFor="Other">Other</label>
                        {(formErrors.gender && <p>{formErrors.gender}</p>)}
                    </div>
                </div>
                <div className="input-container">
                    <div>
                        <label htmlFor="Address">Address</label>
                        <textarea  className={formErrors.address ? 'inputError' : 'Address'} id="Address" name="address" type="text" onChange={handleChange} 
                        onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} value={visitorFormData.address} />
                         {(formErrors.address && <p>{formErrors.address}</p>)}
                    </div>
                </div>
                <button onClick={()=>onSubmitValid(setFormErrors)(visitorFormData)} type="submit">Register</button>
            </div>
            </form>
        </div>    
        </div>
        <div className="view-visitors-table-btn">
             <button  onClick={()=> navigate("/time/visitor/details")} type="submit">View Visitors Details</button>
        </div>
    </div>
    );
}

export default VisitorRegistration;