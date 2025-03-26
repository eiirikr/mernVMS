import { useState, useRef } from 'react';
import axios from 'axios';
import "./css/EmployeeRegistration.css";
import blankProfile from "../src/blank-profile-picture.jpg"
import { useNavigate } from "react-router-dom";
import { IoCameraOutline } from 'react-icons/io5';
import FadeLoader from "react-spinners/FadeLoader";
import { useFormContext } from './FormContext';

function EmployeeRegistration({handleChangeDashboardEmpData}){

    const { empFormData, setEmpFormData, initialEmpFormData,
            profileImgUrl, setProfileImgUrl, profileImg, setProfileImg } = useFormContext(); 

    const[formErrors, setFormErrors]= useState({});
    const[loading, setLoading]= useState(false);
    const profile=useRef(null)

    const token = localStorage.getItem('jwtToken');
    const headers = { 'Authorization': `Bearer ${token}` };

    // handle change employee data
    const handleChange=(event)=>{

       setEmpFormData({
            ...empFormData,
            [event.target.name]:event.target.value
        });
    };

     // validate employee data
     const validation=(name, value)=>{
        const errors={};

        const email_pattern=/^[^\s@]+@[^\s@]+\.[^\s@]{2,4}$/;
        const mobileNo_pattern=/^[0-9\b]+$/;
        const name_pattern=/^[a-zA-Z\s]+$/;

       
        if(name==="profile"){
          if(!profile.current.files[0]){
            errors.profile="profile is required"
          }else if((profile.current.files[0]).size > 150 * 1024) {   
            errors.profile = "file size exceeds 150KB";
          }else{
            onChangeProfileFocus(setFormErrors)("profile")
          }
        }

        if(name==="name"){
            if(value.length<1){
                 errors.name="full name is required"
            }else if(!name_pattern.test(value)) {
                 errors.name = "name only contain letters";
        } }

        if(name==="gender"){
            if(value.length<1){
             errors.gender="gender is required"
        } }


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
            }
        }

        if(name==="department"){
            if(value.length<1){
                errors.department="department is required"
            }
         }

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
                errors.mobileNo="mobile number must be a numeric value"
            }else if(value.length!==11){
                errors.mobileNo="mobile number must have 11 digits"
        } }
        
        if(name==="address"){
            if(value.length<1){
                errors.address="address is required"
        } }

        if(name==="appliedLeave"){
            if(value.length<1){
                 errors.appliedLeave="applied leave is required"
        } }

        
        if(empFormData.appliedLeave==="yes"){

            if(name==="leaveStatus"){
                if(value==="Choose Status"){
                     errors.leaveStatus="leave status is required"
            } }
        
            if(name==="leaveStart"){
             if(!value){
                errors.leaveStart="leave start date is required"
            } }
        
            if(name==="leaveEnd"){
                if(!value){
                    errors.leaveEnd="leave end date is required"
                }else if(empFormData.leaveStart && (new Date(empFormData.leaveStart).setHours(0,0,0,0) > new Date(empFormData.leaveEnd).setHours(0,0,0,0))){
                    errors.leaveEnd="end date lesser than start date"
                }
          }
       }


        if(name==="onsite"){
        if(value.length<1){
            errors.onsite="onsite data is required"
        }}
        

        if(empFormData.onsite==="yes"){
        
        if(name==="onsiteStart"){
            if(!value){
                errors.onsiteStart="onsite start date is required"
        }}
        
        if(name==="onsiteEnd"){
            if(!value){
             errors.onsiteEnd="onsite end date is required"
            }else if(empFormData.onsiteStart && (new Date(empFormData.onsiteStart).setHours(0,0,0,0) > new Date(empFormData.onsiteEnd).setHours(0,0,0,0))){
              errors.onsiteEnd="end date lesser than start date"
            }
        }
        
        }

        return errors
    }

    // validate employee data during submit
    const onSubmitValid=(setter)=>(formdata)=>{
      for(const field in formdata) { 
         setter((formErrors)=>{
            return{
                ...formErrors,
                ...validation(field, formdata[field])
            }
        })
    } }

    // validate employee data during blur
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

    // validate employee profile image during blur
    const onChangeProfileBlur=(setter)=>(name, value)=>{
      setter((formErrors)=>{
        return{
            ...formErrors,
            ...validation(name, value)
        }
      })
    }

    // remove employee profile image  error during focus
    const onChangeProfileFocus=(setter)=>(name)=>{
        setter((formErrors)=>{
        delete formErrors[name]
         return{
             ...formErrors
         }
      })
    }

    // handle change employee profile image
    const handleImageChange = () => {

        onChangeProfileBlur(setFormErrors)("profile","pic")
        
        const file=profile.current.files[0]
        console.log(file);

        if(file){
         setProfileImg(profile.current.files[0]);
         setProfileImgUrl(URL.createObjectURL(file));
        }


    };

    let formData='';
    // post employee data
    const handleSubmit = async(e) => {
        e.preventDefault();
        
        onChangeProfileBlur(setFormErrors)("profile","pic")
        console.log(formErrors);

        if(Object.keys(formErrors).length<1){

        setLoading(true)

        // create form data
        formData =new FormData()

        // append profile image data to formdata
        formData.append('profileImg', profileImg)

        // append all data in empFormData to formdata
        Object.keys(empFormData).forEach((key) => {
            formData.append(key, empFormData[key]);
        });
        
        console.log(Object.fromEntries(formData));

        await axios.post("http://localhost:4000/api/register/employee",formData, {headers:headers})
        .then(res=> {
            
             setLoading(false)

             if(res.data==="Account Already Exist with this Email" || res.data==="Account Already Exist with this Mobile number"){
                alert(res.data);
                setFormErrors({});
            }
            else{
            console.log(res); 
            alert("Employee Details Registered Successfully!");
            setEmpFormData(initialEmpFormData);
            setProfileImg('');
            setProfileImgUrl(blankProfile);
            setFormErrors({}) } })
        .catch(err=>console.log(err)) 
     }}

    
    const navigate = useNavigate();

    return(
         <div>
         <div className="employee-details-registration">
          <div className="employee-container">
            <div className="title">
                <h2>Employee Registration</h2>
            </div>
            <form onSubmit={handleSubmit}  className="employee-form">
             <div className="employee-details">
                <div className="input-container">
                    <div className='profile-label'>
                        <label>Profile</label>
                    </div>
                    <div className='profile-pic-container'>
                        <img src={profileImgUrl} alt="Blank Profile" id="profile-img"/>
                        <input id="Profile" type="file"  accept="image/*"  onChange={handleImageChange}  ref={profile} 
                        onClick={()=>{onChangeProfileBlur(setFormErrors)("profile","pic")}} />
                        <label htmlFor="Profile" id="pic-upload-btn"><IoCameraOutline size={20}/></label>
                    </div>
                     {(formErrors.profile && <p>{formErrors.profile}</p>)}
                </div>
                <div className="input-container">
                    <label htmlFor="Name">Full Name</label>
                    <input className={formErrors.name ? 'inputError' : 'Name'} id="Name" name="name" type="text" onChange={handleChange} 
                     onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} value={empFormData.name} />
                    {(formErrors.name && <p>{formErrors.name}</p>)}
                </div>
                <div className="input-container">
                    <label htmlFor="Age">Age</label>
                    <input className={formErrors.age ? 'inputError' : 'Age'} id="Age" name="age" type="number" onChange={handleChange} 
                    onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} value={empFormData.age} />
                    {(formErrors.age && <p>{formErrors.age}</p>)}
                </div>
                <div className="radio-btn-container wrap2">
                    <div className='radio-btn'>
                        <label htmlFor='Male'>Gender</label>
                        <div className='radio-options'>
                        <div>
                        <input id="Male" name="gender" type="radio" value="male" onChange={handleChange}  
                        onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} checked={empFormData.gender === "male"} />
                        <label htmlFor="Male">Male</label>
                       </div>
                       <div>
                        <input id="Female" name="gender" type="radio" onChange={handleChange} 
                         onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} value="female" checked={empFormData.gender === "female"} />
                        <label htmlFor="Female">Female</label>
                       </div>
                       <div>
                        <input id="Other" name="gender" type="radio" onChange={handleChange} 
                         onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} value="other" checked={empFormData.gender === "other"} />
                        <label htmlFor="Other">Other</label>

                        {(formErrors.gender && <p>{formErrors.gender}</p>)}
                      </div>
                      </div>
                    </div>
                </div>
                <div className="input-container">
                    <label htmlFor="Designation">Designation</label>
                    <input className={formErrors.designation ? 'inputError' : 'Designation'} id="Designation" name="designation" type="text" onChange={handleChange} 
                    onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} value={empFormData.designation} />
                     {(formErrors.designation && <p>{formErrors.designation}</p>)}
                </div>
                <div className="input-container">
                    <label htmlFor="Department">Department</label>
                    <input className={formErrors.department ? 'inputError' : 'Department'} id="Department" name="department" type="text" onChange={handleChange} 
                    onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} value={empFormData.department} />
                     {(formErrors.department && <p>{formErrors.department}</p>)}
                </div>
                <div className="input-container">
                    <label  htmlFor="Mobile_no">Mobile no</label>
                    <input className={formErrors.mobileNo ? 'inputError' : 'Mobile_Number'} id="Mobile_no" name="mobileNo" type="text" onChange={handleChange} 
                    onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} value={empFormData.mobileNo} />
                     {(formErrors.mobileNo && <p>{formErrors.mobileNo}</p>)}
                </div>
                 <div className="input-container">
                    <label  htmlFor="Email">Email</label>
                    <input className={formErrors.email ? 'inputError' : 'Email'} id="Email" name="email" type="email" onChange={handleChange} 
                    onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} value={empFormData.email} />
                     {(formErrors.email && <p>{formErrors.email}</p>)}
                </div>
                <div className="input-container">
                    <div>
                        <label htmlFor="Address">Address</label>
                        <textarea  className={formErrors.address ? 'inputError' : 'Address'} id="Address" name="address" type="text" onChange={handleChange} 
                        onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} value={empFormData.address} />
                        {(formErrors.address && <p>{formErrors.address}</p>)}
                    </div>
                </div>
                 <div className="radio-btn-container wrap">
                 <div className='radio-btn'>
                    <label htmlFor='Leave-Yes'>Applied Leave</label>
                    
                    <input id="Leave-Yes" name="appliedLeave" type="radio" value="yes" onChange={handleChange} 
                    onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} checked={empFormData.appliedLeave === "yes"} />
                    <label htmlFor="Leave-Yes">Yes</label>
                    
                    <input id="Leave-No" name="appliedLeave" type="radio" onChange={handleChange} value="no" 
                    onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} checked={empFormData.appliedLeave === "no"} />
                    <label htmlFor="Leave-No">No</label>
                    {(formErrors.appliedLeave && <p>{formErrors.appliedLeave}</p>)}
                </div>
                </div>
                {empFormData.appliedLeave === "yes" && 
                  (<div className="leave-info">
                  <div className="input-container">
                    <label htmlFor="leaveStatus">Leave Status</label>
                    <select className={formErrors.leaveStatus ? 'inputError' : 'leave_Status'} id="leaveStatus" name="leaveStatus" onChange={handleChange} 
                     onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)}  value={empFormData.leaveStatus}>
                        <option disabled hidden>Choose Status</option>
                        <option value="Waiting for Approval">Waiting for Approval</option>
                        <option value="Approved">Approved</option>
                        <option value="Rejected">Rejected</option>
                    </select>
                    {(formErrors.leaveStatus && <p>{formErrors.leaveStatus}</p>)}
                </div>
                <div className="input-container">
                    <label htmlFor="Leave-Start">Leave Start Date</label>
                    <input className={formErrors.leaveStart ? 'inputError' : 'leave_Start'} id="Onsite-Start" name="leaveStart" type="date" onChange={handleChange} 
                    onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} value={empFormData.leaveStart} />
                    {(formErrors.leaveStart && <p>{formErrors.leaveStart}</p>)}
                </div>
                <div className="input-container">
                    <label htmlFor="Leave-End">Leave End Date</label>
                    <input className={formErrors.leaveEnd ? 'inputError' : 'leave_End'} id="Leave-End" name="leaveEnd" type="date" onChange={handleChange} 
                     onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} value={empFormData.leaveEnd} />
                    {(formErrors.leaveEnd && <p>{formErrors.leaveEnd}</p>)}
                </div>
                </div>)}
                <div className='Onsite-Project wrap'>
                <div className="radio-btn-container">
                  <div className='radio-btn'>
                    <label htmlFor='Onsite-Yes'>Allocated to Onsite Project</label>
                        <input id="Onsite-Yes" name="onsite" type="radio" value="yes" onChange={handleChange} 
                        onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} checked={empFormData.onsite === "yes"} />
                        <label htmlFor="Onsite-Yes">Yes</label>
                   
                        <input id="Onsite-No" name="onsite" type="radio" onChange={handleChange} value="no" 
                        onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} checked={empFormData.onsite === "no"} />
                        <label htmlFor="Onsite-No">No</label>
                        {(formErrors.onsite && <p>{formErrors.onsite}</p>)}
                </div>
                </div>
                </div>
                {empFormData.onsite === "yes" &&
                (<div className='onsite-duration'>
                <div className="input-container">
                    <label htmlFor="Onsite-Start">Onsite Start Date</label>
                    <input  className={formErrors.onsiteStart ? 'inputError' : 'Onsite_Start'} id="Onsite-Start" name="onsiteStart" type="date" onChange={handleChange} 
                    onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} value={empFormData.onsiteStart} />
                     {(formErrors.onsiteStart && <p>{formErrors.onsiteStart}</p>)}
                </div>
                <div className="input-container">
                    <label htmlFor="Onsite-End">Onsite End Date</label>
                    <input  className={formErrors.onsiteEnd ? 'inputError' : 'Onsite_End'} id="Onsite-End" name="onsiteEnd" type="date" onChange={handleChange} 
                    onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} value={empFormData.onsiteEnd} />
                     {(formErrors.onsiteEnd && <p>{formErrors.onsiteEnd}</p>)}
                </div>
                </div>)}
               <div>
                <button onClick={()=>onSubmitValid(setFormErrors)(empFormData)} type="submit">Register</button>
                </div>
            </div>
            </form>
            <div className='Loader'>
             <FadeLoader color={'#5d8ee7'} loading={loading} size={50} />
            </div>
        </div>    
        </div>
        <div className="view-employees-table-btn">
             <button  onClick={()=>{navigate("/time/employee/details"); handleChangeDashboardEmpData('')}} type="submit">View Employees Details</button>
        </div>
    </div>
    );
}

export default EmployeeRegistration;