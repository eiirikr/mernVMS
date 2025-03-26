import { useState, useEffect, useMemo } from 'react';
import axios from 'axios';
import "./css/MeetingRegistration.css";
import "./css/DisplayTable.css";
import { useNavigate } from "react-router-dom";
import {AiOutlineClose } from 'react-icons/ai';
import {AiOutlineClockCircle } from 'react-icons/ai';
import socketIOClient from 'socket.io-client';
import Datetime from 'react-datetime';
import 'react-datetime/css/react-datetime.css';
import { useFormContext } from './FormContext';
const moment=require('moment')

function PreRegistration({handleChangeDashboardPreregisterData, handleChangeDashboardEmpData}){

    const {preregisterFormData, setPreregisterFormData, initialPreregisterFormData} = useFormContext(); 
    const[formErrors, setFormErrors]= useState({});
    const[isSubmit, setIsSubmit]= useState(false);

    const[available, setAvailable]= useState(true); 
    const[visitor, setVisitor]= useState('');
    const[employee, setEmployee]= useState('');
    const [imageData, setImageData] = useState('');
    const[availFormData, setAvailFormData]= useState({});
    const[availFormID, setAvailFormID]= useState('');

    const token = localStorage.getItem('jwtToken');
    const headers = useMemo(() => ({
      'Authorization': `Bearer ${token}`
    }), [token]);

  // generate form id function
  const GenerateFormID=()=>
  {
    var form_id="F";
    let i=0;
    var chars="0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    while(i<3){
        form_id+= chars.charAt(Math.floor(Math.random() * chars.length));
        i++;
    }
    return form_id;

  }
    
   // handle change preRegister data
    const handleChange=(event)=>{

       setPreregisterFormData({
            ...preregisterFormData,
            [event.target.name]:event.target.value
        });
    };

    // handle change input time
    const handleChangeDatetime=(momentObj,name)=>{
      setPreregisterFormData({
        ...preregisterFormData, 
         [name]: momentObj.format('hh:mm A') }); 

         onChangeDatetimeFocus(setFormErrors)(name)
      }

     // valiadte autofill input
     const autofillInputValidation=(values)=>{
        const errors={};

        if(values.autofillVisitorInput===""){
            errors.autofillVisitorInput="visitor filed is required"
        }

        if(values.autofillEmpInput===''){
            errors.autofillEmpInput="employee field is required"
        }
        
        return errors
     }

    // validate preRegister data
     const validation=(name, value)=>{
        const errors={};

        const email_pattern=/^[^\s@]+@[^\s@]+\.[^\s@]{2,4}$/;
        const mobileNo_pattern=/^[0-9\b]+$/;
        const name_pattern=/^[a-zA-Z\s]+$/;

        if(name==="visitorName"){
          if(value.length<1){
            errors.visitorName="visitor name is required"
          }else if(!name_pattern.test(value)) {
            errors.visitorName = "name only contain letters";
          } 
        }

        if(name==="visitorDesignation"){
          if(value.length<1){
            errors.visitorDesignation="visitor designation is required"
          }else if(!name_pattern.test(value)) {
            errors.visitorDesignation = "name only contain letters";
          } 
        }

        if(name==="visitorMobileNo"){
          if(value.length<1){
            errors.visitorMobileNo="visitor mobile number is required"
          }else if(!mobileNo_pattern.test(value)){
             errors.visitorMobileNo="mobile number must be a numeric value"
          }else if(!(value.length===10)){
             errors.visitorMobileNo="mobile number must have 10 digits"
          } 
        }

        if(name==="visitorAddress"){
          if(value.length<1){
            errors.visitorAddress="visitor address is required"
          }
        }

        if(name==="employeeName"){
          if(value.length<1){
            errors.employeeName="employee name is required"
          }else if(!name_pattern.test(value)) {
            errors.employeeName = "name only contain letters";
          } 
        }

        if(name==="employeeDesignation"){
          if(value.length<1){
            errors.employeeDesignation="employee designation is required"
          }
        }

        if(name==="employeeDepartment"){
          if(value.length<1){
            errors.employeeDepartment="employee department is required"
          }
        }

        if(name==="employeeEmail"){
          if(value.length<1){
            errors.employeeEmail="employee email is required"
           }else if(!email_pattern.test(value)){
            errors.employeeEmail="invalid email"
          }
        }

        if(name==="employeeMobileNo"){
          if(value.length<1){
            errors.employeeMobileNo="employee mobile number is required"
          }else if(!mobileNo_pattern.test(value)){
             errors.employeeMobileNo="mobile number must be numeric"
          }else if(!(value.length===10)){
             errors.employeeMobileNo="mobile number must have 10 digits"
        }}

        if(name==="meetingDate"){
          if(value.length<1){
            errors.meetingDate="meeting date is required"
         }if(new Date(value).setHours(0,0,0,0) < new Date().setHours(0,0,0,0)){
            errors.meetingDate="expired date"
         }
      }

        if(name==="meetingStartTime"){
          if(!value){
            errors.meetingStartTime="meeting start time is required"
        }}

        if(name==="meetingEndTime"){
         if(!value){
            errors.meetingEndTime="meeting end time is required"
          }else if(moment(preregisterFormData.meetingEndTime,'hh:mm A').isBefore(moment(preregisterFormData.meetingStartTime,'hh:mm A'))){
            errors.meetingEndTime="end time lesser than start time"
        }}

        if(name==="meetingPurpose"){
          if(value.length<1){
            errors.meetingPurpose="meeting purpose is required"
        }}
      
        return errors
    }

     // validate preRegister data during submit
     const onSubmitValid=(setter)=>(formdata)=>{
      for(const field in formdata) { 
         setter((formErrors)=>{
            return{
                ...formErrors,
                ...validation(field, formdata[field])
            }
        })
    } }

    // validate preRegister data during blur
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
    
    // validate time input during blur
    const onChangeDatetimeBlur=(setter)=>(name, value)=>{
      setter((formErrors)=>{
        return{
            ...formErrors,
            ...validation(name, value)
        }
      })
    }

    // remove time input during focus
    const onChangeDatetimeFocus=(setter)=>(name)=>{
        setter((formErrors)=>{
        delete formErrors[name]
         return{
             ...formErrors
         }
      })
    }

    // check availability function
    const availabilityCheck=(employeeData)=>{
         let is_leave;
         let is_onsite;
         console.log(preregisterFormData.meetingDate);

         if(employeeData){
         if(employeeData.applied_leave==="yes" && employeeData.leave_status!=="Rejected"){
            
            if((new Date(preregisterFormData.meetingDate).setHours(0, 0, 0, 0) >=new Date(employeeData.leave_start).setHours(0, 0, 0, 0)) &&
               (new Date(preregisterFormData.meetingDate).setHours(0, 0, 0, 0) <=new Date(employeeData.leave_end).setHours(0, 0, 0, 0)) ){
                  is_leave=true;
            }else{
                is_leave=false;
            }
         }
         else{
            is_leave=false;
         }

         if(employeeData.onsite==="yes"){
             if((new Date(preregisterFormData.meetingDate).setHours(0, 0, 0, 0) >= new Date(employeeData.onsite_start).setHours(0, 0, 0, 0)) &&
               (new Date(preregisterFormData.meetingDate).setHours(0, 0, 0, 0)) <= new Date(employeeData.onsite_end).setHours(0, 0, 0, 0)){
                 is_onsite=true;
            }
            else{
                is_onsite=false;
            }
         }
         else{
            is_onsite=false;
         }

         console.log("validate: "+is_leave+" "+is_onsite);
         if(is_leave ||  is_onsite)
         {
            return "no"
         }
         else{
            return "yes"
         }
        }
    }

    const handleSubmit = async(e) => {
        e.preventDefault();
       
        console.log(preregisterFormData);
        console.log(formErrors);

        // check availability
        const avail= availabilityCheck(employee);
        setAvailable(avail)

      // sent mail for meet approval if employee available
      if(((Object.keys(formErrors).length < 1) && isSubmit) && avail==="yes"){
        
        // generate form id
        const Form_ID=GenerateFormID()
        setAvailFormID(Form_ID)

        const socket = socketIOClient.connect('http://localhost:4000');

        // get real time availability data
        socket.on('preRegistrationAvailability', (formData) => {
          console.log("socket: "+formData);
          setAvailFormData(formData);

          return () => {
            socket.disconnect();
          }
        });

        // sent confirmation mail if employee available
        await axios.post("http://localhost:4000/api/send/preregister/meeting/confirmation/mail",{
          employeeEmail:preregisterFormData.employeeEmail, formID:Form_ID, meetingDate:preregisterFormData.meetingDate, 
          meetingStartTime:preregisterFormData.meetingStartTime, meetingEndTime:preregisterFormData.meetingEndTime},{headers:headers})
        .then(res=> {
            console.log(res.data); 
            alert(res.data);
        })
        .catch(err=>console.log(err)) } 
        else if(avail==="no"){
          alert("Employee Not Available in Office !");
        }
      }

      // post preregister data if employee accept meet
      useEffect(() => {
       if(availFormData.formID===availFormID && availFormData.email===preregisterFormData.employeeEmail){ 

        if(availFormData.availability==="yes"){
        axios.post("http://localhost:4000/api/preregister/meeting",preregisterFormData,{headers:headers})
        .then(res=> {
            console.log(res); 
            alert("Meeting Pre-Registered Successfully!");
            setPreregisterFormData(initialPreregisterFormData)
            setFormErrors({})
            setEmployee('') 
            setImageData('')
            setAvailFormData({})
            setIsSubmit(false)
            setAvailable('')  })
        .catch(err=>console.log(err)) 
      } else if(availFormData.availability==="no"){
          alert("Employee Not Approved Meet!");
        }
    }

     },[availFormData, availFormID, headers])

    // autofill visitor and employee data by their id
    const getAutofillData = ()=> {

    console.log("visitor:"+preregisterFormData.autofillVisitorInput);
    console.log("employee:"+preregisterFormData.autofillEmpInput);
    if(preregisterFormData.autofillVisitorInput!=='' && preregisterFormData.autofillEmpInput!==''){
    axios.get(`http://localhost:4000/api/get/autofill/meeting/details/${preregisterFormData.autofillVisitorInput}/${preregisterFormData.autofillEmpInput}`,{headers:headers})
      .then(res=> {
        console.log(res);
        if(res.data.message==='Visitor & Employee not found'){
          alert(res.data.message)
        }else{
          if(res.data.employee_data)
          {
            setEmployee(res.data.employee_data);
            setImageData(res.data.profile_img_data);

            // check availability
            const avail= availabilityCheck(res.data.employee_data);
            setAvailable(avail)
            if(avail==='no')
            {
              alert('Employee Not Available in Office !')
            }

          }else{
            alert('Employee not found')
          }
          
          if(res.data.visitor_data){
            setVisitor(res.data.visitor_data)
          }else{
            alert('Visitor not found')
          }
          
       } })
      .catch(err=>console.log(err))
    }
}

useEffect(() => {
  
  if(visitor && available==="yes"){
      // set preRegister data
      setPreregisterFormData((prevPreregisterFormData) => ({
          ...prevPreregisterFormData, 
          visitorID: visitor.visitor_id,
          visitorName: visitor.name,
          visitorDesignation: visitor.designation,
          visitorMobileNo: visitor.mobile_no,
          visitorAddress: visitor.address,
       }));
      }

      if(employee && available==="yes"){
        setPreregisterFormData((prevPreregisterFormData) => ({
          ...prevPreregisterFormData, 
          employeeID: employee.employee_id,
          employeeName:employee.name,
          employeeDesignation: employee.designation,
          employeeDepartment: employee.department,
          employeeEmail: employee.email,
          employeeMobileNo: employee.mobile_no }));
      }

  },[employee, visitor,  setPreregisterFormData, available])
    
    const navigate = useNavigate();

    return(
         <div>
         <div className="meeting-registration">
          <div className="meeting-registration-container">
            <div className="title">
                <h2>Pre-Registration</h2>
            </div>
            <form onSubmit={handleSubmit}  className="meeting-form" >
             <div className="meeting-details">
                <div className="input-container">
                    <label htmlFor="visitor_id">Visitor ID / MobileNo</label>
                    <input className={formErrors.autofillVisitorInput ? 'inputError' : 'Visitor_ID'} id="visitor_id" name="autofillVisitorInput" type="text" onChange={handleChange} 
                    onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} value={preregisterFormData.autofillVisitorInput} />
                    {(formErrors.autofillVisitorInput && <p>{formErrors.autofillVisitorInput}</p>)}
                </div>
                <div className="input-container wrap3">
                    <label htmlFor="employee_id">Employee ID / MobileNo</label>
                    <input className={formErrors.autofillEmpInput ? 'inputError' : 'Employee_ID'} id="employee_id" name="autofillEmpInput" type="text" onChange={handleChange} 
                    onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} value={preregisterFormData.autofillEmpInput} />
                    {(formErrors.autofillEmpInput && <p>{formErrors.autofillEmpInput}</p>)}
                </div>
                <div className="input-container wrap3">
                   <button onClick={()=>{setFormErrors(autofillInputValidation(preregisterFormData)); setIsSubmit(false); getAutofillData()}} id="autofill-btn" type="submit">Auto fill</button>
                </div>
                <div className="input-container">
                    <label htmlFor="visitor_name">Visitor Name</label>
                    <input className={formErrors.visitorName ? 'inputError' : 'Visitor_Name'} id="visitor_name" name="visitorName" type="text" onChange={handleChange} 
                    onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} value={preregisterFormData.visitorName} />
                    {(formErrors.visitorName && <p>{formErrors.visitorName}</p>)}
                </div>
                <div className="input-container">
                    <label htmlFor="visitor_designation">Visitor Designation</label>
                    <input className={formErrors.visitorDesignation ? 'inputError' : 'Visitor_Designation'} id="visitor_designation" name="visitorDesignation" type="text" onChange={handleChange} 
                    onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} value={preregisterFormData.visitorDesignation} />
                     {(formErrors.visitorDesignation && <p>{formErrors.visitorDesignation}</p>)}
                </div>
                 <div className="input-container">
                    <label  htmlFor="visitor_Mobile_no">Visitor Mobile number</label>
                    <input className={formErrors.visitorMobileNo ? 'inputError' : 'Mobile_Number'} id="visitor_Mobile_no" name="visitorMobileNo" type="text" onChange={handleChange} 
                    onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} value={preregisterFormData.visitorMobileNo} />
                     {(formErrors.visitorMobileNo && <p>{formErrors.visitorMobileNo}</p>)}
                </div>
                 <div className="input-container wrap">
                    <label htmlFor="visitor_address">Visitor Address</label>
                    <textarea  className={formErrors.visitorAddress ? 'inputError' : 'Visitor_Address'} id="visitor_address" name="visitorAddress" type="text" onChange={handleChange} 
                    onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} value={preregisterFormData.visitorAddress} />
                    {(formErrors.visitorAddress && <p>{formErrors.visitorAddress}</p>)}
                 </div>
                <div className="input-container">
                    <label htmlFor="employee_name">Employee Name</label>
                    <input className={formErrors.employeeName ? 'inputError' : 'Employee_Name'} id="employee_name" name="employeeName" type="text" onChange={handleChange} 
                    onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} value={preregisterFormData.employeeName} />
                    {(formErrors.employeeName && <p>{formErrors.employeeName}</p>)}
                </div>
                <div className="input-container">
                    <label htmlFor="employee_designation">Employee Designation</label>
                    <input className={formErrors.employeeDesignation ? 'inputError' : 'Employee_Designation'} id="employee_designation" name="employeeDesignation" type="text" onChange={handleChange} 
                    onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} value={preregisterFormData.employeeDesignation} />
                     {(formErrors.employeeDesignation && <p>{formErrors.employeeDesignation}</p>)}
                </div>
                 <div className="input-container">
                    <label htmlFor="employee_department">Employee Department</label>
                    <input className={formErrors.employeeDepartment ? 'inputError' : 'Employee_Department'} id="employee_department" name="employeeDepartment" type="text" onChange={handleChange} 
                    onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} value={preregisterFormData.employeeDepartment} />
                     {(formErrors.employeeDepartment && <p>{formErrors.employeeDepartment}</p>)}
                </div>
                <div className="input-container">
                    <label  htmlFor="employee_email">Employee Email</label>
                    <input className={formErrors.employeeEmail ? 'inputError' : 'Employee_Email'} id="employee_email" name="employeeEmail" type="email" onChange={handleChange} 
                    onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} value={preregisterFormData.employeeEmail} />
                     {(formErrors.employeeEmail && <p>{formErrors.employeeEmail}</p>)}
                </div>
                <div className="input-container wrap2">
                    <label  htmlFor="employee_Mobile_no">Employee Mobile number</label>
                    <input className={formErrors.employeeMobileNo ? 'inputError' : 'Employee_Mobile_Number'} id="employee_Mobile_no" name="employeeMobileNo" type="text" onChange={handleChange} 
                    onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} value={preregisterFormData.employeeMobileNo} />
                     {(formErrors.employeeMobileNo && <p>{formErrors.employeeMobileNo}</p>)}
                </div>
                 <div className="input-container">
                    <label  htmlFor="meeting_date">Meeting Date</label>
                    <input className={formErrors.meetingDate ? 'inputError' : 'Meeting_Date'} id="meeting_date" name="meetingDate" type="date" onChange={handleChange} 
                    onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} value={preregisterFormData.meetingDate} />
                     {(formErrors.meetingDate && <p>{formErrors.meetingDate}</p>)}
                </div>
                <div className="time-input-container">
                    <label  htmlFor="meeting_start_time">Meeting Start time</label>
                    <div onBlur={()=>onChangeDatetimeBlur(setFormErrors)("meetingStartTime", preregisterFormData.meetingStartTime)} >
                      <Datetime className={formErrors.meetingStartTime ? 'inputError' : 'Meeting_StartTime'} id="meeting_start_time" name="meetingStartTime" timeFormat={true} dateFormat={false}
                      inputProps={{ placeholder: '-- : --' }} onChange={(momentObj) => {handleChangeDatetime(momentObj,"meetingStartTime")}} />
                    </div>
                      <div className='clock-icon'>
                        <AiOutlineClockCircle/>
                      </div>
                     {(formErrors.meetingStartTime && <p>{formErrors.meetingStartTime}</p>)}
                </div>
                 <div className="time-input-container wrap4">
                    <label  htmlFor="meeting_end_time">Meeting End time</label>
                    <div onBlur={()=>{onChangeDatetimeBlur(setFormErrors)("meetingEndTime", preregisterFormData.meetingEndTime)}} >
                      <Datetime className={formErrors.meetingEndTime ? 'inputError' : 'Meeting_EndTime'} id="meeting_end_time" name="meetingEndTime" timeFormat={true} dateFormat={false}
                       inputProps={{ placeholder: '-- : --' }}  onChange={(momentObj) => {handleChangeDatetime(momentObj,"meetingEndTime")}} />
                    </div>
                      <div className='clock-icon'>
                        <AiOutlineClockCircle/>
                      </div>
                     {(formErrors.meetingEndTime && <p>{formErrors.meetingEndTime}</p>)}
                </div>
                <div className="input-container">
                    <label htmlFor="meeting_purpose">Meeting Purpose</label>
                    <textarea  className={formErrors.meetingPurpose ? 'inputError' : 'Meeting_Purpose'} id="meeting_purpose" name="meetingPurpose" type="text" onChange={handleChange} 
                    onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} value={preregisterFormData.meetingPurpose} />
                    {(formErrors.meetingPurpose && <p>{formErrors.meetingPurpose}</p>)}
                </div>
               <div className="input-container">
                 <button onClick={()=>{onSubmitValid(setFormErrors)(preregisterFormData); setIsSubmit(true)}} type="submit">Register</button>
              </div>
            </div>
            </form>
        </div>    
        </div>
        <div className='redirect-table-btns'>
        <div className="view-table-btn">
             <button  onClick={()=> {handleChangeDashboardPreregisterData(''); navigate("/time/preregistration/details")}} type="submit">View<br/>Pre-Registrations Details</button>
        </div>
        <div className="view-table-btn">
             <button  onClick={()=> navigate("/time/visitor/details")} type="submit">View Visitor Details</button>
        </div>
         <div className="view-table-btn">
             <button  onClick={()=> {navigate("/time/employee/details"); handleChangeDashboardEmpData('')}} type="submit">View Employee Availability</button>
        </div>
        </div>
        {((employee && available==="no") && isSubmit) && (
        <div className="display-single-data">
        <div className="single-data-container">
          <div  className="single-data-close-icon">
            <AiOutlineClose onClick={()=>{setIsSubmit(false);}} />
          </div>
          <div>
            <h2>Employee Details</h2>
          </div>
          <div className="profile-pic-container">
              {imageData && <img src={`data:image/jpeg;base64,${imageData}`} alt="Employee Profile" />}
          </div>
          <div className="single-data">
            <h4>Employee ID :</h4>
            <p>{employee.employee_id}</p>
          </div>
          <div className="single-data">
             <h4>Name :</h4>
            <p>{employee.name}</p>
          </div>
          <div className="single-data">
            <h4>Age :</h4>
            <p>{employee.age}</p>
          </div>
          <div className="single-data">
            <h4>Gender :</h4>
            <p>{employee.gender}</p>
          </div>
          <div className="single-data">
            <h4>Designation :</h4>
            <p>{employee.designation}</p>
          </div>
          <div className="single-data">
            <h4>Department :</h4>
            <p>{employee.department}</p>
          </div>
          <div className="single-data">
            <h4>Mobile No :</h4>
            <p>{employee.mobile_no}</p>
          </div>
          <div className="single-data">
            <h4>Email :</h4>
            <p>{employee.email}</p>
          </div>
          <div className="single-data">
            <h4>Address :</h4>
            <p>{employee.address}</p>
          </div>
          <div className="single-data">
            <h4>Applied Leave :</h4>
            <p>{employee.applied_leave}</p>
          </div>
          {employee.applied_leave==="yes" && (
          <div>
          <div className="single-data">
            <h4>Leave Status :</h4>
            <p>{employee.leave_status}</p>
          </div>
          <div className="single-data">
            <h4>Leave Duration :</h4>
            <p>{new Date(employee.leave_start).toLocaleDateString('en-GB')+" to "+new Date(employee.leave_end).toLocaleDateString('en-GB')}</p>
          </div>
          </div>)}
          <div className="single-data">
            <h4>Onsite :</h4>
            <p>{employee.onsite}</p>
          </div>
          {employee.onsite==="yes" && (
          <div className="single-data">
            <h4>Onsite Duration :</h4>
            <p>{new Date(employee.onsite_start).toLocaleDateString('en-GB')+" to "+new Date(employee.onsite_end).toLocaleDateString('en-GB')}</p>
          </div>)}
          {(employee.onsite==="yes" ||employee.applied_leave==="yes") && (
         <div className="single-data">
            <h4>Available from :</h4>
            <p>{(() => {
                var maxDate;

                if(employee.applied_leave==="yes" && employee.onsite==="yes"){
                   var dateDiff=(new Date(employee.leave_end).setHours(0, 0, 0, 0))-(new Date(employee.onsite_start).setHours(0, 0, 0, 0)) 
                   const daysDiff = dateDiff / (1000 * 60 * 60 * 24); 
                   if(Math.abs(daysDiff)>1){
                     if((new Date(employee.onsite_end).setHours(0, 0, 0, 0))<(new Date(employee.leave_end).setHours(0, 0, 0, 0))){
                         maxDate=new Date(employee.onsite_end)
                     } else{
                         maxDate=new Date(employee.leave_end)
                     }
                   }
                   else{
                      if((new Date(employee.onsite_end).setHours(0, 0, 0, 0))>(new Date(employee.leave_end).setHours(0, 0, 0, 0))){
                         maxDate=new Date(employee.onsite_end)
                     } else{
                         maxDate=new Date(employee.leave_end)
                     }
                   }
                
                } else if(employee.applied_leave==="yes" && employee.onsite==="no"){
                    maxDate=new Date(employee.leave_end)
                } else if(employee.onsite==="yes" && employee.applied_leave==="no"){    
                    maxDate=new Date(employee.onsite_end)
                }

                const availableDate = new Date(maxDate);
                availableDate.setDate(availableDate.getDate() + 1);
                return availableDate.toLocaleDateString('en-GB');
          })()}</p>
          </div>)}
        </div>
      </div>)}
       {(availFormData && availFormData.availability==="no") && (
        <div className="display-single-data">
        <div className="single-data-container">
          <div  className="single-data-close-icon">
            <AiOutlineClose onClick={()=>{setIsSubmit(false); setAvailFormData({})}} />
          </div>
          <div>
            <h2>Employee Not Available!</h2>
          </div>
          <div className="single-data">
            <h4>Email : </h4>
            <p>{availFormData.email}</p>
          </div>
          <div className="single-data">
            <h4>Available? : </h4>
            <p>{availFormData.availability}</p>
          </div>
           <div className="single-data">
             <h4>Reason : </h4>
            <p>{availFormData.reason}</p>
          </div>
          <div className="single-data">
            <h4>Available Date : </h4>
            <p>{availFormData.availableDate}</p>
          </div>
          <div className="single-data">
            <h4>Available Time : </h4>
            <p>{availFormData.availStartTime+" - "+availFormData.availEndTime}</p>
          </div>
        </div>
      </div>)}
   
    </div>
    );
}

export default PreRegistration;