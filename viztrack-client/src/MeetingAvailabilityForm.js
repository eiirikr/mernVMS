import { useState } from 'react';
import "./css/ViztrackForm.css";
import socketIOClient from 'socket.io-client';
import Datetime from 'react-datetime';
import 'react-datetime/css/react-datetime.css';

function MeetingAvailabilityForm(){

    const socket = socketIOClient.connect('http://localhost:4000');
  
    const initialFormData = {
        formID:'',
        email: '',
        availability: '',
        reason:'',
        availableDate:'',
        availStartTime:'',
        availEndTime:''
    };

    const[formData, setFormData]= useState(initialFormData);
    const[resSent, setResSent]= useState(false);
    const[formErrors, setFormErrors]= useState({});

    // handle change availability form data
    const handleChange=(event)=>{

        setFormData({
            ...formData,
            [event.target.name]:event.target.value
        });
         console.log(formData);
    };

    // handle change time input
    const handleChangeDatetime=(momentObj,name)=>{
      setFormData({
        ...formData, 
         [name]: momentObj.format('hh:mm A') }); 

         onChangeDatetimeFocus(setFormErrors)(name)
      }
    
    // validate availability form data
    const validation=(name, value)=>{
        const errors={};
        const email_pattern=/^[^\s@]+@[^\s@]+\.[^\s@]{2,4}$/;
        const id_pattern=/^[a-zA-Z0-9\s]+$/;

        if(name==="formID"){
            if(value.length<1){
                errors.formID="form id is required"
            }else if(!id_pattern.test(value)) {
                errors.formID = "id only contain letters & numbers";
            }else if(value.length!==4){
                errors.formID ="id must be 4 characters"
        }}

        if(name==="email"){
            if(value.length<1){
                errors.email="email is required"
            }else if(!email_pattern.test(value)){
                errors.email="invalid email"
        }}

        if(name==="availability"){
           if(value.length<1){
            errors.availability="availability is required"
        }}

        if(formData.availability==="no"){

          if(name==="reason"){
          if(value.length<1){
             errors.reason="reason is required"
          }}

         if(name==="availableDate"){
          if(!value){
             errors.availableDate="available date is required"
          }}

         if(name==="availStartTime"){
          if(!value){
             errors.availStartTime="start time is required"
          }}

         if(name==="availEndTime"){
          if(!value){
             errors.availEndTime="end time is required"
          }}
        }

        return errors
    }

    // validate availability form data during submit
    const onSubmitValid=(setter)=>(formdata)=>{
      for(const field in formdata) { 
         setter((formErrors)=>{
            return{
                ...formErrors,
                ...validation(field, formdata[field])
            }
        })
    } }

    // validate availability form data during blur
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

    // remove time input error during focus
    const onChangeDatetimeFocus=(setter)=>(name)=>{
        setter((formErrors)=>{
        delete formErrors[name]
         return{
             ...formErrors
         }
      })
    }
    
    // emit availability form data
    const handleSubmit = async(e) => {

        e.preventDefault();
        console.log(formData); 
        console.log(formErrors);
        
        if(Object.keys(formErrors).length < 1){  
            socket.emit('availabilityFormData', formData);
            alert("your respose sent successfully")
            setResSent(true)
        }  
  };

    return(
         <div className="ViztrackForm">
          { !resSent ?
          (<div className="viztrackForm-container">
            <div className="title">
                <h2>Availability Form</h2>
            </div>
            <form onSubmit={handleSubmit}  className="viztrackForm">
             <div className="viztrackForm-details">
                <div className="input-container">
                    <label  htmlFor="FormID">Form ID</label>
                    <input className={formErrors.formID ? 'inputError' : 'FormID'} id="FormID" name="formID" type="text" onChange={handleChange} 
                    onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} value={formData.formID} />
                    {(formErrors.formID && <p>{formErrors.formID}</p>)}
                </div>
                <div className="input-container">
                    <label  htmlFor="Email">Email</label>
                    <input className={formErrors.email ? 'inputError' : 'Email'} id="Email" name="email" type="email" onChange={handleChange} 
                    onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} value={formData.email} />
                    {(formErrors.email && <p>{formErrors.email}</p>)}
                </div>
                <div className='single-employee-data'>
                <div className="radio-btn-container">
                  <div className='radio-btn'>
                    <label htmlFor='availability-yes'>Are you available now ?</label>
                        <input id="availability-yes" name="availability" type="radio" value="yes" onChange={handleChange} checked={formData.availability === "yes"} 
                        onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} />
                        <label htmlFor="availability-yes">Yes</label>
                   
                        <input id="availability-no" name="availability" type="radio" onChange={handleChange} value="no" checked={formData.availability === "no"} 
                        onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} />
                        <label htmlFor="availability-no">No</label>
                        {(formErrors.availability && <p>{formErrors.availability}</p>)}
                    </div>
                   </div>
                 </div>
                </div>
                {formData.availability === "no" &&
                <div className="viztrackForm-details">
                <div className="input-container">
                    <label htmlFor="Reason">Reason</label>
                    <input  className={formErrors.reason ? 'inputError' : 'Reason'} id="Reason" name="reason" type="text" onChange={handleChange} 
                    onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} value={formData.reason} />
                     {(formErrors.reason && <p>{formErrors.reason}</p>)}
                </div>
                <div className="input-container">
                 <div className='date-containter'>
                    <label htmlFor="Available_Date">Available Date</label>
                    <input  className={formErrors.availableDate ? 'inputError' : 'Available_Date'} id="Available_Date" name="availableDate" type="date" onChange={handleChange} 
                    onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} value={formData.availableDate} />
                     {(formErrors.availableDate && <p>{formErrors.availableDate}</p>)}
                 </div>
                </div>
                <div className='time-input-container'>
                    <label htmlFor="AvailableStart_Time">Available Time</label>
                    <div className='time-inner-container'>
                    <div className='time-input' >
                        <div onBlur={()=>{onChangeDatetimeBlur(setFormErrors)("availStartTime",formData.availStartTime)}} >
                            <Datetime  className={formErrors.availStartTime ? 'inputError' : 'AvailableStart_Time'} id="AvailStart_Time"  timeFormat={true} dateFormat={false}
                            inputProps={{ placeholder: '-- : --' }} onChange={(momentObj) => {handleChangeDatetime(momentObj,"availStartTime")}} />
                        </div>
                        <div>
                            {(formErrors.availStartTime && <p>{formErrors.availStartTime}</p>)}
                        </div>
                     </div>
                    <div className='time-input'>
                        <p id='to'>to</p>
                    </div>
                    <div className='time-input'>
                        <div onBlur={()=>{onChangeDatetimeBlur(setFormErrors)("availEndTime",formData.availEndTime)}} >
                            <Datetime  className={formErrors.availEndTime ? 'inputError' : 'AvailableEnd_Time'} id="AvailableEnd_Time" name="availEndTime"  timeFormat={true} dateFormat={false} 
                            inputProps={{ placeholder: '-- : --' }} onChange={(momentObj) => {handleChangeDatetime(momentObj,"availEndTime")}}/>
                        </div>
                        <div>
                            {(formErrors.availEndTime && <p>{formErrors.availEndTime}</p>)}
                        </div>
                     </div>
                  </div>
                 </div> 
                </div>}
                <div className='viztrackForm-details'>
                  <button onClick={()=>onSubmitValid(setFormErrors)(formData)} type="submit">Submit</button>
                </div>
            </form>
        </div>):(<h1 style={{ color: '#4A4A4A' }}>Thanks for your response</h1>) }    
        </div>
    );
}

export default MeetingAvailabilityForm;