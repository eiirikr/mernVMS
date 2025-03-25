import { useState } from 'react';
import axios from 'axios';
import "./css/ViztrackForm.css";
import Datetime from 'react-datetime';
import 'react-datetime/css/react-datetime.css';

function EmergencyReport(){

    const initialFormData = {
        reportPersonID: '',
        meetingID:'',
        reportedFor:'',
        issue:'',
        updateDate:'',
        updateStartTime:'',
        updateEndTime:''
    };

    const[formData, setFormData]= useState(initialFormData);
    const[resSent, setResSent]= useState(false);
    const[formErrors, setFormErrors]= useState({});

    // handle change emergency report data
    const handleChange=(event)=>{

        setFormData({
            ...formData,
            [event.target.name]:event.target.value
        });
         console.log(formData);
    };

    // handle change input time
    const handleChangeDatetime=(momentObj,name)=>{
      setFormData({
        ...formData, 
         [name]: momentObj.format('hh:mm A') }); 

         onChangeDatetimeFocus(setFormErrors)(name)
      }
    
    // validate emergency report data
    const validation=(name, value)=>{
        
       const errors={};
       const id_pattern=/^[a-zA-Z0-9\s]+$/;

       if(name==="reportPersonID"){
        if(value.length<1){
            errors.reportPersonID="report person id is required"
        }else if(!id_pattern.test(value)) {
            errors.reportPersonID = "id only contain letters & numbers";
        }else if(value.length!==6){
           errors.reportPersonID="id must be 6 characters"
        }
      }

    if(name==="meetingID"){
       if(value.length<1){
            errors.meetingID="meeting id is required"
        }else if(!id_pattern.test(value)) {
            errors.meetingID = "id only contain letters & numbers";
        }else if(value.length!==8){
           errors.meetingID="meeting id must be 8 characters"
        }
    }

        if(name==="reportedFor"){
            if(value.length<1){
                errors.reportedFor="report need is required"
            }
        }

        if(name==="issue"){
            if(value.length<1){
                errors.issue="reason is required"
        }}

        if(formData.reportedFor==="update meet"){

        if(name==="updateDate"){
          if(!value){
             errors.updateDate="update date is required"
        }}

          if(name==="updateStartTime"){
            if(!value){
                errors.updateStartTime="start time is required"
        }}

          if(name==="updateEndTime"){
            if(!value){
                errors.updateEndTime="end time is required"
          }}
        }

        return errors
    }

    // validate emergency report data during submit
    const onSubmitValid=(setter)=>(formdata)=>{
      for(const field in formdata) { 
         setter((formErrors)=>{
            return{
                ...formErrors,
                ...validation(field, formdata[field])
            }
        })
    } }

    // validate emergency report data during blur
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

    // post emergency report data
    const handleSubmit = async(e) => {

        e.preventDefault();
        console.log(formData); 
        console.log(formErrors);
        
        if(Object.keys(formErrors).length < 1){  
           
        await axios.post("http://localhost:4000/api/register/emergency/report", formData)
        .then(res=> {

            if(res.data==="Your ID is wrong" || res.data==="Meeting ID not found"){
                alert(res.data);
                setFormErrors({});
            }else{
            console.log(res.data); 
            alert("your respose sent successfully")
            setResSent(true)
            setFormData(initialFormData)
            setFormErrors({})} }) 
        .catch(err=>console.log(err))
        }
        
  };

    return(
         <div className="ViztrackForm">
          { resSent ?
          (<div className="viztrackForm-container">
            <div className="title">
                <h2>Emergency Report</h2>
            </div>
            <form onSubmit={handleSubmit}  className="viztrackForm">
             <div className="viztrackForm-details">
                <div className="input-container">
                    <label  htmlFor="ReportPersonID">Your ID</label>
                    <input className={formErrors.reportPersonID ? 'inputError' : 'ReportPersonID'} id="ReportPersonID" name="reportPersonID" type="text" onChange={handleChange} 
                     onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} value={formData.reportPersonID} />
                    {(formErrors.reportPersonID && <p>{formErrors.reportPersonID}</p>)}
                </div>
                <div className="input-container">
                    <label  htmlFor="MeetingID">Meeting ID</label>
                    <input className={formErrors.meetingID ? 'inputError' : 'MeetingID'} id="MeetingID" name="meetingID" type="text" onChange={handleChange} 
                     onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} value={formData.meetingID} />
                    {(formErrors.meetingID && <p>{formErrors.meetingID}</p>)}
                </div>
                <div className='single-employee-data'>
                <div className="radio-btn-container2">
                  <div className='radio-btn'>
                    <label htmlFor='cancel-meet'>Reported for?</label>
                       
                        <input id="cancel-meet" name="reportedFor" type="radio" value="cancel meet" onChange={handleChange} checked={formData.reportedFor === "cancel meet"} 
                         onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} />
                        <label id="cancel-meet-label" htmlFor="cancel-meet">Cancel meet</label>
                   
                        <input id="update-meet" name="reportedFor" type="radio" onChange={handleChange} value="update meet" checked={formData.reportedFor === "update meet"} 
                         onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} />
                        <label id="update-meet-label" htmlFor="update-meet">Update meet</label>
                        
                        {(formErrors.reportedFor && <p>{formErrors.reportedFor}</p>)}
                    </div>
                </div>
                </div>
                <div className="input-container">
                    <label htmlFor="Issue">Reason</label>
                    <input  className={formErrors.issue ? 'inputError' : 'Issue'} id="Issue" name="issue" type="text" onChange={handleChange} 
                     onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} value={formData.issue} />
                     {(formErrors.issue && <p>{formErrors.issue}</p>)}
                </div>
                </div>
                {formData.reportedFor === "update meet" &&
                <div className="viztrackForm-details">
                <div className="input-container">
                   <div className='date-containter'>
                    <label htmlFor="Update_Date">Update Date</label>
                    <input  className={formErrors.updateDate ? 'inputError' : 'Update_Date'} id="Update_Date" name="updateDate" type="date" onChange={handleChange} 
                     onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} value={formData.updateDate} />
                     {(formErrors.updateDate && <p>{formErrors.updateDate}</p>)}
                   </div>
                </div>
                <div className='time-input-container'>
                    <label htmlFor="UpdateStart_Time">Update Time</label>
                    <div className='time-inner-container'>
                    <div className='time-input'>
                    <div onBlur={()=>{onChangeDatetimeBlur(setFormErrors)("updateStartTime",formData.updateStartTime)}} >
                        <Datetime  className={formErrors.updateStartTime ? 'inputError' : 'Update_StartTime'} id="Update_StartTime" timeFormat={true} dateFormat={false}
                        inputProps={{ placeholder: '-- : --' }} onChange={(momentObj) => {handleChangeDatetime(momentObj,"updateStartTime")}}/>
                    </div>
                     {(formErrors.updateStartTime && <p>{formErrors.updateStartTime}</p>)}
                    </div>
                    <div className='time-input'>
                        <p id='to'>to</p>
                    </div>
                    <div className='time-input'>
                     <div onBlur={()=>{onChangeDatetimeBlur(setFormErrors)("updateEndTime",formData.updateEndTime)}} >
                         <Datetime  className={formErrors.updateEndTime ? 'inputError' : 'Update_EndTime'} id="Update_EndTime" timeFormat={true} dateFormat={false} 
                        inputProps={{ placeholder: '-- : --' }} onChange={(momentObj) => {handleChangeDatetime(momentObj,"updateEndTime")}}/>
                     </div>
                     <div>
                       {(formErrors.updateEndTime && <p>{formErrors.updateEndTime}</p>)}
                     </div>
                     </div>
                     </div>
                 </div>
                </div> }
                <div className='viztrackForm-details'>
                  <button onClick={()=>onSubmitValid(setFormErrors)(formData)} type="submit">Submit</button>
                </div>
            </form>
        </div> ):(<h1 style={{ color: '#4A4A4A' }}>Thanks for your response</h1>) 
         }
        </div>
    );
}

export default EmergencyReport;