import { useEffect, useState, useMemo} from "react";
import axios from "axios";
import { MdOutlineEdit } from 'react-icons/md';
import { MdDelete } from 'react-icons/md';
import { MdRemoveRedEye } from 'react-icons/md';
import {AiOutlineClose } from 'react-icons/ai';
import {BiSearchAlt } from 'react-icons/bi';
import "./css/DisplayTable.css"


function DisplayMeetingDetails() {
  
  const [status, setStatus]=useState(0);
  const [optionStatus, setOptionStatus]=useState('');

  const [meetingsDetails, setMeetingsDetails]=useState([]);
  const [meetingsByDate, setMeetingsByDate]=useState([]);
  const [meetingDate, setMeetingDate]=useState(new Date());
  const [isLoading, setIsLoading] = useState(true);
  const[formErrors, setFormErrors]= useState({});

  const token = localStorage.getItem('jwtToken');
  const headers = useMemo(() => ({
      'Authorization': `Bearer ${token}`
  }), [token]);

    // validate meeting data
     const validation=(name, value)=>{
        const errors={};

        const email_pattern=/^[^\s@]+@[^\s@]+\.[^\s@]{2,4}$/;
        const mobileNo_pattern=/^[0-9\b]+$/;
        const name_pattern=/^[a-zA-Z\s]+$/;
        
        if(name==="visitor_name"){
          if(value.length<1){
            errors.visitor_name="visitor name is required"
          }else if(!name_pattern.test(value)) {
            errors.visitor_name = "name only contain letters";
          } 
        }

        if(name==="visitor_designation"){
          if(value.length<1){
            errors.visitor_designation="visitor designation is required"
          }else if(!name_pattern.test(value)) {
            errors.visitor_designation = "designation only contain letters";
          } 
        }
        
        if(name==="visitor_mobileNo"){
          if(value.length<1){
            errors.visitor_mobileNo="visitor mobile number is required"
          }else if(!mobileNo_pattern.test(value)){
            errors.visitor_mobileNo="mobile number must be a numeric value"
          }else if(value.length<10){
            errors.visitor_mobileNo="mobile number must have 10 digits"
        }}
        
        if(name==="visitor_address"){
        if(value.length<1){
            errors.visitor_address="visitor address is required"
        }}
        
        if(name==="employee_name"){
          if(value.length<1){
            errors.employee_name="employee name is required"
          }else if(!name_pattern.test(value)) {
            errors.employee_name = "name only contain letters";
        } }

        if(name==="employee_designation"){
          if(value.length<1){
            errors.employee_designation="employee designation is required"
          } }
        
        if(name==="employee_department"){
          if(value.length<1){
            errors.employee_department="employee department is required"
          } }
        
        if(name==="employee_email"){
          if(value.length<1){
            errors.employee_email="employee email is required"
          }else if(!email_pattern.test(value)){
            errors.employee_email="invalid email"
        }}

      if(name==="employee_mobileNo"){
        if(value.length<1){
            errors.employee_mobileNo="employee mobile number is required"
        }else if(!mobileNo_pattern.test(value)){
             errors.employee_mobileNo="mobile number must be a numeric value"
        }else if(value.length<10){
             errors.employee_mobileNo="mobile number must have 10 digits"
      } }

      if(name==="meeting_duration"){
        if(value.length<1){
            errors.meeting_duration="meeting duration is required"
        }}

      if(name==="meeting_purpose"){
        if(value.length<1){
            errors.meeting_purpose="meeting purpose leave is required"
      }}

        return errors
    }

    // validate meeting data during submit
    const onSubmitValid=(setter)=>(formdata)=>{
      for(const field in formdata) { 
         setter((formErrors)=>{
            return{
                ...formErrors,
                ...validation(field, formdata[field])
            }
        })
    } }

    // validate meeting data during blur
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


  // get all meetings data
  useEffect(()=>{
       axios.get("http://localhost:4000/api/get/meetings/details",{headers:headers})
      .then(res=> {
        setMeetingsDetails(res.data); setIsLoading(false);
      })
      .catch(err=>console.log(err))
  },[meetingsDetails, headers, isLoading]);
  
  // filter meeting data by date
  useEffect(()=>{
      const filterMeetingsDate = meetingsDetails.filter( (meeting)=>
        new Date(meeting.meeting_date).setHours(0,0,0,0) === new Date(meetingDate).setHours(0,0,0,0));
      setMeetingsByDate(filterMeetingsDate)
  },[meetingsDetails, meetingDate])
  
  // get meeting data by id
  const [meeting, setMeeting]=useState('');

  const ViewSingleMeetingData = (meetingId, option)=> {
     
      //set option
      setOptionStatus(option);
      
      axios.get(`http://localhost:4000/api/get/meetings/details/${meetingId}`,{headers:headers})
      .then(res=> {
        console.log(res);
        setMeeting(res.data);})
      .catch(err=>console.log(err))

  };

  // handle change meetin data
  const handleChange=(event)=>{

        setMeeting({
            ...meeting,
            [event.target.name]:event.target.value
        });
    };

  //Update Visitor data based on id
  const updateSingleMeetingData = ()=> {

      console.log(meeting);
      onSubmitValid(setFormErrors)(meeting);
      
     if(Object.keys(formErrors).length <1){
      axios.patch(`http://localhost:4000/api/update/meetings/details/${meeting._id}`,meeting,{headers:headers})
      .then(res=> {
        console.log(res.data);
        alert("Meeting Details Updated Successfully!");
        setMeeting('');
        setOptionStatus('');})
      .catch(err=>console.log(err))
     }

  };

    // delete meeting data based on id
     const deleteSingleMeetingData =(meetingID)=>{
 
      console.log(meetingID);
       axios.delete(`http://localhost:4000/api/delete/meetings/details/${meetingID}`,{headers:headers})
      .then(res=> {
          console.log(res.data);
          setMeeting('');
          setOptionStatus('');})
      .catch(err=>console.log(err))
      
    };
  
  const [searchMeetingData, setSearchMeetingData]=useState('');

  // handle change search text 
  const searchMeeting=(e)=>{
      setSearchMeetingData(e.target.value);
  }

  // handle change meeting date
  const changeMeetingDate=(e)=>{
    setMeetingDate(e.target.value)
  }

  const [displayData, setDisplayData] = useState([]);
  useEffect(() => {

    if(status){
       
        const keys=["meeting_id","visitor_name","visitor_mobileNo","employee_name","employee_mobileNo"]
        
        //filter meeting data by search text
        const filterMeeting = meetingsByDate.filter((item) => keys.some((key) => item[key].toLowerCase().includes(searchMeetingData.toLowerCase())));
        if(filterMeeting.length>0){
  
        setDisplayData(filterMeeting)
      }
        else{  
          setDisplayData('')
        }
  
      }
         
    else{
       setDisplayData(meetingsByDate);
    }
  }, [status,meetingsDetails, searchMeetingData, meetingsByDate]);


  
  //set status to show all meeting data or filtered meeting data
  useEffect(() => {
  if (searchMeetingData === '') {
    setStatus(0);
  } else {
    setStatus(1);
  }
}, [searchMeetingData]);

    return (
       <div className="display-table">
        <div className="table-header">
        <div className="table-search-container">
          <input type="text" id="meetingSearch" placeholder="Meeting id / Name / MobileNo" className="meeting-search"
            autoComplete="off" onChange={searchMeeting}>
          </input>
        </div>
        <div className="search-icon">
          <BiSearchAlt size={22} />
        </div>
        <div className="table-title">
          <h3>Meeting's Details</h3>
        </div>
        <div className="inputDate-container">
            <input type="date" className="meeting_date" name="meetingDate" onChange={changeMeetingDate} value={new Date(meetingDate).toISOString().split('T')[0]}/>
        </div>
        </div>
        <div className="table-container">
          <div className="table-data">
          <table>
            <thead>
                <tr>
                    <th>SNo.</th>
                    <th>Meeting ID</th>
                    <th>Meeting Date</th>
                    <th>Visitor Name</th>
                    <th>Visitor Designation</th>
                    <th>Visitor MobileNo</th>
                    <th>Employee Name</th>
                    <th>Employee Designation</th>
                    <th>Employee MobileNo.</th>
                    <th>Meeting Purpose</th>
                    <th>Meeting<br/>Duration</th>
                    <th>Action</th>
                </tr>
            </thead>
            { !isLoading  && (<tbody>
              {  
              displayData && displayData.map((Meeting,index)=>{
                  
                return(
                  <tr key={index}>
                    <td>{index+1}</td>
                    <td>
                     { Meeting.meeting_id && searchMeetingData && Meeting.meeting_id.toLowerCase().includes(searchMeetingData.toLowerCase()) ? 
                         <span>
                             {Meeting.meeting_id.split(new RegExp(`(${searchMeetingData})`, 'gi')).map((text, index) => {
                            if (text.toLowerCase() === searchMeetingData.toLowerCase()) {
                                  return <mark key={index}>{text}</mark>;
                            } else {
                               return <span key={index}>{text}</span>;
                                   }
                            })}
                        </span> 
                        : (<span>{Meeting.meeting_id}</span>) }
                    </td>
                    <td>{new Date(Meeting.meeting_date).toLocaleDateString('en-GB')}</td>
                    <td>
                      {  Meeting.visitor_name && searchMeetingData && Meeting.visitor_name.toLowerCase().includes(searchMeetingData.toLowerCase()) ? 
                         <span>
                             {Meeting.visitor_name.split(new RegExp(`(${searchMeetingData})`, 'gi')).map((text, index) => {
                            if (text.toLowerCase() === searchMeetingData.toLowerCase()) {
                                  return <mark key={index}>{text}</mark>;
                            } else {
                               return <span key={index}>{text}</span>;
                                   }
                            })}
                        </span> 
                        : (<span>{Meeting.visitor_name}</span>)}
                    </td>
                    <td>{Meeting.visitor_designation}</td>
                    <td>
                    {  Meeting.visitor_mobileNo && searchMeetingData &&  Meeting.visitor_mobileNo.toLowerCase().includes(searchMeetingData.toLowerCase()) ? 
                      <span>
                         {Meeting.visitor_mobileNo.split(new RegExp(`(${searchMeetingData})`, 'gi')).map((text, index) => {
                            if (text.toLowerCase() === searchMeetingData.toLowerCase()) {
                                  return <mark key={index}>{text}</mark>;
                            } else {
                               return <span key={index}>{text}</span>;
                                   }
                            })}
                        </span> 
                        : (<span>{Meeting.visitor_mobileNo}</span>) }
                    </td>
                    <td>
                      {  Meeting.employee_name && searchMeetingData && Meeting.employee_name.toLowerCase().includes(searchMeetingData.toLowerCase()) ? 
                         <span>
                             {Meeting.employee_name.split(new RegExp(`(${searchMeetingData})`, 'gi')).map((text, index) => {
                            if (text.toLowerCase() === searchMeetingData.toLowerCase()) {
                                  return <mark key={index}>{text}</mark>;
                            } else {
                               return <span key={index}>{text}</span>;
                                   }
                            })}
                        </span> 
                        : (<span>{Meeting.employee_name}</span>)}
                    </td>
                    <td>{Meeting.employee_designation}</td>
                    <td>
                    {  Meeting.employee_mobileNo && searchMeetingData &&  Meeting.employee_mobileNo.toLowerCase().includes(searchMeetingData.toLowerCase()) ? 
                      <span>
                         {Meeting.employee_mobileNo.split(new RegExp(`(${searchMeetingData})`, 'gi')).map((text, index) => {
                            if (text.toLowerCase() === searchMeetingData.toLowerCase()) {
                                  return <mark key={index}>{text}</mark>;
                            } else {
                               return <span key={index}>{text}</span>;
                                   }
                            })}
                        </span> 
                        : (<span>{Meeting.employee_mobileNo}</span>) }
                    </td>
                    <td>{Meeting.meeting_purpose}</td>
                    <td>{Meeting.meeting_duration}</td>
                    <td>
                       <div className="icons-container">
                        <div className="icons" onClick={()=>ViewSingleMeetingData(Meeting._id,"view")}>
                          <MdRemoveRedEye />
                        </div>
                        <div className="icons"  onClick={()=>ViewSingleMeetingData(Meeting._id,"edit")} >
                          <MdOutlineEdit />
                        </div>
                        <div className="icons"  onClick={()=>deleteSingleMeetingData(Meeting._id)}>
                          <MdDelete />
                        </div>
                       </div>
                    </td>
                  </tr>
              )})
            }
          </tbody> )}
          </table>
        </div>
        { isLoading &&<p id="loading-text">Loading...</p>}
        { (!isLoading && meetingsByDate.length===0) && <p id="loading-text">No Data !</p>}
        <span className="table-data-not-found">
          {
            (!displayData && (<p>No Records Found !</p>))
          }
        </span>
        {(meeting && optionStatus==="view") && (
        <div className="display-single-data">
        <div className="single-data-container">
          <div  className="single-data-close-icon">
            <AiOutlineClose onClick={()=>setMeeting('')} />
          </div>
          <div>
            <h2>Meeting Details</h2>
          </div>
          <div className="single-data">
            <h4>Meeting ID :</h4>
            <p>{meeting.meeting_id}</p>
          </div>
           <div className="single-data">
            <h4>Meeting Date :</h4>
            <p>{new Date(meeting.meeting_date).toLocaleDateString('en-GB')}</p>
          </div>
           <div className="single-data">
            <h4>Meeting Duration :</h4>
            <p>{meeting.meeting_duration}</p>
          </div>
          <div className="single-data">
            <h4>Meeting Purpose :</h4>
            <p>{meeting.meeting_purpose}</p>
          </div>
          <br></br>
          <div className="single-data">
            <h4>Visitor ID :</h4>
            <p>{meeting.visitor_id}</p>
          </div>
           <div className="single-data">
            <h4>Visitor Name :</h4>
            <p>{meeting.visitor_name}</p>
          </div>
          <div className="single-data">
            <h4>Visitor Designation :</h4>
            <p>{meeting.visitor_designation}</p>
          </div>
          <div className="single-data">
            <h4>Visitor MobileNo :</h4>
            <p>{meeting.visitor_mobileNo}</p>
          </div>
          <div className="single-data">
            <h4>Visitor Address :</h4>
            <p>{meeting.visitor_address}</p>
          </div>
          <br></br>
          <div className="single-data">
             <h4>Employee ID :</h4>
            <p>{meeting.employee_id}</p>
          </div>
          <div className="single-data">
             <h4>Employee Name :</h4>
            <p>{meeting.employee_name}</p>
          </div>
          <div className="single-data">
            <h4>Employee Designation :</h4>
            <p>{meeting.employee_designation}</p>
          </div>
          <div className="single-data">
            <h4>Employee Department :</h4>
            <p>{meeting.employee_department}</p>
          </div>
          <div className="single-data">
            <h4>Employee MobileNo :</h4>
            <p>{meeting.employee_mobileNo}</p>
          </div>
          <div className="single-data">
            <h4>Employee Email :</h4>
            <p>{meeting.employee_email}</p>
          </div>
        </div>
      </div>
      )}

      { (meeting && optionStatus==="edit") && (
        <div className="update-single-data">
        <div className="update-single-data-container">
           <div  className="single-data-close-icon">
            <AiOutlineClose onClick={()=>{setMeeting(''); setFormErrors({})}} />
          </div>
          <div className="title">
            <h2>Meeting Details</h2>
          </div>
          <div className="single-data">
            <label htmlFor="Visitor_Name">Visitor Name :</label>
            <input className={formErrors.visitor_name ? 'inputError' : 'Visitor_Name'} id="Visitor_Name" name="visitor_name" type="text"  onChange={handleChange} value={meeting.visitor_name}
             onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} />
          </div>
          <div className="single-data">
            <label htmlFor="Visitor_Designation">Visitor Designation :</label>
            <input className={formErrors.visitor_designation ? 'inputError' : 'Visitor_Designation'} id="Visitor_Designation" name="visitor_designation" type="text"  onChange={handleChange} value={meeting.visitor_designation}
             onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} />
          </div>
          <div className="single-data">
            <label htmlFor="Visitor_MobileNo">Visitor MobileNo :</label>
            <input className={formErrors.visitor_mobileNo ? 'inputError' : 'Mobile_Number'} id="Visitor_MobileNo" name="visitor_mobileNo" type="text"  onChange={handleChange} value={meeting.visitor_mobileNo}
             onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} />
          </div>
          <div className="single-data">
            <label htmlFor="Visitor_Address">Visitor Address :</label>
            <textarea className={formErrors.visitor_address ? 'inputError' : 'Visitor_Address'} id="Visitor_Address" name="visitor_address" type="text" onChange={handleChange} value={meeting.visitor_address} 
             onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} />
          </div>
           <br></br>
          <div className="single-data">
            <label htmlFor="Employee_Name">Employee Name :</label>
            <input className={formErrors.employee_name ? 'inputError' : 'Full_Name'} id="Employee_Name" name="employee_name" type="text"  onChange={handleChange} value={meeting.employee_name}
             onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} />
          </div>
          <div className="single-data">
            <label htmlFor="Employee_Designation">Employee Designation :</label>
            <input  className={formErrors.employee_designation ? 'inputError' : 'Employee_Designation'} id="Employee_Designation" name="employee_designation" type="text" onChange={handleChange} value={meeting.employee_designation} 
             onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} />
          </div>
          <div className="single-data">
            <label htmlFor="Employee_Department">Employee Department :</label>
            <input className={formErrors.employee_department ? 'inputError' : 'Employee_Department'} id="Employee_Department" name="employee_department" type="text" onChange={handleChange} value={meeting.employee_department} 
             onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} />
          </div>
          <div className="single-data">
            <label htmlFor="Employee_MobileNo">Employee MobileNo :</label>
            <input className={formErrors.employee_mobileNo ? 'inputError' : 'Employee_Mobile_Number'} id="Employee_MobileNo" name="employee_mobileNo" type="text" onChange={handleChange} value={meeting.employee_mobileNo} 
             onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} />
          </div>
          <div className="single-data">
            <label htmlFor="Employee_Email">Employee Email :</label>
            <input className={formErrors.employee_email ? 'inputError' : 'Employee_Email'} id="Employee_Email" name="employee_email" type="email" onChange={handleChange} value={meeting.employee_email} 
             onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} />
          </div>
          <br></br>
          <div className="single-data">
            <label htmlFor="Meeting_Purpose">Meeting Purpose:</label>
             <textarea className={formErrors.meeting_purpose ? 'inputError' : 'Meeting_Purpose'} id="Meeting_Purpose" name="meeting_purpose" type="text" onChange={handleChange} value={meeting.meeting_purpose} 
              onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} />
          </div>
          <div className="single-data">
            <label htmlFor="Meeting_Duration">Meeting_Duration :</label>
             <input className={formErrors.meeting_duration ? 'inputError' : 'Meeting_Duration'} id="Meeting_Duration" name="meeting_duration" type="number" onChange={handleChange} value={meeting.meeting_duration} 
              onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} />
          </div>
               
          <button type="submit" onClick={updateSingleMeetingData}>Update</button>
        </div>
      </div>
      )}
      </div>
      </div>
    )
}

export default DisplayMeetingDetails;