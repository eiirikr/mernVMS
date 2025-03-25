import { useEffect, useState, useMemo} from "react";
import axios from "axios";
import { MdOutlineEdit } from 'react-icons/md';
import { MdDoneOutline } from 'react-icons/md';
import { MdDelete } from 'react-icons/md';
import { MdRemoveRedEye } from 'react-icons/md';
import {AiOutlineClose } from 'react-icons/ai';
import {BiSearchAlt } from 'react-icons/bi';
import "./css/DisplayTable.css"
import Datetime from 'react-datetime';
import 'react-datetime/css/react-datetime.css';
import moment from "moment";

function EmergencyReport({handleChangeReportCount}) {

  const [status, setStatus]=useState(0);
  const [optionStatus, setOptionStatus]=useState('');

  const [emergencyReports, setEmergencyReports]=useState([]);
  const [reportsByDate, setReportsByDate]=useState([]);
  const [reportDate, setReportDate]=useState(new Date());
  const [isLoading, setIsLoading] = useState(true);

  const token = localStorage.getItem('jwtToken');
  const headers = useMemo(() => ({
      'Authorization': `Bearer ${token}`
  }), [token]);


  // get all emergency reports details
  useEffect(()=>{   
       axios.get("http://localhost:4000/api/get/emergency/reports",{headers:headers})
      .then(res=> {setEmergencyReports(res.data); setIsLoading(false);
      })
      .catch(err=>console.log(err))
  },[emergencyReports, headers, isLoading]);

  
  // filter emergency reports by date
  useEffect(()=>{
      const filterReportsbyDate = emergencyReports.filter((report)=>(new Date(reportDate).setHours(0,0,0,0) === new Date(report.reported_date).setHours(0,0,0,0)));
      setReportsByDate(filterReportsbyDate)
      handleChangeReportCount(emergencyReports.length)
  },[reportDate, emergencyReports])

  
 // get check in/out data by id
  const [meeting, setMeeting]=useState('');

  const ViewSinglePreRegisterData = (meetingId, option)=> {
     
      // set option
      setOptionStatus(option);
      
      // get pre-registrations details
      axios.get(`http://localhost:4000/api/get/preregister/meetings/details/${meetingId}`,{headers:headers})
      .then(res=> {
        console.log(res);
        if(res.data.message==='meeting data not found'){
            alert(res.data.message)
        }else{
        setMeeting(res.data); } })
      .catch(err=>console.log(err))

  };


  // handle change preRegister details
  const handleChange=(event)=>{

        setMeeting({
            ...meeting,
            [event.target.name]:event.target.value
        });
    };

  // update preRegister data by meeting id
  const updateSinglePreRegisterData = ()=> {
     
       console.log(meeting);
     
      axios.patch(`http://localhost:4000/api/update/preregister/meetings/details/${meeting.meeting_id}`,meeting,{headers:headers})
      .then(res=> {
        console.log(res.data);
        alert("Meeting Details Updated Successfully!");
        setMeeting('');
        setOptionStatus('');})
      .catch(err=>console.log(err))

  };

    
     // delete preRegister data by meeting id
     const deleteSinglePreRegisterData =(meetingID)=>{
 
      console.log(meetingID);
       axios.delete(`http://localhost:4000/api/delete/preregister/meetings/details/${meetingID}`,{headers:headers})
      .then(res=> {
          console.log(res.data);  
          if(res.data.message==='meeting data not found' || res.data.message==='Admin not Authorized'){
            alert(res.data.message)
          }else{
          alert(res.data.message)
          setMeeting('');
          setOptionStatus(''); } })
      .catch(err=>console.log(err))
      
    };


  // delete emergency report by id
  const deleteEmergencyReportData =(reportID)=>{
 
      console.log(reportID);
       axios.delete(`http://localhost:4000/api/delete/emergency/reports/${reportID}`,{headers:headers})
      .then(res=> {
          console.log(res.data);  
          setOptionStatus('');   })
      .catch(err=>console.log(err))
      
    };
  

  const [searchReportData, setSearchReportData]=useState('');

  // handle change search text 
  const searchReport=(e)=>{
      setSearchReportData(e.target.value);
  }

  // handle change date
  const changeReportDate=(e)=>{
    setReportDate(e.target.value)
  }

  const [displayData, setDisplayData] = useState([]);

  useEffect(() => {

    if(status){
       
        const keys=["meeting_id","id","name","mobile_no"]
        
        // filter emergency reports by search text
        const filterReports = reportsByDate.filter((item) => keys.some((key) => item[key].toLowerCase().includes(searchReportData.toLowerCase())));
        if(filterReports.length>0){
  
        setDisplayData(filterReports)
      }
        else{  
          setDisplayData('')
        }
  
      }
         
    else{
       setDisplayData(reportsByDate);
    }
  }, [status, searchReportData, reportsByDate]);


  
  // set status to show emergency reports / filtered emergency reports
  useEffect(() => {
  if (searchReportData === '') {
    setStatus(0);
  } else {
    setStatus(1);
  }
}, [searchReportData]);

    return (
       <div className="display-table">
        <div className="table-header">
        <div className="table-search-container">
          <input type="text" id="meetingSearch" placeholder="Meeting id / id / Name / MobileNo" className="meeting-search"
            autoComplete="off" onChange={searchReport}>
          </input>
        </div>
        <div className="search-icon">
          <BiSearchAlt size={22} />
        </div>
        <div className="table-title">
          <h3>Emergency Reports</h3>
        </div>
        <div className="inputDate-container">
            <input type="date" className="report_date" name="reportDate" onChange={changeReportDate} value={new Date(reportDate).toISOString().split('T')[0]}/>
        </div>
        </div>
        <div className="reports-count">
          <p>Overall reports: {emergencyReports.length}</p>
          <p>Total reports by date: {reportsByDate.length}</p>
        </div>
        <div className="table-container">
          <div className="table-data">
          <table>
            <thead>
                <tr>
                    <th>SNo.</th>
                    <th>Reported<br/>Date</th>
                    <th>ID</th>
                    <th>Name</th>
                    <th>Designation</th>
                    <th>MobileNo</th>
                    <th>Meeting ID</th>
                    <th>Issue</th>
                    <th>Cancel/Update<br/>Meet</th>
                    <th>Update Date</th>
                    <th>Update Time</th>
                    <th>Meet Action</th>
                    <th>Report<br/>Action</th>
                </tr>
            </thead>
            { !isLoading && (
           <tbody>
            {  
             
              displayData && displayData.map((EmergencyReport,index)=>{
                  
                return(
                  <tr key={index}>
                    <td>{index+1}</td>
                    <td>{new Date(EmergencyReport.reported_date).toLocaleDateString('en-GB')}</td>
                    <td>
                     { EmergencyReport.id && searchReportData && EmergencyReport.id.toLowerCase().includes(searchReportData.toLowerCase()) ? 
                         <span>
                             {EmergencyReport.id.split(new RegExp(`(${searchReportData})`, 'gi')).map((text, index) => {
                            if (text.toLowerCase() === searchReportData.toLowerCase()) {
                                  return <mark key={index}>{text}</mark>;
                            } else {
                               return <span key={index}>{text}</span>;
                                   }
                            })}
                        </span> 
                        : (<span>{EmergencyReport.id}</span>) }
                    </td>
                    <td>
                      {  EmergencyReport.name && searchReportData && EmergencyReport.name.toLowerCase().includes(searchReportData.toLowerCase()) ? 
                         <span>
                             {EmergencyReport.name.split(new RegExp(`(${searchReportData})`, 'gi')).map((text, index) => {
                            if (text.toLowerCase() === searchReportData.toLowerCase()) {
                                  return <mark key={index}>{text}</mark>;
                            } else {
                               return <span key={index}>{text}</span>;
                                   }
                            })}
                        </span> 
                        : (<span>{EmergencyReport.name}</span>)}
                    </td>
                    <td>{EmergencyReport.designation}</td>
                    <td>
                    {  EmergencyReport.mobile_no && searchReportData &&  EmergencyReport.mobile_no.toLowerCase().includes(searchReportData.toLowerCase()) ? 
                      <span>
                         { EmergencyReport.mobile_no.split(new RegExp(`(${searchReportData})`, 'gi')).map((text, index) => {
                            if (text.toLowerCase() === searchReportData.toLowerCase()) {
                                  return <mark key={index}>{text}</mark>;
                            } else {
                               return <span key={index}>{text}</span>;
                                   }
                            })}
                        </span> 
                        : (<span>{EmergencyReport.mobile_no}</span>) }
                    </td>
                    <td>
                      {  EmergencyReport.meeting_id && searchReportData && EmergencyReport.meeting_id.toLowerCase().includes(searchReportData.toLowerCase()) ? 
                         <span>
                             {EmergencyReport.meeting_id.split(new RegExp(`(${searchReportData})`, 'gi')).map((text, index) => {
                            if (text.toLowerCase() === searchReportData.toLowerCase()) {
                                  return <mark key={index}>{text}</mark>;
                            } else {
                               return <span key={index}>{text}</span>;
                                   }
                            })}
                        </span> 
                        : (<span>{EmergencyReport.meeting_id}</span>)}
                    </td>
                    <td>{EmergencyReport.issue}</td>
                    <td>{EmergencyReport.reported_for}</td>
                    <td>{EmergencyReport.update_date && new Date(EmergencyReport.update_date).toLocaleDateString('en-GB')}</td>
                    <td>{EmergencyReport.update_time}</td>
                    <td>
                       <div className="icons-container">
                        <div className="icons" onClick={()=>ViewSinglePreRegisterData(EmergencyReport.meeting_id,"view")}>
                          <MdRemoveRedEye />
                        </div>
                        <div className="icons"  onClick={()=>ViewSinglePreRegisterData(EmergencyReport.meeting_id,"edit")} >
                          <MdOutlineEdit />
                        </div>
                        <div className="icons"  onClick={()=>deleteSinglePreRegisterData(EmergencyReport.meeting_id)}>
                          <MdDelete />
                        </div>
                       </div>
                    </td>
                    <td>
                       <div className="icons-container">
                        <div className="icons"  onClick={()=>deleteEmergencyReportData(EmergencyReport._id)}>
                          <MdDoneOutline />
                        </div>
                       </div>
                    </td>
                  </tr>
              )})
            }
          </tbody>)}
          </table>
        </div>
        { isLoading &&<p id="loading-text">Loading...</p>}
        { (!isLoading && reportsByDate.length===0) && <p id="loading-text">No Data !</p>}
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
            <h4>Meeting Time :</h4>
            <p>{moment(meeting.meeting_startTime,'hh:mm A').format('hh:mm A')+" - "+moment(meeting.meeting_endTime,'hh:mm A').format('hh:mm A')}</p>
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
            <AiOutlineClose onClick={()=>setMeeting('')} />
          </div>
          <div className="title">
            <h2>Pre-Register Meeting Details</h2>
          </div>
          <div className="single-data">
            <label htmlFor="Visitor_Name">Visitor Name :</label>
            <input id="Visitor_Name" name="visitor_name" type="text"  onChange={handleChange} value={meeting.visitor_name}/>
          </div>
          <div className="single-data">
            <label htmlFor="Visitor_Designation">Visitor Designation :</label>
            <input id="Visitor_Designation" name="visitor_designation" type="text"  onChange={handleChange} value={meeting.visitor_designation}/>
          </div>
          <div className="single-data">
            <label htmlFor="Visitor_MobileNo">Visitor MobileNo :</label>
            <input id="Visitor_MobileNo" name="visitor_mobileNo" type="text"  onChange={handleChange} value={meeting.visitor_mobileNo}/>
          </div>
          <div className="single-data">
            <label htmlFor="Visitor_Address">Visitor Address :</label>
            <textarea id="Visitor_Address" name="visitor_address" type="text" onChange={handleChange} value={meeting.visitor_address} />
          </div>
           <br></br>
          <div className="single-data">
            <label htmlFor="Employee_Name">Employee Name :</label>
            <input id="Employee_Name" name="employee_name" type="text"  onChange={handleChange} value={meeting.employee_name}/>
          </div>
          <div className="single-data">
            <label htmlFor="Employee_Designation">Employee Designation :</label>
            <input id="Employee_Designation" name="employee_designation" type="text" onChange={handleChange} value={meeting.employee_designation} />
          </div>
          <div className="single-data">
            <label htmlFor="Employee_Department">Employee Department :</label>
            <input id="Employee_Department" name="employee_department" type="text" onChange={handleChange} value={meeting.employee_department} />
          </div>
          <div className="single-data">
            <label htmlFor="Employee_MobileNo">Employee MobileNo :</label>
            <input id="Employee_MobileNo" name="employee_mobileNo" type="text" onChange={handleChange} value={meeting.employee_mobileNo} />
          </div>
          <div className="single-data">
            <label htmlFor="Employee_Email">Employee Email :</label>
            <input id="Employee_Email" name="employee_email" type="email" onChange={handleChange} value={meeting.employee_email} />
          </div>
          <br></br>
          <div className="single-data">
          <div className="input-container">
            <label htmlFor="Meeting_Date">Meeting Date :</label>
            <input id="Meeting_Date" name="meeting_date" type="date" onChange={handleChange} value={new Date(meeting.meeting_date).toISOString().split('T')[0]} />
          </div>
          <div className="input-container">
            <label htmlFor="Meeting_StartTime">Meeting Start Time :</label>
             <Datetime  id="Meeting_StartTime" name="meeting_startTime" timeFormat={true} dateFormat={false}
                inputProps={{ placeholder: '-- : --' }} onChange={(momentObj) => {
                  setMeeting((prevFormInput) => ({
                        ...prevFormInput, 
                        meeting_startTime: momentObj.format('hh:mm A')  })); 
              }} value={moment(meeting.meeting_startTime, 'hh:mm A')}/>
              
          </div>
          <div className="input-container">
            <label htmlFor="Meeting_EndTime">Meeting End Time :</label>
             <Datetime  id="Meeting_EndTime" name="meeting_endTime" timeFormat={true} dateFormat={false} inputProps={{ placeholder: '-- : --' }} 
              onChange={(momentObj) => {
                        setMeeting((prevFormInput) => ({
                         ...prevFormInput, 
                          meeting_endTime: momentObj.format('hh:mm A')  })); 
              }} value={ moment(meeting.meeting_endTime, 'hh:mm A')}/>
          </div>
          </div>
          <div className="single-data">
            <label htmlFor="Meeting_Purpose">Meeting Purpose:</label>
             <textarea id="Meeting_Purpose" name="meeting_purpose" type="text" onChange={handleChange} value={meeting.meeting_purpose} />
          </div>
          <button type="submit" onClick={updateSinglePreRegisterData}>Update</button>
        </div>
      </div>
      )}
      </div>
      </div>
    )
}

export default EmergencyReport;