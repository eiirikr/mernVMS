import { useEffect, useState, useMemo } from "react";
import axios from "axios";
import { MdOutlineEdit } from 'react-icons/md';
import { MdDelete } from 'react-icons/md';
import { MdRemoveRedEye } from 'react-icons/md';
import {AiOutlineClose } from 'react-icons/ai';
import {BiSearchAlt } from 'react-icons/bi';
import { MdDateRange } from 'react-icons/md';
import "./css/DisplayTable.css";
import Datetime from 'react-datetime';
import 'react-datetime/css/react-datetime.css'; 
const moment = require('moment');

function DisplayCheckInOutData({handleDashboardChange, handleVisitorShowData}) {

  const [status, setStatus]=useState(0);
  const [optionStatus, setOptionStatus]=useState('');
  
  const [meetingDate, setMeetingDate]=useState(new Date());
  const [checkInOutDetails, setCheckInOutDetails]=useState([]);
  const [todayCheckInOuts, setTodayCheckInOuts]=useState([]);
  const [visitorInData, setVisitorInData]=useState([]);
  const [visitorOutData, setVisitorOutData]=useState([]);
  const [checkInOutDataShow, setCheckInOutDataShow]=useState([]);
  const [completedPreRegisterations, setCompletedPreRegisterations]=useState([]);
  const [pendingPreRegisterations, setPendingPreRegisterations]=useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const[formErrors, setFormErrors]= useState({});

  const token = localStorage.getItem('jwtToken');
  const headers = useMemo(() => ({
      'Authorization': `Bearer ${token}`
  }), [token]);

     // validate check in/out details
     const validation=(name, value)=>{
        const errors={};
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
            errors.visitor_designation = "name only contain letters";
          } 
        }

        if(name==="visitor_mobileNo"){
          if(value.length<1){
            errors.visitor_mobileNo="visitor mobile number is required"
          }else if(!mobileNo_pattern.test(value)){
             errors.visitor_mobileNo="mobile number must be a numeric value"
          }else if(!(value.length===10)){
             errors.visitor_mobileNo="mobile number must have 10 digits"
          } 
        }

        if(name==="visit_date"){
          if(!value){
            errors.visit_date="visit date is required"
          }
        }

        if(name==="visit_startTime"){
          if(!value){
            errors.visit_startTime="visit start time is required"
        }}

        if(name==="visit_endTime"){
         if(!value){
            errors.visit_endTime="visit end time is required"
        }}

          if(name==="allotted_visit_duration"){
          if(value.length<1){
            errors.allotted_visit_duration="allotted visit duration is required"
          }
        }

        if(name==="checkIn"){
          if(!value){
            errors.checkIn="check in time is required"
        }}

        if(name==="checkOut"){
          if(!value){
            errors.meetingDate="check out time is required"
        }}

        if(name==="visit_duration"){
          if(value.length<1){
            errors.visit_duration="visit duration is required"
          }
        }

         if(name==="visit_purpose"){
          if(value.length<1){
            errors.visit_purpose="visit purpose is required"
          }
        }

        if(name==="visitor_status"){
          if(value.length<1){
            errors.visitor_status="visit status is required"
          }
        }

        return errors
    }

     // validate check in/out details during submit
     const onSubmitValid=(setter)=>(formdata)=>{
      for(const field in formdata) { 
         setter((formErrors)=>{
            return{
                ...formErrors,
                ...validation(field, formdata[field])
            }
        })
    } }

    // validate check in/out details during blur
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

    // handle change time input
    const handleChangeDatetime=(momentObj,name)=>{
      setCheckInOutData({
        ...checkInOutData, 
         [name]: momentObj.format('hh:mm A') }); 

         onChangeDatetimeFocus(setFormErrors)(name)
      }


  // get all check in/out details
  useEffect(()=>{
       axios.get("http://localhost:4000/api/get/all/check/in/out/details",{headers:headers})
      .then(res=> {setCheckInOutDetails(res.data); setIsLoading(false);})
      .catch(err=>console.log(err))
  },[checkInOutDetails, headers, isLoading]);
  
  // filter check in/out details by date
  useEffect(()=>{
      const filterMeetingsDate = checkInOutDetails.filter( (checkData)=>
        new Date(checkData.visit_date).setHours(0,0,0,0) === new Date(meetingDate).setHours(0,0,0,0));
      setCheckInOutDataShow(filterMeetingsDate)
  },[checkInOutDetails, meetingDate])

  const [checkInOutData, setCheckInOutData]=useState('');

   // get check in/out data by id
  const ViewSingleCheckInOutData = (visitPassId, option)=> {
     
      //set option
      setOptionStatus(option);
  
       axios.get(`http://localhost:4000/api/get/check/in/out/details/${visitPassId}`,{headers:headers})
      .then(res=> {setCheckInOutData(res.data)})
      .catch(err=>console.log(err))
  };

  // handle change check in/out details
  const handleChange=(event)=>{

        setCheckInOutData({
            ...checkInOutData,
            [event.target.name]:event.target.value
        });
    };

  // set date
  const changeMeetingDate=(e)=>{
    setMeetingDate(e.target.value)
  }

  // update check in/out details by id
  const updateSingleCheckInOutData = ()=> {
 
      console.log(checkInOutData._id);
      onSubmitValid(setFormErrors)(checkInOutData);
      
      if(Object.keys(formErrors).length <1){
       axios.patch(`http://localhost:4000/api/update/check/in/out/details/${checkInOutData._id}`,checkInOutData,{headers:headers})
      .then(res=> {
        console.log(res.data);
        setCheckInOutData('');
        setOptionStatus('')})
      .catch(err=>console.log(err))
    }; }

    
    // delete check in/out details by id
     const deleteSingleCheckInOutData =(visitPassID)=>{
 
      console.log(visitPassID);
       axios.delete(`http://localhost:4000/api/delete/check/in/out/details/${visitPassID}`,{headers:headers})
      .then(res=> {
          console.log(res.data);
          setCheckInOutData('');
          setOptionStatus('');})
      .catch(err=>console.log(err))

    };


  const [searchCheckInOutData, setSearchCheckInOutData]=useState('');

  //handle change search text 
  const searchCheckInOut=(e)=>{
      setSearchCheckInOutData(e.target.value);
  }


   useEffect(()=>{

      const today=new Date().setHours(0,0,0,0);
      
      // filter check in/out data by visitor status
      const todayCheckIns = checkInOutDetails.filter( (checkData)=> ( (checkData.visitor_status !== "") && (new Date(checkData.visit_date).setHours(0,0,0,0) === today) ));
      const filterStatusIn = checkInOutDetails.filter( (checkData)=> ((checkData.visitor_status === "In") && (new Date(checkData.visit_date).setHours(0,0,0,0) === today) ));
      const filterStatusOut = checkInOutDetails.filter( (checkData)=> ((checkData.visitor_status === "Out")  && (new Date(checkData.visit_date).setHours(0,0,0,0) === today) ) );
      
      setTodayCheckInOuts(todayCheckIns)
      setVisitorInData(filterStatusIn);
      setVisitorOutData(filterStatusOut);
      
      const  pendingPreRegister= checkInOutDetails.filter( (checkData)=> ((checkData.visitPass_id[0] === 'P' && checkData.visitor_status === "In") && new Date(checkData.visit_date).setHours(0,0,0,0)=== today) );
      const  completedPreRegister= checkInOutDetails.filter( (checkData)=> ((checkData.visitPass_id[0] === 'P' && checkData.visitor_status === "Out")&& new Date(checkData.visit_date).setHours(0,0,0,0)=== today) );

       setCompletedPreRegisterations(completedPreRegister);
       setPendingPreRegisterations(pendingPreRegister);
      
      // set count
      const formData = {
        TotalVisitorCount: todayCheckIns.length,
        VisitorInCount: filterStatusIn.length,
        VisitorOutCount: filterStatusOut.length,
        PendingPreRegisterCount:pendingPreRegister.length,
        CompletedPreRegisterCount: completedPreRegister.length
      };
    
    handleDashboardChange(formData);

  },[checkInOutDetails])

  
  const [displayData, setDisplayData] = useState([]);
  useEffect(() => {

    // determine the data to display.
    if(handleVisitorShowData==='Total Visitors'){
          setCheckInOutDataShow(todayCheckInOuts)

    }else if(handleVisitorShowData==='Visitors In'){
          setCheckInOutDataShow(visitorInData)
        
    }else if(handleVisitorShowData==='Visitors Out'){
          setCheckInOutDataShow(visitorOutData)

    }else if(handleVisitorShowData==='Completed PreRegistrations'){
          setCheckInOutDataShow(completedPreRegisterations)
          
    }else if(handleVisitorShowData==='Pending PreRegistrations'){
         setCheckInOutDataShow(pendingPreRegisterations)
    }
       
    if(status){
        const keys=["visitPass_id","visitor_id","visitor_mobileNo","visitor_name"]
         
        // filter check in/out details by search text
        const filterCheckData = checkInOutDataShow.filter((item) => keys.some((key) => item[key].toLowerCase().includes(searchCheckInOutData.toLowerCase())));
        if(filterCheckData.length>0){
  
        setDisplayData(filterCheckData)
      }
        else{  
          setDisplayData('')
        }
  
      }
         
    else{
       setDisplayData(checkInOutDataShow);
    }
  }, [status, searchCheckInOutData,todayCheckInOuts, visitorInData, visitorOutData,
      completedPreRegisterations, pendingPreRegisterations, checkInOutDataShow, handleVisitorShowData]);

  
  // set status to show sll checkInOut details / filtered checkInOut Details
  useEffect(() => {
    if (searchCheckInOutData === '') {
      setStatus(0);
    } else {
      setStatus(1);
    }
  }, [searchCheckInOutData]);

    return (
       <div className="display-table">
        <div className="table-header">
        <div className="table-search-container">
          <input type="text" id="visitorSearch" placeholder="Visit Pass id / Visitor id / Mobile no / Name" className="checkData-search"
            onChange={searchCheckInOut}></input>
        </div>
        <div className="search-icon">
          <BiSearchAlt size={22} />
        </div>
        <div className={((handleVisitorShowData==='Visitors In' || handleVisitorShowData==='Visitors Out') 
        || handleVisitorShowData==='Total Visitors')? "table-title2" : "table-title"}>
         {(handleVisitorShowData!=='') ? (<h3>{handleVisitorShowData}</h3>):(<h3>Check In/Out Details</h3>)}
        </div>
        <div className="inputDate-container">
         {(handleVisitorShowData!=='') ? (
          <div className="date">
            <MdDateRange size={20}/>
            <p>{new Date().toLocaleDateString('en-GB')}</p>
          </div>) :
          (<input type="date" className="meeting_date" name="meetingDate" onChange={changeMeetingDate} value={new Date(meetingDate).toISOString().split('T')[0]}/>)
          }
        </div>
        </div>
        <div className="table-container">
          <div className="table-data">
          <table>
            <thead>
                <tr>
                    <th>SNo.</th>
                    <th>Visit Pass ID</th>
                    <th>Visitor ID</th>
                    <th>Visitor Name</th>
                    <th>Visitor Designation</th>
                    <th>Visitor MobileNo.</th>
                    <th>Visit Date</th>
                    <th>Allotted<br/>Visit Time</th>
                    <th>Allotted<br/>Duration<small>(mins)</small></th>
                    <th>Check In</th>
                    <th>Check Out</th>
                    <th>Visit Status</th>
                    <th>Visit<br/>Duration<small>(mins)</small></th>
                    <th>Action</th>
                </tr>
            </thead>
           { !isLoading  && (
          <tbody>
            {  
             
              displayData && displayData.map((CheckInfo,index)=>{
                  
                return(
                  <tr key={index}>
                    <td>{index+1}</td>
                    <td>
                     { CheckInfo.visitPass_id && searchCheckInOutData && CheckInfo.visitPass_id.toLowerCase().includes(searchCheckInOutData.toLowerCase()) ? 
                         <span>
                             {CheckInfo.visitPass_id.split(new RegExp(`(${searchCheckInOutData})`, 'gi')).map((text, index) => {
                            if (text.toLowerCase() === searchCheckInOutData.toLowerCase()) {
                                  return <mark key={index}>{text}</mark>;
                            } else {
                               return <span key={index}>{text}</span>;
                                   }
                            })}
                        </span> 
                        : (<span>{CheckInfo.visitPass_id}</span>) }
                    </td>
                    <td>
                     { CheckInfo.visitor_id && searchCheckInOutData && CheckInfo.visitor_id.toLowerCase().includes(searchCheckInOutData.toLowerCase()) ? 
                         <span>
                             {CheckInfo.visitor_id.split(new RegExp(`(${searchCheckInOutData})`, 'gi')).map((text, index) => {
                            if (text.toLowerCase() === searchCheckInOutData.toLowerCase()) {
                                  return <mark key={index}>{text}</mark>;
                            } else {
                               return <span key={index}>{text}</span>;
                                   }
                            })}
                        </span> 
                        : (<span>{CheckInfo.visitor_id}</span>) }
                    </td>
                    <td>
                      { CheckInfo.visitor_name && searchCheckInOutData && CheckInfo.visitor_name.toLowerCase().includes(searchCheckInOutData.toLowerCase()) ? 
                         <span>
                             {CheckInfo.visitor_name.split(new RegExp(`(${searchCheckInOutData})`, 'gi')).map((text, index) => {
                            if (text.toLowerCase() === searchCheckInOutData.toLowerCase()) {
                                  return <mark key={index}>{text}</mark>;
                            } else {
                               return <span key={index}>{text}</span>;
                                   }
                            })}
                        </span> 
                        : (<span>{CheckInfo.visitor_name}</span>)}
                    </td>
                    <td>{CheckInfo.visitor_designation}</td>
                    <td>
                    { CheckInfo.visitor_mobileNo && searchCheckInOutData && CheckInfo.visitor_mobileNo.toLowerCase().includes(searchCheckInOutData.toLowerCase()) ? 
                      <span>
                         {CheckInfo.visitor_mobileNo.split(new RegExp(`(${searchCheckInOutData})`, 'gi')).map((text, index) => {
                            if (text.toLowerCase() === searchCheckInOutData.toLowerCase()) {
                                  return <mark key={index}>{text}</mark>;
                            } else {
                               return <span key={index}>{text}</span>;
                                   }
                            })}
                        </span> 
                        : (<span>{CheckInfo.visitor_mobileNo}</span>) }
                    </td>
                    <td>{new Date(CheckInfo.visit_date).toLocaleDateString('en-GB')}</td>
                    <td>{CheckInfo.visit_startTime+"-"+CheckInfo.visit_endTime}</td>
                    <td>{CheckInfo.allotted_visit_duration}</td>
                    <td>{CheckInfo.checkIn}</td>
                    <td>{CheckInfo.checkOut}</td>
                    <td>{CheckInfo.visitor_status}</td>
                    <td>{
                      (CheckInfo.checkIn!=='' && CheckInfo.checkOut!=='')?
                      (moment(CheckInfo.checkOut, 'HH:mm').diff(moment(CheckInfo.checkIn, 'HH:mm'), 'minutes'))
                      :('')
                    }</td>
                    <td>
                       <div className="icons-container">
                        <div className="icons" onClick={()=>ViewSingleCheckInOutData(CheckInfo._id,"view")}>
                          <MdRemoveRedEye />
                        </div>
                        <div className="icons"  onClick={()=>ViewSingleCheckInOutData(CheckInfo._id,"edit")} >
                          <MdOutlineEdit />
                        </div>
                        <div className="icons"  onClick={()=>deleteSingleCheckInOutData(CheckInfo._id)}>
                          <MdDelete />
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
        { (!isLoading && checkInOutDataShow.length===0) && <p id="loading-text">No Data !</p>}
        <span className="table-data-not-found">
          {
            (!displayData && (<p>No Records Found !</p>))
          }
        </span>

        {(checkInOutData && optionStatus==="view") && (
        <div className="display-single-data">
        <div className="single-data-container">
          <div  className="single-data-close-icon">
            <AiOutlineClose onClick={()=>setCheckInOutData('')} />
          </div>
          <div>
            <h2>Check In/Out Details</h2>
          </div>
          <div className="single-data">
            <h4>Visit Pass ID :</h4>
            <p>{checkInOutData.visitPass_id}</p>
          </div>
          <div className="single-data">
            <h4>Visitor ID :</h4>
            <p>{checkInOutData.visitor_id}</p>
          </div>
          <div className="single-data">
             <h4>Visitor Name :</h4>
            <p>{checkInOutData.visitor_name}</p>
          </div>
          <div className="single-data">
            <h4>Visitor Designation :</h4>
            <p>{checkInOutData.visitor_designation}</p>
          </div>
          <div className="single-data">
            <h4> Visitor MobileNo. :</h4>
            <p>{checkInOutData.visitor_mobileNo}</p>
          </div>
          <div className="single-data">
            <h4>Visit Date :</h4>
            <p>{new Date(checkInOutData.visit_date).toLocaleDateString('en-GB')}</p>
          </div>
          <div className="single-data">
            <h4>Allotted Visit Time :</h4>
            <p>{checkInOutData.visit_startTime+"-"+checkInOutData.visit_endTime}</p>
          </div>
          <div className="single-data">
            <h4>Allotted Visit Duration :</h4>
            <p>{checkInOutData.allotted_visit_duration}</p>
          </div>
          <div className="single-data">
            <h4>Visit Purpose :</h4>
            <p>{checkInOutData.visit_purpose}</p>
          </div>
          <div className="single-data">
            <h4>CheckIn :</h4>
            <p>{checkInOutData.checkIn}</p>
          </div>
          <div className="single-data">
            <h4>CheckOut :</h4>
            <p>{checkInOutData.checkOut}</p>
          </div>
          <div className="single-data">
            <h4>Visit Status :</h4>
            <p>{checkInOutData.visitor_status}</p>
          </div>
          {checkInOutData.checkOut && (<div className="single-data">
            <h4>Visit Duration :</h4>
            <p>{moment(checkInOutData.checkOut, 'HH:mm').diff(moment(checkInOutData.checkIn, 'HH:mm'), 'minutes')}</p>
          </div>)}
        </div>
      </div>
      )}

      { (checkInOutData && optionStatus==="edit") && (
        <div className="update-single-data">
        <div className="update-single-data-container">
           <div  className="single-data-close-icon">
            <AiOutlineClose onClick={()=>{setCheckInOutData(''); setFormErrors({})}} />
          </div>
          <div className="title">
            <h2>Check In/Out Details</h2>
          </div>
          <div className="single-data">
            <label htmlFor="Name">Visitor Name :</label>
            <input className={formErrors.visitor_name ? 'inputError' : 'Visitor_Name'} id="Name" name="visitor_name" type="text"  onChange={handleChange} value={checkInOutData.visitor_name}
            onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} />
          </div>
          <div className="single-data">
            <label htmlFor="Designation">Visitor Designation :</label>
            <input className={formErrors.visitor_designation ? 'inputError' : 'Visitor_Designation'} id="Designation" name="visitor_designation" type="text" onChange={handleChange} value={checkInOutData.visitor_designation} 
            onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} />
          </div>
          <div className="single-data">
            <label htmlFor="Mobile_no">Visitor MobileNo. :</label>
            <input className={formErrors.visitor_mobileNo ? 'inputError' : 'Mobile_Number'} id="Mobile_no" name="visitor_mobileNo" type="text" onChange={handleChange} value={checkInOutData.visitor_mobileNo} 
            onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} />
          </div>
          <div className="single-data">
            <label htmlFor="VisitDate">Visit Date :</label>
            <input className={formErrors.visit_date ? 'inputError' : 'Visitor_Date'} id="VisitDate" name="visit_date" type="date" onChange={handleChange} value={new Date(checkInOutData.visit_date).toISOString().split('T')[0]} 
            onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} />
          </div>
           <div className="single-data">
            <label htmlFor="Visit_StartTime">Allotted Visit Time :</label>
            <div>
             <div onBlur={()=>{onChangeDatetimeBlur(setFormErrors)("visit_startTime", checkInOutData.visit_startTime)}} >
                <Datetime className={formErrors.visit_startTime ? 'inputError' : 'Visit_Start_Time'} id="Visit_StartTime" name="visit_startTime" timeFormat={true} dateFormat={false} inputProps={{ placeholder: '-- : --' }} 
                onChange={(momentObj) => {handleChangeDatetime(momentObj,"visit_startTime")}} value={moment(checkInOutData.visit_startTime,"hh:mm A")} />
              </div>
              <small style={{marginLeft:'50px'}}>to</small>
              <div onBlur={()=>{onChangeDatetimeBlur(setFormErrors)("visit_endTime", checkInOutData.visit_endTime)}} >
                <Datetime className={formErrors.visit_endTime ? 'inputError' : 'Visitor_End_Time'} id="Visitor_EndTime" name="visit_endTime" timeFormat={true} dateFormat={false} inputProps={{ placeholder: '-- : --' }} 
                onChange={(momentObj) => {handleChangeDatetime(momentObj,"visit_endTime")}} value={moment(checkInOutData.visit_endTime,"hh:mm A")}/>
              </div>
            </div>
          </div>
           <div className="single-data">
            <label htmlFor="Alloted_Duration">Alloted Visit Duration :</label>
            <input className={formErrors.allotted_visit_duration ? 'inputError' : 'Alloted_Duration'} id="Alloted_Duration" name="allotted_visit_duration" type="Number" onChange={handleChange} 
            onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} value={checkInOutData.allotted_visit_duration} />
          </div>
          <div className="single-data">
            <label htmlFor="Purpose">Visit Purpose :</label>
            <input className={formErrors.visit_purpose ? 'inputError' : 'Purpose'} id="Purpose" name="visit_purpose" type="text" onChange={handleChange} value={checkInOutData.visit_purpose} 
            onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} />
          </div>
          <div className="single-data">
            <label htmlFor="CheckIn">CheckIn :</label>
             <div onBlur={()=>{onChangeDatetimeBlur(setFormErrors)("checkIn",checkInOutData.checkIn)}} >
              <Datetime  id="CheckIn" name="checkIn" timeFormat={true} dateFormat={false} inputProps={{ placeholder: '-- : --' }} 
              value={moment(checkInOutData.checkIn,"hh:mm A")} onChange={(momentObj) => {handleChangeDatetime(momentObj,"checkIn")}} />
             </div>
          </div>
          <div className="single-data">
            <label htmlFor="CheckOut">CheckOut :</label>
             <div onBlur={()=>{onChangeDatetimeBlur(setFormErrors)("checkOut",checkInOutData.checkOut)}} >
              <Datetime  id="CheckOut" name="checkOut" timeFormat={true} dateFormat={false} inputProps={{ placeholder: '-- : --' }} 
              value={moment(checkInOutData.checkOut,"hh:mm A")} onChange={(momentObj) => {handleChangeDatetime(momentObj,"checkOut")}} />
             </div>
          </div>
          <div className="single-data">
            <label htmlFor="Status">Visit Status :</label>
            <input className={formErrors.visitor_status ? 'inputError' : 'Visitor_ID'} id="Status" name="visitor_status" type="text" onChange={handleChange} 
            value={checkInOutData.visitor_status} />
          </div>
          <button type="submit" onClick={updateSingleCheckInOutData}>Update</button>
        </div>
      </div>
      )}
      </div>
    </div>)
}

export default DisplayCheckInOutData;