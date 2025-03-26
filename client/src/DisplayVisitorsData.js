import { useEffect, useState, useMemo } from "react";
import axios from "axios";
import { MdOutlineEdit } from 'react-icons/md';
import { MdDelete } from 'react-icons/md';
import { MdRemoveRedEye } from 'react-icons/md';
import {AiOutlineClose } from 'react-icons/ai';
import {BiSearchAlt } from 'react-icons/bi';
import "./css/DisplayTable.css";

function DisplayVisitorsData() {

  const [status, setStatus]=useState(0);
  const [optionStatus, setOptionStatus]=useState('');
  const [visitors, setVisitors]=useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const[formErrors, setFormErrors]= useState({});

  const token = localStorage.getItem('jwtToken');
  const headers = useMemo(() => ({
      'Authorization': `Bearer ${token}`
  }), [token]);

  // validate visitor data
  const validation=(name, value)=>{
        const errors={};

        const email_pattern=/^[^\s@]+@[^\s@]+\.[^\s@]{2,4}$/;
        const mobileNo_pattern=/^[0-9\b]+$/;
        const name_pattern=/^[a-zA-Z\s]+$/;

        if(name==="name"){
            if(value.length<1){
                errors.name="name is required"
            }else if(!name_pattern.test(value)) {
                errors.name = "name only contain letters";
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

        if(name==="mobile_no"){
            if(value.length<1){
                errors.mobile_no="mobile number is required"
            }else if(!mobileNo_pattern.test(value)){
                errors.mobile_no="mobile number must be a numeric value"
            }else if(value.length!==10){
                errors.mobile_no="mobile number have 10 digits"
        }}
        
        if(name==="address"){
            if(value.length<1){
                errors.address="address is required"
        }}

        return errors
    }

    const onSubmitValid=(setter)=>(formdata)=>{
      for(const field in formdata) { 
         setter((formErrors)=>{
            return{
                ...formErrors,
                ...validation(field, formdata[field])
            }
        })
    } }

    const onChangeBlur=(setter)=>(e)=>{
      setter((formErrors)=>{
        return{
            ...formErrors,
            ...validation(e.target.name, e.target.value),
        }
      })
    }

    const onChangeFocus=(setter)=>(e)=>{
        
        setter((formErrors)=>{
        delete formErrors[e.target.name]
         return{
             ...formErrors
         }
      })
    }
    

  // get all visitors data
  useEffect(()=>{
       axios.get("http://localhost:4000/api/get/visitors/details",{headers:headers})
      .then(res=> {setVisitors(res.data); setIsLoading(false);})
      .catch(err=>console.log(err))
  },[visitors, headers, isLoading]);
  
  const [visitor, setVisitor]=useState('');

  // get visitor data by id
  const ViewSingleVisitorData = (visitorId, option)=> {

      // set option
      setOptionStatus(option);
  
       axios.get(`http://localhost:4000/api/get/visitors/details/${visitorId}`,{headers:headers})
      .then(res=> {setVisitor(res.data)})
      .catch(err=>console.log(err))

  };


  // handle change visitor data
  const handleChange=(event)=>{

        setVisitor({
            ...visitor,
            [event.target.name]:event.target.value
        });
    };

  
  // update visitor data by id
  const updateSingleVisitorData = ()=> {


      console.log(visitor._id);
      
      onSubmitValid(setFormErrors)(visitor);
    
      console.log(formErrors);

      if(Object.keys(formErrors).length <1){
        
       axios.patch(`http://localhost:4000/api/update/visitors/details/${visitor._id}`,visitor,{headers:headers})
      .then(res=> {
        console.log(res.data);
        if(res.data==="Email Already Exist" || res.data==="Mobile Number Already Exist")
        {
          alert(res.data)
        }else{
        setVisitor('');
        setOptionStatus('') }})
      .catch(err=>console.log(err))
      }
    };

    
    // delete visitor data by id
     const deleteSingleVisitorData =(visitorID)=>{
 
      console.log(visitorID);
       axios.delete(`http://localhost:4000/api/delete/visitors/details/${visitorID}`,{headers:headers})
      .then(res=> {
          console.log(res.data);
          setVisitor('');
          setOptionStatus('');})
      .catch(err=>console.log(err))
      
    };
  
  const [searchDataVisitors, setSearchDataVisitors]=useState('');

  // handle change search text 
  const searchVisitor=(e)=>{
      setSearchDataVisitors(e.target.value);
  }

  const [displayData, setDisplayData] = useState([]);
  useEffect(() => {

    if(status){
       
        const keys=["visitor_id","mobile_no","name"]
        
        //filter visior data by search text
        const filterVisitor = visitors.filter((item) => keys.some((key) => item[key].toLowerCase().includes(searchDataVisitors.toLowerCase())));
        if(filterVisitor.length>0){
  
        setDisplayData(filterVisitor)
      }
        else{  
          setDisplayData('')
        }
  
      }
         
    else{
       setDisplayData(visitors);
    }
  }, [status, visitors, searchDataVisitors]);


  //set status to show all visitors data or filtered visitors data
  useEffect(() => {
  if (searchDataVisitors === '') {
    setStatus(0);
  } else {
    setStatus(1);
  }
}, [searchDataVisitors]);


    return (
       <div className="display-table">
        <div className="table-header">
        <div className="table-search-container">
          <input type="text" id="visitorSearch" placeholder="Enter Visitor id / Mobile no / Name" className="visitor-search"
            onChange={searchVisitor}></input>
        </div>
        <div className="search-icon">
          <BiSearchAlt size={22} />
        </div>
        <div className="table-title2">
          <h3>Visitor's Details</h3>
        </div>
        </div>
        <div className="table-container">
          <div className="table-data">
          <table>
            <thead>
                <tr>
                    <th>SNo.</th>
                    <th>Visitor ID</th>
                    <th>Name</th>
                    <th>Designation</th>
                    <th>Mobile no.</th>
                    <th>Action</th>
                </tr>
            </thead>
            { !isLoading && (<tbody>
            {  
             
              displayData && displayData.map((Visitor,index)=>{
                  
                return(
                  <tr key={index}>
                    <td>{index+1}</td>
                    <td>
                     { Visitor.visitor_id && searchDataVisitors && Visitor.visitor_id.toLowerCase().includes(searchDataVisitors.toLowerCase()) ? 
                         <span>
                             {Visitor.visitor_id.split(new RegExp(`(${searchDataVisitors})`, 'gi')).map((text, index) => {
                            if (text.toLowerCase() === searchDataVisitors.toLowerCase()) {
                                  return <mark key={index}>{text}</mark>;
                            } else {
                               return <span key={index}>{text}</span>;
                                   }
                            })}
                        </span> 
                        : (<span>{Visitor.visitor_id}</span>) }
                    </td>
                    <td>
                      { Visitor.name && searchDataVisitors && Visitor.name.toLowerCase().includes(searchDataVisitors.toLowerCase()) ? 
                         <span>
                             {Visitor.name.split(new RegExp(`(${searchDataVisitors})`, 'gi')).map((text, index) => {
                            if (text.toLowerCase() === searchDataVisitors.toLowerCase()) {
                                  return <mark key={index}>{text}</mark>;
                            } else {
                               return <span key={index}>{text}</span>;
                                   }
                            })}
                        </span> 
                        : (<span>{Visitor.name}</span>)}
                    </td>
                    <td>{Visitor.designation}</td>
                    <td>
                    { Visitor.mobile_no && searchDataVisitors && Visitor.mobile_no.toLowerCase().includes(searchDataVisitors.toLowerCase()) ? 
                      <span>
                         {Visitor.mobile_no.split(new RegExp(`(${searchDataVisitors})`, 'gi')).map((text, index) => {
                            if (text.toLowerCase() === searchDataVisitors.toLowerCase()) {
                                  return <mark key={index}>{text}</mark>;
                            } else {
                               return <span key={index}>{text}</span>;
                                   }
                            })}
                        </span> 
                        : (<span>{Visitor.mobile_no}</span>) }
                    </td>
                    <td>
                       <div className="icons-container">
                        <div className="icons" onClick={()=>ViewSingleVisitorData(Visitor._id,"view")}>
                          <MdRemoveRedEye />
                        </div>
                        <div className="icons"  onClick={()=>ViewSingleVisitorData(Visitor._id,"edit")} >
                          <MdOutlineEdit />
                        </div>
                        <div className="icons"  onClick={()=>deleteSingleVisitorData(Visitor._id)}>
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
        { isLoading &&(<p id="loading-text">Loading...</p>) }
        { (!isLoading && visitors.length===0) && <p id="loading-text">No Data !</p>}
        <span className="table-data-not-found">
          {
            (!displayData && (<p>No Records Found !</p>))
          }
        </span>

        {(visitor && optionStatus==="view") && (
        <div className="display-single-data">
        <div className="single-data-container">
          <div  className="single-data-close-icon">
            <AiOutlineClose onClick={()=>setVisitor('')} />
          </div>
          <div>
            <h2>Visitor Details</h2>
          </div>
          <div className="single-data">
            <h4>Visitor ID :</h4>
            <p>{visitor.visitor_id}</p>
          </div>
          <div className="single-data">
             <h4>Name :</h4>
            <p>{visitor.name}</p>
          </div>
          <div className="single-data">
            <h4>Age :</h4>
            <p>{visitor.age}</p>
          </div>
          <div className="single-data">
            <h4>Gender :</h4>
            <p>{visitor.gender}</p>
          </div>
          <div className="single-data">
            <h4>Designation :</h4>
            <p>{visitor.designation}</p>
          </div>
          <div className="single-data">
            <h4>Mobile No :</h4>
            <p>{visitor.mobile_no}</p>
          </div>
          <div className="single-data">
            <h4>Email :</h4>
            <p>{visitor.email}</p>
          </div>
          <div className="single-data">
            <h4>Address :</h4>
            <p>{visitor.address}</p>
          </div>
        </div>
      </div>
      )}
      { (visitor && optionStatus==="edit") && (
        <div className="update-single-data">
        <div className="update-single-data-container">
           <div  className="single-data-close-icon">
            <AiOutlineClose onClick={()=>{setVisitor(''); setFormErrors({})}} />
          </div>
          <div className="title">
            <h2>Visitor Details</h2>
          </div>
          <div className="single-data">
            <label htmlFor="Name">Name :</label>
            <input id="Name" name="name" type="text" className={formErrors.name ? 'inputError' : 'Name'}  onChange={handleChange} onBlur={onChangeBlur(setFormErrors)} 
            onFocus={onChangeFocus(setFormErrors)} value={visitor.name}/>
          </div>
          <div className="single-data">
            <label htmlFor="Age">Age :</label>
            <input id="Age" name="age" type="number" onChange={handleChange} className={formErrors.age ? 'inputError' : 'Email'} onBlur={onChangeBlur(setFormErrors)} 
            onFocus={onChangeFocus(setFormErrors)} value={visitor.age} />
          </div>
          
          <div className="radio-btn-container">
              <div className='radio-btn'>

                <label htmlFor='Male'>Gender</label>
                       
                <input id="Male" name="gender" type="radio" value="male" onChange={handleChange} checked={visitor.gender === "male"} />
                <label style={{fontWeight:500, fontSize:14}} htmlFor="Male">Male</label>
                      
                <input id="Female" name="gender" type="radio" onChange={handleChange} value="female" checked={visitor.gender === "female"} />
                <label style={{fontWeight:500, fontSize:14}} htmlFor="Female">Female</label>
                     
                <input id="Other" name="gender" type="radio" onChange={handleChange} value="other" checked={visitor.gender === "other"} />
                <label style={{fontWeight:500, fontSize:14}} htmlFor="Other">Other</label>
              </div>
            </div>
          <div className="single-data">
            <label htmlFor="Designation">Designation :</label>
            <input id="Designation" name="designation" type="text"  className={formErrors.designation ? 'inputError' : 'Designation'} onChange={handleChange} onBlur={onChangeBlur(setFormErrors)} 
            onFocus={onChangeFocus(setFormErrors)} value={visitor.designation} />
          </div>
          <div className="single-data">
            <label htmlFor="Mobile_no">Mobile no :</label>
            <input id="Mobile_no" name="mobile_no" type="text" className={formErrors.mobile_no ? 'inputError' : 'Mobile_Number'} onChange={handleChange} onBlur={onChangeBlur(setFormErrors)} 
            onFocus={onChangeFocus(setFormErrors)} value={visitor.mobile_no} />
          </div>
          <div className="single-data">
            <label htmlFor="Email">Email <small>(optional)</small> :</label>
            <input id="Email" name="email" type="email" className={formErrors.email ? 'inputError' : 'Email'} onChange={handleChange} onBlur={onChangeBlur(setFormErrors)} 
            onFocus={onChangeFocus(setFormErrors)} value={visitor.email} />
          </div>
          <div className="single-data">
            <label htmlFor="Address">Address :</label>
             <textarea id="Address" name="address" type="text" className={formErrors.address ? 'inputError' : 'Address'}  onChange={handleChange} onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} value={visitor.address} />
          </div>
          <button type="submit" onClick={updateSingleVisitorData}>Update</button>
        </div>
      </div>
      )}
      </div>
      </div>
      
    )
}

export default DisplayVisitorsData;