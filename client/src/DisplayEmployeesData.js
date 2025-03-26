import { useEffect, useState, useRef, useMemo } from "react";
import axios from "axios";
import { MdOutlineEdit } from 'react-icons/md';
import { MdDelete } from 'react-icons/md';
import { MdRemoveRedEye } from 'react-icons/md';
import {AiOutlineClose } from 'react-icons/ai';
import {BiSearchAlt } from 'react-icons/bi';
import "./css/DisplayTable.css"
import { IoCameraOutline } from 'react-icons/io5';
import { MdDateRange } from 'react-icons/md';
import FadeLoader from "react-spinners/FadeLoader";

function DisplayEmployeesData({handleDashboardChange, handleEmpShowData}) {
  
  const [status, setStatus]=useState(0);
  const [optionStatus, setOptionStatus]=useState('');

  const [imgChange, setImgChange]=useState('');
  const [employees, setEmployees]=useState([]);
  const [presentEmployees, setPresentEmployees]=useState([]);
  const [absentEmployees, setAbsentEmployees]=useState([]);
  const [leaveEmployees, setLeaveEmployees]=useState([]);
  const [onsiteEmployees, setOnsiteEmployees]=useState([]);
  const [employeesDataShow, setEmployeesDataShow]=useState([]);

  const [imageData, setImageData] = useState('');
  const[profileImgUrl, setProfileImgUrl]= useState('');
  const[updateLoading, setUpdateLoading]= useState(false);
  const profile=useRef(null)

  const [checkDate, setCheckDate]=useState(new Date());
  const [isLoading, setIsLoading] = useState(true);
   const[formErrors, setFormErrors]= useState({});

  const token = localStorage.getItem('jwtToken');
  const headers = useMemo(() => ({
      'Authorization': `Bearer ${token}`
  }), [token]);

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

        if(name==="mobile_no"){
            if(value.length<1){
                errors.mobile_no="mobile number is required"
            }else if(!mobileNo_pattern.test(value)){
                errors.mobile_no="mobile number must be a numeric value"
            }else if(value.length!==10){
                errors.mobile_no="mobile number must have 10 digits"
        } }
        
        if(name==="address"){
            if(value.length<1){
                errors.address="address is required"
        } }

        if(name==="applied_leave"){
            if(value.length<1){
                 errors.applied_leave="applied leave is required"
        } }

        
        if(employee.applied_leave==="yes"){

            if(name==="leave_status"){
                if(value==="Choose Status"){
                     errors.leave_status="leave status is required"
            } }
        
            if(name==="leave_start"){
             if(value.length<1){
                errors.leave_start="leave start date is required"
            } }
        
            if(name==="leave_end"){
                if(value.length<1){
                    errors.leave_end="leave end date is required"
                }else if(employee.leave_start && (new Date(employee.leave_start).setHours(0,0,0,0) > new Date(employee.leave_end).setHours(0,0,0,0))){
                  errors.leave_end="end date lesser than start date"
             } }
       }


        if(name==="onsite"){
        if(value.length<1){
            errors.onsite="onsite data is required"
        }}
        

        if(employee.onsite==="yes"){
        
        if(name==="onsite_start"){
            if(!value){
                errors.onsite_start="onsite start date is required"
        }}
        
        if(name==="onsite_end"){
            if(!value){
             errors.onsite_end="onsite end date is required"
              }else if(employee.onsite_start && (new Date(employee.onsite_start).setHours(0,0,0,0) > new Date(employee.onsite_end).setHours(0,0,0,0))){
                errors.onsite_end="end date lesser than start date"
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

    // remove employee profile image error during blur
    const onChangeProfileFocus=(setter)=>(name)=>{
        setter((formErrors)=>{
        delete formErrors[name]
         return{
             ...formErrors
         }
      })
    }


  // get all employee data
  useEffect(()=>{
       axios.get("http://localhost:4000/api/get/employees/details",{headers:headers})
      .then(res=> {setEmployees(res.data); setIsLoading(false)})
      .catch(err=>console.log(err))
  },[employees, headers, isLoading]);
  
  
  // get employee data by id
  const [employee, setEmployee]=useState('');

  const ViewSingleEmployeeData = (employeeId, option)=> {

      //set option
      setOptionStatus(option);
      
      axios.get(`http://localhost:4000/api/get/employees/details/${employeeId}`,{headers:headers})
      .then(res=> {
        console.log(res);
        setEmployee(res.data.employee_data);
        setImageData(res.data.profile_img_data);
        setProfileImgUrl(res.data.profile_img_data)})
      .catch(err=>console.log(err))

  };


  // handle changes employee data
  const handleChange=(event)=>{

        setEmployee({
            ...employee,
            [event.target.name]:event.target.value
        });
    };


  // handle change employee profile image
  const handleImageChange = () => {

        onChangeProfileBlur(setFormErrors)("profile","pic")

        setImgChange('yes')
        const file=profile.current.files[0]
        setImageData(file);

        const reader = new FileReader();
        reader.onloadend = () => {
        setProfileImgUrl(reader.result.split(',')[1]); // Split to remove the data URI header
    };

      if (file) {
        reader.readAsDataURL(file);
      }
  };
    
  
  // update employee data by id
  const updateSingleEmployeeData = async()=> {

    onSubmitValid(setFormErrors)(employee)
    onChangeProfileBlur(setFormErrors)("profile","pic")

   if(Object.keys(formErrors).length <1){

    if(imgChange==='yes'){

     setUpdateLoading(true)

     const formData =new FormData()
      formData.append("profileImg", imageData)
      Object.keys(employee).forEach((key) => {
      formData.append(key, employee[key]);
    });
     
      console.log(Object.fromEntries(formData));
      
       await axios.patch(`http://localhost:4000/api/update/employees/details/and/profile/${employee._id}`,formData,{headers:headers})
      .then(res=> {
        console.log( res.data);
        setUpdateLoading(false);
        if(res.data==="Email Already Exist" || res.data==="Mobile Number Already Exist")
        {
          alert(res.data)
        }else{
        alert("Employee Details Updated Successfully!");
        setEmployee('');
        setOptionStatus('');
        setImageData('');
        setProfileImgUrl('');
        setImgChange('')
        setFormErrors({}) } })
      .catch(err=>console.log(err))
    }else{
       
       console.log(employee);
     
      await axios.patch(`http://localhost:4000/api/update/employees/details/${employee._id}`,employee,{headers:headers})
      .then(res=> {
        console.log(res.data);
        if(res.data==="Email Already Exist" || res.data==="Mobile Number Already Exist")
        {
          alert(res.data)
        }else{
        alert("Employee Details Updated Successfully!");
        setEmployee('');
        setOptionStatus('');
        setImgChange(''); 
        setFormErrors({}) }})
      .catch(err=>console.log(err))
    }
   }
  };

    
    // delete employee data by id
     const deleteSingleEmployeeData =(employeeID)=>{
 
      console.log(employeeID);
       axios.delete(`http://localhost:4000/api/delete/employees/details/${employeeID}`,{headers:headers})
      .then(res=> {
          console.log(res.data);
          setEmployee('');
          setOptionStatus('');})
      .catch(err=>console.log(err))
      
    };
  
  const [searchDataEmployees, setSearchDataEmployees]=useState('');
  
  // handle change search text
  const searchEmployee=(e)=>{
      setSearchDataEmployees(e.target.value);
  }

  //handle change date
  const changeCheckDate=(e)=>{
    setCheckDate(e.target.value)
  }


  const [displayData, setDisplayData] = useState([]);
  useEffect(() => {

    // Determine the data to display
    if(handleEmpShowData==='Total Employees'|| handleEmpShowData===''){
        setEmployeesDataShow(employees)    
               
    }else if(handleEmpShowData==='Present Employees'){
        setEmployeesDataShow(presentEmployees)    

    }else if(handleEmpShowData==='Absent Employees'){
        setEmployeesDataShow(absentEmployees)    

    }else if(handleEmpShowData==='Employees on Leave'){
        setEmployeesDataShow(leaveEmployees)    

    }else if(handleEmpShowData==='Employees on Onsite'){
        setEmployeesDataShow(onsiteEmployees)    
    }

    if(status){
       
        const keys=["employee_id","mobile_no","name"]

        //filter employee by search text
        const filterEmployee = employeesDataShow.filter((item) => keys.some((key) => item[key].toLowerCase().includes(searchDataEmployees.toLowerCase())));
        if(filterEmployee.length>0){
  
        setDisplayData(filterEmployee)
      }
        else{  
          setDisplayData('')
        }
  
      }
         
    else{
       setDisplayData(employeesDataShow);
    }
  },  [status, employees, searchDataEmployees, presentEmployees, absentEmployees, leaveEmployees,
      onsiteEmployees, employeesDataShow, handleEmpShowData]);

  
  // filter employee data by present, absent, leave, onsite
   useEffect(() => {

    const PresentEmps = [];
    const AbsentEmps = [];

    const LeaveEmps = employees.filter((empData)=>(empData.applied_leave === "yes" && empData.leave_status === "Approved"));
    const OnsiteEmps = employees.filter((empData)=> (empData.onsite === "yes"));
    
    employees.filter(Employee => {
        let EmpAvailable = false;

        const today=new Date().setHours(0, 0, 0, 0)
        
        // check availability
        if (
          (Employee.applied_leave === "yes" && new Date(Employee.leave_start).setHours(0, 0, 0, 0) <=today &&
            new Date(Employee.leave_end).setHours(0, 0, 0, 0) >= today) ||
          (Employee.onsite === "yes" && new Date(Employee.onsite_start).setHours(0, 0, 0, 0) <= today &&
            new Date(Employee.onsite_end).setHours(0, 0, 0, 0) >= today)
         ) {
           EmpAvailable = false;
        } else {
           EmpAvailable = true;
        }

        if (EmpAvailable) {
           PresentEmps.push(Employee);
        } else {
           AbsentEmps.push(Employee);
        }

    }); 

    setPresentEmployees(PresentEmps)
    setAbsentEmployees(AbsentEmps)
    setLeaveEmployees(LeaveEmps)
    setOnsiteEmployees(OnsiteEmps)

    // set count
    const formData = {
      TotalEmpCount: employees.length,
      PresentEmpCount: PresentEmps.length,
      AbsentEmpCount: AbsentEmps.length,
      LeaveEmpCount: LeaveEmps.length,
      OnsiteEmpCount: OnsiteEmps.length
    };
  
    handleDashboardChange(formData);
   
  },[employees]);


  //set status to Show all employee data or filtered employee data
  useEffect(() => {
  if (searchDataEmployees === '') {
    setStatus(0);
  } else {
    setStatus(1);
  }
}, [searchDataEmployees]);


    return (
       <div className="display-table">
        <div className="table-header">
        <div className="table-search-container">
          <input type="text" id="employeeSearch" placeholder="Enter Employee id / Mobile no / Name" className="visitor-search"
             autoComplete="off" onChange={searchEmployee} value={searchDataEmployees}></input>
        </div>
        <div className="search-icon">
          <BiSearchAlt size={22} />
        </div>
        <div className="table-title">
           {(handleEmpShowData!=='') ? (<h3>{handleEmpShowData}</h3>):(<h3>Employee's Details</h3>)}
        </div>
        <div className="inputDate-container">
          {(handleEmpShowData!=='') ? (
          <div className="date">
            <MdDateRange size={20}/>
            <p>{new Date().toLocaleDateString('en-GB')}</p>
          </div>) :
            (<input type="date" className="emp_avail_date" name="checkDate" onChange={changeCheckDate} value={new Date(checkDate).toISOString().split('T')[0]}/>) }
        </div>
        </div>
        <div className="table-container">
          <div className="table-data">
          <table>
            <thead>
                <tr>
                    <th>SNo.</th>
                    <th>Employee ID</th>
                    <th>Name</th>
                    <th>Designation</th>
                    <th>Department</th>
                    <th>Mobile no.</th>
                    <th>Email</th>
                    {handleEmpShowData==='' && <th>Availability</th>}
                    <th>Action</th>
                </tr>
            </thead>
          { !isLoading && (          
            <tbody>
            {  
              displayData && displayData.map((Employee,index)=>{
                  
                return(
                  <tr key={index}>
                    <td>{index+1}</td>
                    <td>
                     { Employee.employee_id && searchDataEmployees && Employee.employee_id.toLowerCase().includes(searchDataEmployees.toLowerCase()) ? 
                         <span>
                             {Employee.employee_id.split(new RegExp(`(${searchDataEmployees})`, 'gi')).map((text, index) => {
                            if (text.toLowerCase() === searchDataEmployees.toLowerCase()) {
                                  return <mark key={index}>{text}</mark>;
                            } else {
                               return <span key={index}>{text}</span>;
                                   }
                            })}
                        </span> 
                        : (<span>{Employee.employee_id}</span>) }
                    </td>
                    <td>
                      {  Employee.name && searchDataEmployees && Employee.name.toLowerCase().includes(searchDataEmployees.toLowerCase()) ? 
                         <span>
                             {Employee.name.split(new RegExp(`(${searchDataEmployees})`, 'gi')).map((text, index) => {
                            if (text.toLowerCase() === searchDataEmployees.toLowerCase()) {
                                  return <mark key={index}>{text}</mark>;
                            } else {
                               return <span key={index}>{text}</span>;
                                   }
                            })}
                        </span> 
                        : (<span>{Employee.name}</span>)}
                    </td>
                    <td>{Employee.designation}</td>
                    <td>{Employee.department}</td>
                    <td>
                    { Employee.mobile_no && searchDataEmployees && Employee.mobile_no.toLowerCase().includes(searchDataEmployees.toLowerCase()) ? 
                      <span>
                         {Employee.mobile_no.split(new RegExp(`(${searchDataEmployees})`, 'gi')).map((text, index) => {
                            if (text.toLowerCase() === searchDataEmployees.toLowerCase()) {
                                  return <mark key={index}>{text}</mark>;
                            } else {
                               return <span key={index}>{text}</span>;
                                   }
                            })}
                        </span> 
                        : (<span>{Employee.mobile_no}</span>) }
                    </td>
                    <td>{Employee.email}</td>
                     {handleEmpShowData==='' && ((Employee.applied_leave === "yes" ||  Employee.onsite === "yes") ? (
                        
                      ( ((Employee.applied_leave === "yes")?
                        ((new Date(Employee.leave_start).setHours(0, 0, 0, 0)<=new Date(checkDate).setHours(0, 0, 0, 0)) &&  
                        (new Date(Employee.leave_end).setHours(0, 0, 0, 0)>=new Date(checkDate).setHours(0, 0, 0, 0))): false) ||
                        
                        ((Employee.onsite === "yes")?
                        ((new Date(Employee.onsite_start).setHours(0, 0, 0, 0)<=new Date(checkDate).setHours(0, 0, 0, 0)) &&  
                        (new Date(Employee.onsite_end).setHours(0, 0, 0, 0)>=new Date(checkDate).setHours(0, 0, 0, 0))): false) )?
                        
                        (<td>{"no"}</td>):(<td>{"yes"}</td>)
                     
                      ) : (<td>{"yes"}</td>) ) }
                    <td>
                       <div className="icons-container">
                        <div className="icons" onClick={()=>ViewSingleEmployeeData(Employee._id,"view")}>
                          <MdRemoveRedEye />
                        </div>
                        <div className="icons"  onClick={()=>ViewSingleEmployeeData(Employee._id,"edit")} >
                          <MdOutlineEdit />
                        </div>
                        <div className="icons"  onClick={()=>deleteSingleEmployeeData(Employee._id)}>
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
        {isLoading &&  (<p id="loading-text">Loading...</p>)}
        { (!isLoading && employeesDataShow.length===0) &&  (<p id="loading-text">No Data !</p>)}
        <span className="table-data-not-found">
          {
            (!displayData && (<p>No Records Found !</p>))
          }
        </span>

        {((employee && imageData) && optionStatus==="view") && (
        <div className="display-single-data">
        <div className="single-data-container">
          <div  className="single-data-close-icon">
            <AiOutlineClose onClick={()=>setEmployee('')} />
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
          <br />
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
            <h4>Onsite Duration:</h4>
            <p>{new Date(employee.onsite_start).toLocaleDateString('en-GB')+" to "+new Date(employee.onsite_end).toLocaleDateString('en-GB')}</p>
          </div>)}
          <br />
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
      </div>
      )}

      { (employee && optionStatus==="edit") && (
        <div className="update-single-data">
        <div className="update-single-data-container">
           <div  className="single-data-close-icon">
            <AiOutlineClose onClick={()=>{setEmployee(''); setFormErrors({})}} />
          </div>
          <div className="title">
            <h2>Employee Details</h2>
          </div>
          <div className="input-container">
            <div className='profile-pic-container'>
                <img src={`data:image/jpeg;base64,${profileImgUrl}`}  alt="Blank Profile" id="profile-img"/>
                <input id="Profile" type="file"  accept="image/*" onChange={handleImageChange} ref={profile}
                onClick={()=>{onChangeProfileBlur(setFormErrors)("profile","pic")}} />
                <label htmlFor="Profile" id="pic-upload-btn"><IoCameraOutline size={20}/></label>
            </div>
            </div>
          <div className="single-data">
            <label htmlFor="Name">Name :</label>
            <input className={formErrors.name ? 'inputError' : 'Name'} id="Name" name="name" type="text"  onChange={handleChange} value={employee.name}
             onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} />
          </div>
          <div className="single-data">
            <label htmlFor="Age">Age :</label>
            <input className={formErrors.age ? 'inputError' : 'Age'} id="Age" name="age" type="number" onChange={handleChange} value={employee.age} 
             onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} />
          </div>
          <div className="radio-btn-container">
              <div className='radio-btn'>

                        <label htmlFor='Male'>Gender</label>
                       
                        <input id="Male" name="gender" type="radio" value="male" onChange={handleChange} checked={employee.gender === "male"} 
                         onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} />
                        <label style={{fontWeight:500, fontSize:14}} htmlFor="Male">Male</label>
                      
                        <input id="Female" name="gender" type="radio" onChange={handleChange} value="female" checked={employee.gender === "female"} 
                         onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} />
                        <label style={{fontWeight:500, fontSize:14}} htmlFor="Female">Female</label>
                     
                        <input id="Other" name="gender" type="radio" onChange={handleChange} value="other" checked={employee.gender === "other"} 
                         onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} />
                        <label style={{fontWeight:500, fontSize:14}} htmlFor="Other">Other</label>
                </div>
            </div>
          <div className="single-data">
            <label htmlFor="Designation">Designation :</label>
            <input className={formErrors.designation ? 'inputError' : 'Designation'} id="Designation" name="designation" type="text" onChange={handleChange} value={employee.designation} 
             onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} />
          </div>
          <div className="single-data">
            <label htmlFor="Department">Department :</label>
            <input className={formErrors.department ? 'inputError' : 'Department'} id="Department" name="department" type="text" onChange={handleChange} value={employee.department} 
             onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} />
          </div>
          <div className="single-data">
            <label htmlFor="Mobile_no">Mobile no :</label>
            <input className={formErrors.mobile_no ? 'inputError' : 'Mobile_Number'} id="Mobile_no" name="mobile_no" type="text" onChange={handleChange} value={employee.mobile_no} 
             onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} />
          </div>
          <div className="single-data">
            <label htmlFor="Email">Email :</label>
            <input className={formErrors.email ? 'inputError' : 'Email'} id="Email" name="email" type="email" onChange={handleChange} value={employee.email} 
             onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} />
          </div>
          <div className="single-data">
            <label htmlFor="Address">Address :</label>
             <textarea className={formErrors.address ? 'inputError' : 'Address'} id="Address" name="address" type="text" onChange={handleChange} value={employee.address} 
              onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} />
          </div>
           <div className="single-data">
                 <div className="radio-btn-container">
                 <div className='radio-btn'>
                    <label htmlFor='Leave-Yes'>Applied Leave :</label>
                
                    <input id="Leave-Yes" name="applied_leave" type="radio" value="yes" onChange={handleChange} checked={employee.applied_leave === "yes"} 
                     onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} />
                    <label style={{fontWeight:500}} htmlFor="Leave-Yes">Yes</label>
               
                    <input id="Leave-No" name="applied_leave" type="radio" onChange={handleChange} value="no" checked={employee.applied_leave === "no"} 
                     onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} />
                    <label style={{fontWeight:500}}  htmlFor="Leave-No">No</label>
                  
                </div>
                </div>
                </div>
                {employee.applied_leave === "yes" && 
               <div className="single-data">
                  <div className="leave-info">
                  <div className="input-container">
                    <label htmlFor="leaveStatus">Leave Status</label>
                    <select className={formErrors.leave_status ? 'inputError' : 'leave_Status'} id="leaveStatus" name="leave_status" onChange={handleChange} value={employee.leave_status}
                     onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)}>
                        <option disabled hidden>Choose Status</option>
                        <option value="Waiting for Approval">Waiting for Approval</option>
                        <option value="Approved">Approved</option>
                        <option value="Rejected">Rejected</option>
                    </select>
                </div>
                <div className="input-container">
                    <label htmlFor="Leave-Start">Leave Start Date</label>
                    <input className={formErrors.leave_start ? 'inputError' : 'leave_Start'} id="Onsite-Start" name="leave_start" type="date" onChange={handleChange} value={employee.leave_start} 
                     onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)}/>
                </div>
                <div className="input-container">
                    <label htmlFor="Leave-End">Leave End Date</label>
                    <input className={formErrors.leave_end ? 'inputError' : 'leave_End'} id="Leave-End" name="leave_end" type="date" onChange={handleChange} value={employee.leave_end} 
                     onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} />
                </div>
                </div>
                </div>}
                <div className='single-data'>
                <div className="radio-btn-container">
                  <div className='radio-btn'>
                    <label htmlFor='Onsite-Yes'>Allocated to Onsite Project :</label>
                     
                        <input id="Onsite-Yes" name="onsite" type="radio" value="yes" onChange={handleChange} checked={employee.onsite === "yes"} 
                         onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} />
                        <label style={{fontWeight:500}} htmlFor="Onsite-Yes">Yes</label>
                    
                        <input id="Onsite-No" name="onsite" type="radio" onChange={handleChange} value="no" checked={employee.onsite === "no"} 
                         onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} />
                        <label style={{fontWeight:500}} htmlFor="Onsite-No">No</label>
                </div>
                </div>
                </div>
                {  employee.onsite === "yes" && 
                <div className="single-data">
                <div className='onsite-duration'>
                <div className="input-container">
                    <label htmlFor="Onsite-Start">Onsite Start Date</label>
                    <div>
                    <input className={formErrors.onsite_start ? 'inputError' : 'Onsite_Start'} id="Onsite-Start" name="onsite_start" type="date" onChange={handleChange} value={employee.onsite_start} 
                     onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} />
                    </div>
                </div>
                <div className="input-container">
                    <label htmlFor="Onsite-End">Onsite End Date</label>
                    <div>
                    <input className={formErrors.onsite_end ? 'inputError' : 'Onsite_End'} id="Onsite-End" name="onsite_end" type="date" onChange={handleChange} value={employee.onsite_end} 
                     onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)}/>
                    </div>
                </div>
                </div>
                </div>}
          <button type="submit" onClick={updateSingleEmployeeData}>Update</button>
        </div>
         <div className='Loader'>
             <FadeLoader color={'#5d8ee7'} loading={updateLoading} size={50} />
          </div>
      </div>
      )}
      </div>
      </div>
    )
}

export default DisplayEmployeesData;