import { useState } from 'react';
import axios from 'axios';
import "./css/CheckInOut.css";
import { AiFillPrinter } from 'react-icons/ai';
import { useNavigate } from "react-router-dom";

function CheckInOut({handleChangeVisitorPass, handleChangeDashboardVisitorData, handleChangeDashboardPreregisterData}){
    
    const[visitPassID, setVisitPassID]= useState('');
    const[formErrors, setFormErrors]= useState({});

    const token = localStorage.getItem('jwtToken');
    const headers = { 'Authorization': `Bearer ${token}`};

    const navigate = useNavigate();
   
    // handle change visitorPass ID
    const handleChange=(e)=>{
       setVisitPassID(e.target.value)
    };

    // validate visitorPass ID
    const validation=(name, value)=>{
    
    const errors={};
    const id_pattern=/^[a-zA-Z0-9\s]+$/;
        
    if(name==="visitPassID"){
       if(value.length<1){
            errors.visitPassID="visit pass id is required"
        }else if(!id_pattern.test(value)) {
            errors.visitPassID = "visit pass id only contain letters & numbers";
        }else if(value.length!==8){
           errors.visitPassID="visit pass id must be 8 characters"
        }
    }

        return errors
    }

    // validate visitorPass ID during submit
    const onSubmitValid=(setter)=>(visitID)=>{
         setter((formErrors)=>{
            return{
                ...formErrors,
                ...validation("visitPassID", visitID)
            }
        })
     }

    // validate visitorPass ID during blur
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
    
    // post visitorPass ID
    const handleSubmit = async(e) => {

        e.preventDefault();
        console.log(visitPassID); 

        onSubmitValid(setFormErrors)(visitPassID)
        console.log(formErrors);
        
        if(Object.keys(formErrors).length < 1){

        await axios.post("http://localhost:4000/api/check/in/out",{visitPassID:visitPassID},{headers:headers})
        .then(res=> {

            console.log(res);
            alert(res.data);
            if(res.data!=='Invalid Visitor Pass ID')
            {
               setVisitPassID('');
               setFormErrors({}); }
            })
        .catch(err=>console.log(err))
    } };

    // get visitorPass details by visitorPass ID for Print
    const handlePrintClick=async(e)=>{
        await axios.get(`http://localhost:4000/api/check/in/out/pass/${visitPassID}`,{headers:headers})
        .then(res=> {
            console.log(res);

            if(res.data==="Invalid Visit Pass ID"){
                alert(res.data);
            }else{
              handleChangeVisitorPass(res.data);
              navigate('/viztrack/visitor/pass') 
              setVisitPassID('');
              setFormErrors({});
            }
        })
        .catch(err=>console.log(err))
    }

    return(
        <div>
         <div className="checkInOut">
          <div className="checkInOut-container">
            <div className="title">
                <h2>Check In / Out</h2>
            </div>
            <form onSubmit={handleSubmit}  className="checkInOut-form">
             <div className="checkInOut-details">
                <div className="input-container">
                    <label  htmlFor="VisitPassID">Visit Pass ID</label>
                    <input className={formErrors.visitPassID ? 'inputError' : 'VisitPassID'} id="visitPass_ID" name="visitPassID" type="text" onChange={handleChange} 
                     onBlur={onChangeBlur(setFormErrors)} onFocus={onChangeFocus(setFormErrors)} value={visitPassID} />
                    {(formErrors.visitPassID && <p>{formErrors.visitPassID}</p>)}
                    <div className='print-icon' onClick={handlePrintClick}>
                        <AiFillPrinter size={22} />
                    </div>
                </div>
                <div>
                 <button onClick={handleSubmit} type="submit">Submit</button>
                </div>
              </div>
            </form>
            </div>    
        </div>
        <div className='redirect-table-btns'>
            <div className="view-table-btn">
                <button  onClick={()=> navigate("/viztrack/meeting/details")} type="submit">View Meetings Details</button>
            </div>
            <div className="view-table-btn">
                <button  onClick={()=> {handleChangeDashboardPreregisterData(''); navigate("/viztrack/preregistration/details")}} type="submit">View<br/>Pre-Registrations Details</button>
            </div>
            <div className="view-table-btn">
                <button  onClick={()=> {handleChangeDashboardVisitorData('');  navigate("/viztrack/check/in/out/details")}} type="submit">View<br/>Check In/Out Details</button>
            </div>
        </div>
    </div>);
 };

export default CheckInOut;