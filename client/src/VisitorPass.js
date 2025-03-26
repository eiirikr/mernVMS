import {useRef} from 'react';
import {useReactToPrint} from 'react-to-print'
import './css/VisitorPass.css';

function VisitorPass(props){ 

    const componentRef=useRef();

    const visitPass=props.handleChangeVisitPass
    console.log(visitPass.meeting_id);

    // print function
    const handlePrint=useReactToPrint({
      content:()=>componentRef.current,
      documentTitle:'Visitor Pass',
      onAfterPrint: ()=> alert("Printed Successfully")

    })
    
   return(
    <div>
     <div ref={componentRef} className="Visitor-Pass">
       { visitPass && (
        <div className="visitor-pass-container">
          <div>
            <h2>Visitor Pass</h2>
          </div>
          <div className="visitor-pass-data">
            <h2>{visitPass.meeting_id}</h2>
          </div>
          <div className="visitor-pass-data">
            <h4>Meeting Date :</h4>
            <p>{new Date(visitPass.meeting_date).toLocaleDateString('en-GB')}</p>
          </div>
          { visitPass.meeting_duration &&
           <div className="visitor-pass-data">
            <h4>Meeting Duration :</h4>
            <p>{visitPass.meeting_duration+" mins"}</p>
          </div>}
          { (visitPass.meeting_startTime && visitPass.meeting_endTime) &&
           <div className="visitor-pass-data">
            <h4>Meeting Time :</h4>
            <p>{visitPass.meeting_startTime+" - "+visitPass.meeting_endTime}</p>
          </div>}
          <br/>
          <div className="visitor-pass-data">
             <h4>Visitor Name :</h4>
            <p>{visitPass.visitor_name}</p>
          </div>
          <div className="visitor-pass-data">
            <h4>Visitor Designation :</h4>
            <p>{visitPass.visitor_designation}</p>
          </div>
          <br/>
           <div className="visitor-pass-data">
             <h4>Employee Name :</h4>
            <p>{visitPass.employee_name}</p>
          </div>
          <div className="visitor-pass-data">
            <h4>Employee Designation :</h4>
            <p>{visitPass.employee_designation}</p>
          </div>
          <div className="visitor-pass-data">
            <h4>Employee Department :</h4>
            <p>{visitPass.employee_department}</p>
          </div>
      </div>) }
   </div>
   <div className="visitor-pass-print-btn">
     <button onClick={handlePrint} type="submit">Print Visit Pass</button>
    </div>
   </div>)
}

export default VisitorPass;