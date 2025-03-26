import 'react-datetime/css/react-datetime.css';
import { useNavigate } from "react-router-dom";
import "./css/Dashboard.css";

function Dashboard({DashboardDisplayCount, handleChangeDashboardEmpData, handleChangeDashboardVisitorData, handleChangeDashboardPreregisterData}){
   
   const navigate = useNavigate();

    return(
      <div className='Dashboard'>
         <div className='dashboard-header'>
          <div className='title'>
            <h2>Dashboard</h2>
          </div>
         </div>
         <div className='Dashboard-Container'>
         <div className='Dashboard-Components'>
          <div className="Component" onClick={()=> {handleChangeDashboardEmpData('Total Employees'); navigate("/time/employee/details")}}>
             <h4>Total Employees</h4>
             <h2>{DashboardDisplayCount.TotalEmpCount}</h2>
          </div>
          <div className="Component"  onClick={()=> {handleChangeDashboardEmpData('Present Employees'); navigate("/time/employee/details")}}>
             <h4>Present Employees</h4>
             <h2>{DashboardDisplayCount.PresentEmpCount}</h2>
          </div>
          <div className="Component" onClick={()=> {handleChangeDashboardEmpData('Absent Employees'); navigate("/time/employee/details")}} >
             <h4>Absent Employees</h4>
              <h2>{DashboardDisplayCount.AbsentEmpCount}</h2>
          </div>
          <div className="Component" onClick={()=> {handleChangeDashboardEmpData('Employees on Leave'); navigate("/time/employee/details")}} >
             <h4>Employees on Leave</h4>
              <h2>{DashboardDisplayCount.LeaveEmpCount}</h2>
          </div>
          <div className="Component" onClick={()=> {handleChangeDashboardEmpData('Employees on Onsite'); navigate("/time/employee/details")}}>
             <h4>Employees on Onsite</h4>
             <h2>{DashboardDisplayCount.OnsiteEmpCount}</h2>
          </div>
          </div>
          <div className='Dashboard-Components'>
          <div className="Component" onClick={()=> {handleChangeDashboardVisitorData('Total Visitors'); navigate("/time/check/in/out/details")}}>
             <h4>Total Visitors</h4>
             <h2>{DashboardDisplayCount.TotalVisitorCount}</h2>
          </div>
          <div className="Component" onClick={()=> {handleChangeDashboardVisitorData('Visitors In'); navigate("/time/check/in/out/details")}}>
             <h4>Visitors In</h4>
             <h2>{DashboardDisplayCount.VisitorInCount}</h2>
          </div>
          <div className="Component" onClick={()=> {handleChangeDashboardVisitorData('Visitors Out'); navigate("/time/check/in/out/details")}}>
             <h4>Visitors Out</h4>
             <h2>{DashboardDisplayCount.VisitorOutCount}</h2>
          </div>
          </div>
          <div className='Dashboard-Components'>
          <div className="Component" onClick={()=> {handleChangeDashboardPreregisterData('Total Pre-registrations'); navigate("/time/preregistration/details")}}>
             <h4>Total Pre-registrations</h4>
             <h2>{DashboardDisplayCount.TotalPreRegisterCount}</h2>
          </div>
          <div className="Component" onClick={()=> {handleChangeDashboardVisitorData('Completed PreRegistrations'); navigate("/time/check/in/out/details")}}>
             <h4>Completed<br/>Pre-registration visit</h4>
             <h2>{DashboardDisplayCount.CompletedPreRegisterCount}</h2>
          </div>
          <div className="Component" onClick={()=> {handleChangeDashboardVisitorData('Pending PreRegistrations'); navigate("/time/check/in/out/details")}}>
             <h4>Inprogress<br/>Pre-registration visit</h4>
             <h2>{DashboardDisplayCount.PendingPreRegisterCount}</h2>
          </div>
          </div>
          </div>
      </div>
    );
};

export default Dashboard;