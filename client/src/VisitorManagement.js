import Header from './Header';
import Sidebar from './Sidebar';
import VisitorRegistration from './VisitorRegistration';
import DisplayVisitorsData from "./DisplayVisitorsData";
import EmployeeRegistration from "./EmployeeRegistration";
import DisplayEmployeesData from "./DisplayEmployeesData";
import MeetingRegistration from "./MeetingRegistration";
import DisplayMeetingDetails from "./DisplayMeetingDetails";
import DisplayPreRegistrationDetails from './DisplayPreRegistrationDetails';
import Dashboard from './Dashboard';
import DisplayCheckInOutData from './DisplayCheckInOutData';
import DisplayEmergencyReport from './DisplayEmergencyReport';
import VisitorPass from './VisitorPass';
import CheckInOut from './CheckInOut';
import PreRegistration from './PreRegistration';
import {Routes, Route} from "react-router-dom";
import React, { useState} from 'react';
import './css/VisitorManagement.css';
import { FormProvider } from './FormContext';

function VisitorManagement() {

  const [visitorPassData, setVisitorPassData] = useState({});

  // handle change visitor pass
  const handleVisitorPass = (formData) => {
    setVisitorPassData(formData);
  }

   const[empDataShow, setEmpDatadShow]= useState('')
   const[visitorDataShow, setVisitorDataShow]= useState('')
   const[preregisterDataShow, setPreregisterDataShow]= useState('')
   const[reportCount, setReportCount]= useState('')

   const [dashboardCount, setDashboardCount] = useState({
     TotalEmpCount:'',PresentEmpCount:'',AbsentEmpCount:'',LeaveEmpCount:'',OnsiteEmpCount:'',
     TotalVisitorCount:'', VisitorInCount:'', VisitorOutCount:'', TotalPreRegisterCount:'', 
     CompletedPreRegisterCount:'', PendingPreRegisterCount:''
  });

  // handle change count
  const handleDashboardCount = (formData) => {
        setDashboardCount({
            ...dashboardCount,
            ...formData
        });
  }
  
  // handle change display employee 
  const handleDashboardEmpData = (EmpStatus) => {
      setEmpDatadShow(EmpStatus)
  }
  
  // handle change display visitor
  const handleDashboardVisitorData = (VisitorStatus) => {
      setVisitorDataShow(VisitorStatus)
  }

  // handle change display visitor
  const handleDashboardPreregisterData = (preregister) => {
      setPreregisterDataShow(preregister)
  }

  // handle change report count
  const handleReportCount = (report_count) => {
      setReportCount(report_count)
  }

  // call below fonctions to trigger count
  DisplayEmployeesData({handleDashboardChange:handleDashboardCount})
  DisplayCheckInOutData({handleDashboardChange:handleDashboardCount})
  DisplayEmergencyReport({handleChangeReportCount:handleReportCount})
  DisplayPreRegistrationDetails({handleDashboardChange:handleDashboardCount})
  
  return (
    <FormProvider>
      <div className="VisitorManagement">
       <Header/>
       <div className="sidebar-container">
       <Sidebar handleReportCount={reportCount}/>
          <div className="main-content">
            <Routes>
                <Route path="/visitor/registration" element={<VisitorRegistration />} />
                <Route path="/visitor/details" element={<DisplayVisitorsData />} />
                <Route path="/employee/registration" element={<EmployeeRegistration handleChangeDashboardEmpData={handleDashboardEmpData}/>} />
                <Route path="/employee/details" element={<DisplayEmployeesData  handleEmpShowData={empDataShow} handleDashboardChange={handleDashboardCount} />} />
                <Route path="/meeting/registration"  element={<MeetingRegistration handleChangeDashboardEmpData={handleDashboardEmpData} handleChangeVisitorPass={handleVisitorPass}/>} />
                <Route path="/meeting/preregistration"  element={<PreRegistration handleChangeDashboardEmpData={handleDashboardEmpData} handleChangeDashboardPreregisterData={handleDashboardPreregisterData} />} />
                <Route path="/visitor/pass" element={<VisitorPass handleChangeVisitPass={visitorPassData} />} />
                <Route path="/meeting/details" element={<DisplayMeetingDetails/>} />
                <Route path="/preregistration/details" element={<DisplayPreRegistrationDetails  handlePreregisterShowData={preregisterDataShow} handleDashboardChange={handleDashboardCount}/>} />
                <Route path="/check/in/out" element={<CheckInOut  handleChangeDashboardPreregisterData={handleDashboardPreregisterData} handleChangeVisitorPass={handleVisitorPass} handleChangeDashboardVisitorData={handleDashboardVisitorData}/>} />
                <Route path="/check/in/out/details" element={<DisplayCheckInOutData handleVisitorShowData={visitorDataShow} handleDashboardChange={handleDashboardCount} />} />
                <Route path="/emergency/report/details" element={<DisplayEmergencyReport handleChangeReportCount={handleReportCount}/>} />
                <Route path="/dashboard"  element={<Dashboard handleChangeDashboardEmpData={handleDashboardEmpData}
                   handleChangeDashboardPreregisterData={handleDashboardPreregisterData} handleChangeDashboardVisitorData={handleDashboardVisitorData}  DashboardDisplayCount={dashboardCount} />}></Route>
            </Routes>
          </div>
        </div>
    </div>
    </FormProvider>
)};

export default VisitorManagement;
