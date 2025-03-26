import './css/App.css';
import AdminSignup from './AdminSignup';
import AdminLogin from './AdminLogin';
import React,{useState} from 'react';
import { BrowserRouter, Routes, Route, Navigate} from "react-router-dom";
import MeetingAvailabilityForm from './MeetingAvailabilityForm';
import EmergencyReport from './EmergencyReport';
import VisitorManagement from './VisitorManagement';
import ForgotPassword from './ForgotPassword';
import ChangePassword from './ChangePassword';

function App() {
  
  const[adminEmail, setAdminEmail]= useState('')
  
  // check token is present or not for login
  const isLoggedIn = !!window.localStorage.getItem('jwtToken'); 

  // handle change display employee 
  const handleAdminEmail = (email) => {
      setAdminEmail(email)
  }

  return (
    <div className="App">
      <BrowserRouter>
      { isLoggedIn ? (
        <Routes>
          <Route path="/" element={<Navigate to="/time/dashboard" />} />
          <Route path="/time/*" element={<VisitorManagement />} />
          <Route path="/availability/form" element={<MeetingAvailabilityForm />} />
          <Route path="/emergency/report" element={<EmergencyReport />} />
         </Routes>
        ):(<Routes>
            <Route path="/" element={<Navigate to="/admin/login" />} />
            <Route path="/admin/login"  element={<AdminLogin onChangeAdminEmail={handleAdminEmail} />} />
            <Route path="/admin/signup" element={<AdminSignup />} />
            <Route path="/admin/forgot/password" element={<ForgotPassword onChangeAdminEmail={handleAdminEmail} AdminEmailID={adminEmail} />} />
            <Route path="/admin/change/password" element={<ChangePassword onChangeAdminEmail={handleAdminEmail} AdminEmailID={adminEmail}/>} />
            <Route path="/emergency/report" element={<EmergencyReport />} />
          </Routes>)}
       </BrowserRouter>
    </div>
  );
}

export default App;
