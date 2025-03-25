import './css/Sidebar.css';
import logo from './monitoring.png';
import {GiLockedDoor} from 'react-icons/gi';
import { BsPersonWorkspace } from 'react-icons/bs';
import { BsPersonFill } from 'react-icons/bs';
import { MdNotificationImportant } from 'react-icons/md';
import { TbDeviceDesktopAnalytics } from 'react-icons/tb';
import { FaHandshake } from 'react-icons/fa';
import { LuCalendarDays } from 'react-icons/lu';
import { useNavigate } from "react-router-dom";
import { useState } from 'react';

function Sidebar({handleReportCount}) {
    const navigate = useNavigate();

    const [active, setActive] = useState('dashboard');
    
    // handle change active
    const handleChangeActive = (comp) => {
        setActive(comp);
    };

    return (
        <div className="side-bar">
            <div className="sidebar-menu">
                <div className="logo-container">
                    <img src={logo} className="logo-img" alt='logo' />
                    <h5>VizTrack</h5>
                </div> 
                <div className={(active==="dashboard")?"Active":"dashboard"} onClick={()=>{navigate("dashboard"); handleChangeActive('dashboard') }}>
                    <TbDeviceDesktopAnalytics size={40} />
                    <h6>Dashboard</h6>
                </div>
                <div className={(active==="employee")?"Active":"Employee-Registration"} onClick={()=>{navigate("employee/registration"); handleChangeActive('employee') }}>
                    <BsPersonWorkspace size={35}/>
                    <h6>Employee registration</h6>
                </div>
                <div className={(active==="visitor")?"Active":"Visitor-Registration"} onClick={()=>{navigate("visitor/registration"); handleChangeActive('visitor') }}>
                    <BsPersonFill size={35}/>
                    <h6>Visitor registration</h6>
                </div>
                <div className={(active==="meeting")?"Active":"Meeting-Registration"} onClick={()=>{navigate("meeting/registration"); handleChangeActive('meeting') }}>
                    <FaHandshake size={36}/>
                    <h6>Meeting registration</h6>
                </div>
                <div className={(active==="preregister")?"Active":"Pre-Registration"} onClick={()=>{navigate("meeting/preregistration"); handleChangeActive('preregister') }}>
                    <LuCalendarDays size={33}/>
                    <h6>Pre registration</h6>
                </div>
                <div className={(active==="check")?"Active":"Check-In-Out"} onClick={()=>{navigate("check/in/out"); handleChangeActive('check') }}>
                    <GiLockedDoor size={40}/>
                    <h6>Check in/Check out</h6>
                </div>
                <div className={(active==="emergency")?"Active":"Emergency-Report"} onClick={()=>{navigate("emergency/report/details"); handleChangeActive('emergency') }}>
                    <MdNotificationImportant size={36}/>
                    <h6>Emergency report</h6>
                    {(handleReportCount!=='' && handleReportCount!==0) && 
                    (<div className='total-reports-count'>
                        <p>{handleReportCount}</p>
                    </div>)}
                </div>
            </div>
        </div>
    )
}

export default Sidebar;