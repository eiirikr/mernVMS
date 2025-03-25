import './css/Header.css';
import { FaUserCircle } from 'react-icons/fa';
import { MdLogout } from 'react-icons/md';
import { BiTime } from 'react-icons/bi';
import { MdDateRange } from 'react-icons/md';
import moment from 'moment';

function Header() {
    
    // remove token and user name while logout
    const handleLogout = () => {
        window.localStorage.removeItem('jwtToken'); 
        window.localStorage.removeItem('userName')
        console.log("token removed");
        window.location.href = '/admin/login';
    };

    return (
        <div className="header">
          <div className="nav-bar">
              <div className='dateTime-container'>
                <div className='dateTime-container'>
                  <MdDateRange size={18.5} />
                  <p>{moment().format('DD/MM/YYYY')}</p>
                </div>
                <div className='dateTime-container'>
                  <BiTime size={18.5} />
                  <p>{moment().format('hh:mm A')}</p>
                </div>
              </div>
          <div className="nav-title">
            <h1>VizTrack</h1>
          </div>
        <div className="user-info">
          <div className="user-icon">
            <FaUserCircle size={20} />
          </div>
          <div className="user-name">
            <h1>{window.localStorage.getItem('userName')}</h1>
          </div>
          <div className="logout-icon" onClick={handleLogout}>
            <MdLogout />
          </div>
        </div>
      </div>
    </div>
    )
}

export default Header