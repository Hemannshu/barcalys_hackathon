import { useState } from 'react';
import { Link } from 'react-router-dom';
import './sidebar.css';

const Sidebar = () => {
  const [isVisible, setIsVisible] = useState(false);

  return (
    <div 
      className={`sidebar-container ${isVisible ? 'visible' : ''}`}
      onMouseEnter={() => setIsVisible(true)}
      onMouseLeave={() => setIsVisible(false)}
    >
      <div className="sidebar">
        <div className="sidebar-header">
          <h3>Security Tools</h3>
        </div>
        <nav className="sidebar-nav">
          <Link to="/" className="nav-item">
            <span className="nav-icon">🔍</span>
            <span className="nav-text">Password Analyzer</span>
          </Link>
          <Link to="/password-health" className="nav-item">
            <span className="nav-icon">🛡️</span>
            <span className="nav-text">Password Health</span>
          </Link>
          <Link to="/dashboard" className="nav-item">
            <span className="nav-icon">📊</span>
            <span className="nav-text">Security Dashboard</span>
          </Link>
          <div className="nav-divider"></div>
          <Link to="/login" className="nav-item">
            <span className="nav-icon">🔑</span>
            <span className="nav-text">Login</span>
          </Link>
          <Link to="/signup" className="nav-item">
            <span className="nav-icon">✨</span>
            <span className="nav-text">Sign Up</span>
          </Link>
        </nav>
      </div>
    </div>
  );
};

export default Sidebar;