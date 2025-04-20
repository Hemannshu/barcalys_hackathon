import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { useState } from 'react';
import './App.css';
import Sidebar from './sidebar';
import MainPage from './MainPage';
import PasswordHealthDashboard from './PasswordHealthDashboard';
import Dashboard from './Dashboard';
import VulnerabilityAnalysisPage from './VulnerabilityAnalysisPage';

function App() {
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);

  return (
    <Router>
      <div className="app-container">
        <Sidebar />
        <main className="main-content">
          <Routes>
            <Route 
              path="/" 
              element={
                <MainPage 
                  password={password}
                  setPassword={setPassword}
                  showPassword={showPassword}
                  setShowPassword={setShowPassword}
                />
              } 
            />
            <Route path="/password-health" element={<PasswordHealthDashboard />} />
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="/vulnerability-analysis" element={<VulnerabilityAnalysisPage />} />
          </Routes>
        </main>
      </div>
    </Router>
  );
}

export default App;