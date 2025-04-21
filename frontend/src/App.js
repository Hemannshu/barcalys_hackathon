import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { useState } from 'react';
import './App.css';
import Sidebar from './sidebar';
import MainPage from './MainPage';
import PasswordHealthDashboard from './PasswordHealthDashboard';
import Dashboard from './Dashboard';
import VulnerabilityAnalysisPage from './VulnerabilityAnalysisPage';
import LoginPage from './LoginPage';
import SignupPage from './SignupPage';
import FaceAuthPage from './FaceAuthPage'; // New component

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
            <Route path="/login" element={<LoginPage />} />
            <Route path="/signup" element={<SignupPage />} />
            {/* Add this new route */}
            <Route path="/face-auth" element={<FaceAuthPage />} />
          </Routes>
        </main>
      </div>
    </Router>
  );
}

export default App;