import React, { useState } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import './App.css';
import AnimationPage from './AnimationPage';
import Sidebar from './sidebar';
import MainPage from './MainPage';
import PasswordHealthDashboard from './PasswordHealthDashboard';
import Dashboard from './Dashboard';
import VulnerabilityAnalysisPage from './VulnerabilityAnalysisPage';
import LoginPage from './LoginPage';
import SignupPage from './SignupPage';
import FaceAuthPage from './FaceAuthPage';

function App() {
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [showAnimation, setShowAnimation] = useState(true);

  const handleAnimationComplete = () => {
    setShowAnimation(false);
  };

  return (
    <Router>
      <div className="app-container">
        {showAnimation ? (
          <AnimationPage onComplete={handleAnimationComplete} duration={5000} />
        ) : (
          <>
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
                <Route path="/face-auth" element={<FaceAuthPage />} />
                <Route path="*" element={<Navigate to="/" />} />
              </Routes>
            </main>
          </>
        )}
      </div>
    </Router>
  );
}

export default App;