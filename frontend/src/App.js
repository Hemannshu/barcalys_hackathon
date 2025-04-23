import React, { useState, useEffect } from 'react';
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

  // Check if this is the initial load
  useEffect(() => {
    const hasVisited = sessionStorage.getItem('hasVisited');
    if (hasVisited) {
      setShowAnimation(false);
    } else {
      sessionStorage.setItem('hasVisited', 'true');
    }
  }, []);

  const handleAnimationComplete = () => {
    setShowAnimation(false);
  };

  // Don't show animation for password-health route
  const currentPath = window.location.pathname;
  const skipAnimationRoutes = ['/password-health', '/dashboard', '/login', '/signup'];
  const shouldShowAnimation = showAnimation && !skipAnimationRoutes.includes(currentPath);

  return (
    <Router>
      <div className="app-container">
        {shouldShowAnimation ? (
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
                <Route 
                  path="/password-health" 
                  element={<PasswordHealthDashboard />} 
                />
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