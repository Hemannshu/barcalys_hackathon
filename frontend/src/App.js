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

function App() {
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [showAnimation, setShowAnimation] = useState(true);

  const handleAnimationComplete = () => {
    setShowAnimation(false);
  };

  // Only show animation on root path
  const currentPath = window.location.pathname;
  const shouldShowAnimation = showAnimation && currentPath === '/';

  // Check if user is authenticated
  const isAuthenticated = () => {
    return localStorage.getItem('token') !== null;
  };

  // Protected Route component
  const ProtectedRoute = ({ children }) => {
    if (!isAuthenticated()) {
      return <Navigate to="/login" />;
    }
    return children;
  };

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
                {/* Public Routes */}
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
                <Route path="/login" element={<LoginPage />} />
                <Route path="/signup" element={<SignupPage />} />
                <Route path="/vulnerability-analysis" element={<VulnerabilityAnalysisPage />} />

                {/* Protected Routes */}
                <Route 
                  path="/password-health" 
                  element={
                    <ProtectedRoute>
                      <PasswordHealthDashboard />
                    </ProtectedRoute>
                  } 
                />
                <Route 
                  path="/dashboard" 
                  element={
                    <ProtectedRoute>
                      <Dashboard />
                    </ProtectedRoute>
                  } 
                />
                
                {/* Fallback route */}
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