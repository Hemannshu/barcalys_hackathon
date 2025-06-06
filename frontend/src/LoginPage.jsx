import React, { useState, useEffect } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { signInWithEmailAndPassword, sendPasswordResetEmail } from 'firebase/auth';
import { auth } from './firebase';
import './LoginPage.css';
import logo from './images/BCS-745d30bf.png';

const LoginPage = () => {
  const navigate = useNavigate();
  const [formData, setFormData] = useState({
    email: '',
    password: ''
  });
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [showForgotPassword, setShowForgotPassword] = useState(false);
  const [resetData, setResetData] = useState({
    fullName: '',
    email: ''
  });

  // Check if we're returning from face authentication
  useEffect(() => {
    const urlParams = new URLSearchParams(window.location.search);
    const fromFaceAuth = urlParams.get('fromFaceAuth');
    
    if (fromFaceAuth === 'true') {
      // Clear any error messages
      setError('');
    }
  }, []);

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({ ...prev, [name]: value }));
  };

  const handleResetDataChange = (e) => {
    const { name, value } = e.target;
    setResetData(prev => ({ ...prev, [name]: value }));
  };

  const togglePasswordVisibility = () => {
    setShowPassword(!showPassword);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setIsLoading(true);

    try {
      // Validate input
      if (!formData.email || !formData.password) {
        throw new Error('Please fill in all fields');
      }

      const userCredential = await signInWithEmailAndPassword(
        auth,
        formData.email,
        formData.password
      );

      const user = userCredential.user;
      const token = await user.getIdToken();
      localStorage.setItem('token', token);
      localStorage.setItem('userId', user.uid);
      localStorage.setItem('email', user.email);

      // Always redirect to face authentication
      window.location.href = '/face-auth.html?action=authenticate';
      
    } catch (err) {
      console.error('Login error:', err);
      let errorMessage = 'An error occurred during login. Please try again.';
      
      if (err.code === 'auth/user-not-found' || err.code === 'auth/wrong-password') {
        errorMessage = 'Invalid email or password';
      } else if (err.code === 'auth/network-request-failed') {
        errorMessage = 'Network error. Please check your internet connection';
      } else if (err.message === 'Please fill in all fields') {
        errorMessage = err.message;
      }
      
      setError(errorMessage);
    } finally {
      setIsLoading(false);
    }
  };

  const initiatePasswordReset = async (e) => {
    e.preventDefault();
    if (!resetData.email || !resetData.fullName) {
      setError('Please fill in all fields');
      return;
    }

    setIsLoading(true);
    setError('');

    try {
      // Store reset data in localStorage
      localStorage.setItem('resetData', JSON.stringify(resetData));
      
      // Check if face-auth.html exists before redirecting
      try {
        const response = await fetch('/face-auth.html');
        if (response.ok) {
          window.location.href = '/face-auth.html?action=verify_reset';
        } else {
          // If face-auth.html doesn't exist, send reset email directly
          await sendPasswordResetEmail(auth, resetData.email);
          setError('Password reset email sent. Please check your inbox.');
          setShowForgotPassword(false);
        }
      } catch (err) {
        console.error('Error checking face-auth.html:', err);
        // If there's an error checking face-auth.html, send reset email directly
        await sendPasswordResetEmail(auth, resetData.email);
        setError('Password reset email sent. Please check your inbox.');
        setShowForgotPassword(false);
      }
    } catch (err) {
      console.error('Password reset error:', err);
      setError('Failed to send password reset email. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="login-page">
      <header className="app-header">
        <div className="header-content">
          <div className="logo-container">
            <img src={logo} alt="Barclays" className="app-logo" />
            <h1>Barclays</h1>
          </div>
          <div className="header-buttons">
            <button 
              className="home-btn"
              onClick={() => navigate('/')}
            >
              Home
            </button>
            <button 
              className="signup-btn"
              onClick={() => navigate('/signup')}
            >
              Sign Up
            </button>
          </div>
        </div>
      </header>

      <div className="login-container">
        <div className="login-header">
          <div className="logo-placeholder">
            <span className="logo-part-1">Breach.</span>
            <span className="logo-part-2">AI</span>
          </div>
          <h2>Welcome Back</h2>
          <p className="subheader">Please sign in to continue</p>
        </div>

        {showForgotPassword ? (
          <form onSubmit={initiatePasswordReset} className="login-form">
            <h3>Account Recovery</h3>
            <p>Please verify your identity to reset your password.</p>
            
            {error && <div className="error-message">{error}</div>}

            <div className="form-group">
              <label htmlFor="resetName">Full Name</label>
              <div className="input-container">
                <span className="input-icon">
                  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                    <path d="M16 7C16 9.20914 14.2091 11 12 11C9.79086 11 8 9.20914 8 7C8 4.79086 9.79086 3 12 3C14.2091 3 16 4.79086 16 7Z" stroke="#12284C" strokeWidth="2"/>
                    <path d="M5 20C5 16.134 8.13401 13 12 13C15.866 13 19 16.134 19 20" stroke="#12284C" strokeWidth="2" strokeLinecap="round"/>
                  </svg>
                </span>
                <input
                  type="text"
                  id="resetName"
                  name="fullName"
                  value={resetData.fullName}
                  onChange={handleResetDataChange}
                  required
                  placeholder="John Doe"
                />
              </div>
            </div>

            <div className="form-group">
              <label htmlFor="resetEmail">Email Address</label>
              <div className="input-container">
                <span className="input-icon">
                  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                    <path d="M4 4H20C21.1 4 22 4.9 22 6V18C22 19.1 21.1 20 20 20H4C2.9 20 2 19.1 2 18V6C2 4.9 2.9 4 4 4Z" stroke="#12284C" strokeWidth="2"/>
                    <path d="M22 6L12 13L2 6" stroke="#12284C" strokeWidth="2" strokeLinecap="round"/>
                  </svg>
                </span>
                <input
                  type="email"
                  id="resetEmail"
                  name="email"
                  value={resetData.email}
                  onChange={handleResetDataChange}
                  required
                  placeholder="john@example.com"
                />
              </div>
            </div>

            <div className="form-actions">
              <button 
                type="submit" 
                className="login-button"
                disabled={isLoading}
              >
                {isLoading ? 'Verifying...' : 'Continue to Face Verification'}
              </button>
              <button 
                type="button" 
                className="secondary-button"
                onClick={() => {
                  setShowForgotPassword(false);
                  setError('');
                }}
              >
                Back to Login
              </button>
            </div>
          </form>
        ) : (
          <form onSubmit={handleSubmit} className="login-form">
            {error && (
              <div className="error-message">
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                  <path d="M12 8V12M12 16H12.01M22 12C22 17.5228 17.5228 22 12 22C6.47715 22 2 17.5228 2 12C2 6.47715 6.47715 2 12 2C17.5228 2 22 6.47715 22 12Z" stroke="#D32F2F" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                </svg>
                {error}
              </div>
            )}

            <div className="form-group">
              <label htmlFor="email">Email Address</label>
              <div className="input-container">
                <span className="input-icon">
                  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                    <path d="M4 4H20C21.1 4 22 4.9 22 6V18C22 19.1 21.1 20 20 20H4C2.9 20 2 19.1 2 18V6C2 4.9 2.9 4 4 4Z" stroke="#12284C" strokeWidth="2"/>
                    <path d="M22 6L12 13L2 6" stroke="#12284C" strokeWidth="2" strokeLinecap="round"/>
                  </svg>
                </span>
                <input
                  type="email"
                  id="email"
                  name="email"
                  value={formData.email}
                  onChange={handleChange}
                  required
                  placeholder="john@example.com"
                />
              </div>
            </div>

            <div className="form-group">
              <label htmlFor="password">Password</label>
              <div className="input-container">
                <button 
                  type="button" 
                  className="password-toggle"
                  onClick={togglePasswordVisibility}
                  aria-label={showPassword ? "Hide password" : "Show password"}
                >
                  {showPassword ? (
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                      <path d="M9.9 4.24C10.5883 4.07888 11.2931 3.99834 12 4C19 4 23 12 23 12C22.393 13.1356 21.6691 14.2047 20.84 15.19M14.12 14.12C13.8454 14.4147 13.5141 14.6512 13.1462 14.8151C12.7782 14.9791 12.3809 15.0673 11.9781 15.0744C11.5753 15.0815 11.1752 15.0074 10.8016 14.8565C10.4281 14.7056 10.0887 14.481 9.80385 14.1962C9.51897 13.9113 9.29439 13.5719 9.14351 13.1984C8.99262 12.8248 8.91853 12.4247 8.92563 12.0219C8.93274 11.6191 9.02091 11.2218 9.18488 10.8538C9.34884 10.4859 9.58525 10.1546 9.88 9.88M17.94 17.94C16.2306 19.243 14.1491 19.9649 12 20C5 20 1 12 1 12C2.24389 9.6819 3.96914 7.65661 6.06 6.06L17.94 17.94Z" stroke="#12284C" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                      <path d="M1 1L23 23" stroke="#12284C" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                    </svg>
                  ) : (
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                      <path d="M12 15C13.6569 15 15 13.6569 15 12C15 10.3431 13.6569 9 12 9C10.3431 9 9 10.3431 9 12C9 13.6569 10.3431 15 12 15Z" stroke="#12284C" strokeWidth="2"/>
                      <path d="M2 12C2 12 5 5 12 5C19 5 22 12 22 12C22 12 19 19 12 19C5 19 2 12 2 12Z" stroke="#12284C" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                    </svg>
                  )}
                </button>
                <input
                  type={showPassword ? "text" : "password"}
                  id="password"
                  name="password"
                  value={formData.password}
                  onChange={handleChange}
                  required
                  placeholder="••••••••"
                />
              </div>
            </div>

            <div className="form-options">
              <div className="remember-me">
                <input type="checkbox" id="remember" />
                <label htmlFor="remember">Remember me</label>
              </div>
              <button 
                type="button" 
                className="forgot-password"
                onClick={() => setShowForgotPassword(true)}
              >
                Forgot Password?
              </button>
            </div>

            <button 
              type="submit" 
              className="login-button"
              disabled={isLoading}
            >
              {isLoading ? (
                <>
                  <svg className="spinner" viewBox="0 0 50 50">
                    <circle cx="25" cy="25" r="20" fill="none" strokeWidth="5"></circle>
                  </svg>
                  Signing In...
                </>
              ) : 'Sign In'}
            </button>

            <div className="login-redirect">
              Don't have an account? 
              <Link to="/signup" className="login-link">Sign up</Link>
            </div>
          </form>
        )}
      </div>
    </div>
  );
};

export default LoginPage;