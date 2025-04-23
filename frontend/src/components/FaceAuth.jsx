import React, { useEffect, useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import './FaceAuth.css';

const FaceAuth = () => {
  const location = useLocation();
  const navigate = useNavigate();
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [faceio, setFaceio] = useState(null);
  const [isInitialized, setIsInitialized] = useState(false);

  useEffect(() => {
    let mounted = true;

    const loadFaceIO = async () => {
      try {
        // Check if FaceIO is already loaded
        if (window.faceIO) {
          console.log('FaceIO already loaded');
          const faceioInstance = new window.faceIO("fioa6c50");
          if (mounted) {
            setFaceio(faceioInstance);
            setIsInitialized(true);
          }
          return;
        }

        // Load FaceIO SDK
        const script = document.createElement('script');
        script.src = 'https://cdn.faceio.net/fio.js';
        script.async = true;

        await new Promise((resolve, reject) => {
          script.onload = () => {
            console.log('FaceIO script loaded');
            if (window.faceIO) {
              const faceioInstance = new window.faceIO("fioa6c50");
              if (mounted) {
                setFaceio(faceioInstance);
                setIsInitialized(true);
              }
              resolve(faceioInstance);
            } else {
              reject(new Error('FaceIO SDK not available after loading'));
            }
          };

          script.onerror = (error) => {
            console.error('Error loading FaceIO script:', error);
            reject(new Error('Failed to load FaceIO SDK'));
          };

          document.body.appendChild(script);
        });
      } catch (err) {
        console.error('FaceIO initialization error:', err);
        if (mounted) {
          setError('Failed to initialize face authentication. Please try again later.');
          setIsInitialized(false);
        }
      }
    };

    loadFaceIO();

    return () => {
      mounted = false;
      try {
        const script = document.querySelector('script[src="https://cdn.faceio.net/fio.js"]');
        if (script && script.parentNode) {
          script.parentNode.removeChild(script);
        }
      } catch (err) {
        console.warn('Error during FaceIO script cleanup:', err);
      }
    };
  }, []);

  const handleEnroll = async () => {
    if (!isInitialized || !faceio) {
      setError('Face authentication is not ready. Please try again.');
      return;
    }

    setIsLoading(true);
    setError('');

    try {
      const userInfo = await faceio.enroll({
        locale: "auto",
        payload: {
          userId: localStorage.getItem('userId'),
          email: localStorage.getItem('email')
        }
      });

      // Update facial ID in backend
      const response = await fetch('http://localhost:5000/api/auth/update-facial-id', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        },
        body: JSON.stringify({
          userId: localStorage.getItem('userId'),
          facialId: userInfo.facialId
        })
      });

      if (!response.ok) {
        throw new Error('Failed to update facial ID');
      }

      navigate('/dashboard');
    } catch (err) {
      console.error('Face enrollment error:', err);
      setError(err.message || 'Face registration failed. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleAuthenticate = async () => {
    if (!isInitialized || !faceio) {
      setError('Face authentication is not ready. Please try again.');
      return;
    }

    setIsLoading(true);
    setError('');

    try {
      const userData = await faceio.authenticate({
        locale: "auto"
      });

      // Verify facial ID with backend
      const response = await fetch('http://localhost:5000/api/auth/verify-facial-id', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        },
        body: JSON.stringify({
          userId: localStorage.getItem('userId'),
          facialId: userData.facialId
        })
      });

      if (!response.ok) {
        throw new Error('Face verification failed');
      }

      navigate('/dashboard');
    } catch (err) {
      console.error('Face authentication error:', err);
      setError(err.message || 'Face verification failed. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };

  const action = location.state?.action || 'authenticate';

  return (
    <div className="face-auth-container">
      <h1>{action === 'enroll' ? 'Register Your Face' : 'Verify Your Identity'}</h1>
      <p className="description">
        {action === 'enroll' 
          ? 'Please register your facial biometrics for secure authentication.'
          : 'Please authenticate using your registered facial biometrics.'}
      </p>
      
      {error && (
        <div className="error-message">
          {error}
        </div>
      )}

      <button
        className="auth-button"
        onClick={action === 'enroll' ? handleEnroll : handleAuthenticate}
        disabled={isLoading || !isInitialized}
      >
        {isLoading ? 'Processing...' : action === 'enroll' ? 'Start Registration' : 'Start Verification'}
      </button>
    </div>
  );
};

export default FaceAuth; 