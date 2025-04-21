import React, { useEffect } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';

const FaceAuthPage = () => {
  const [searchParams] = useSearchParams();
  const action = searchParams.get('action');
  const navigate = useNavigate();

  useEffect(() => {
    // Load the faceIO script dynamically
    const script = document.createElement('script');
    script.src = 'https://cdn.faceio.net/fio.js';
    script.async = true;
    script.onload = initializeFaceIO;
    document.body.appendChild(script);

    return () => {
      document.body.removeChild(script);
    };
  }, []);

  const initializeFaceIO = () => {
    const faceio = new window.faceIO("fioa6c50"); // Your public ID
    
    if (action === 'enroll') {
      faceio.enroll({
        locale: "auto",
        payload: {
          userId: localStorage.getItem('userId'),
          email: localStorage.getItem('email') || ''
        }
      }).then(userInfo => {
        localStorage.setItem('facialId', userInfo.facialId);
        navigate('/dashboard'); // Redirect after successful enrollment
      }).catch(handleError);
    } else if (action === 'authenticate') {
      faceio.authenticate({
        locale: "auto"
      }).then(userData => {
        if (userData.payload.userId === localStorage.getItem('userId')) {
          navigate('/dashboard'); // Redirect after successful auth
        } else {
          handleError('FACE_MISMATCH');
        }
      }).catch(handleError);
    }
  };

  const handleError = (errCode) => {
    console.error('Face authentication error:', errCode);
    // Handle errors appropriately
  };

  return (
    <div className="face-auth-container">
      <h1>{action === 'enroll' ? 'Face Registration' : 'Face Authentication'}</h1>
      <p>Please allow camera access when prompted</p>
      <div id="faceio-modal"></div>
    </div>
  );
};

export default FaceAuthPage;