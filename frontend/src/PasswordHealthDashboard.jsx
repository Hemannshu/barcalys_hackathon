import { useNavigate } from 'react-router-dom';

const PasswordHealthDashboard = () => {
  const navigate = useNavigate();

  const handleBack = () => {
    navigate('/'); // Navigates back to main page
  };

  return (
    <div className="health-dashboard">
      <h2>Password Health Center</h2>
      <button onClick={handleBack} className="back-button">
        ← Back to Analyzer
      </button>
      {/* Rest of your dashboard content */}
    </div>
  );
};

export default PasswordHealthDashboard;