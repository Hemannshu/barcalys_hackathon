import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import MainPage from './MainPage';
import VulnerabilityAnalysisPage from './VulnerabilityAnalysisPage';
import './App.css';

function App() {
  return (
    <Router>
      <Routes>
        <Route path="/" element={<MainPage />} />
        <Route path="/vulnerability-analysis" element={<VulnerabilityAnalysisPage />} />
      </Routes>
    </Router>
  );
}

export default App; 