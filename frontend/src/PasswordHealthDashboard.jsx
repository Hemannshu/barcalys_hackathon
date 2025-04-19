import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import './dashboard.css';

const PasswordHealthDashboard = () => {
    const navigate = useNavigate();

    const handleBack = () => {
        navigate('/'); // Navigates back to the main page
    };

    // Sample data for the dashboard (this can be dynamic, fetched from an API or state)
    const passwordHealthScore = 78;
    const criticalIssues = 2;
    const warnings = 5;
    const securePasswords = 12;
    const dataBreachAlerts = [
        { name: "Adobe", date: "October 2023", type: "User accounts exposed", details: ["Email", "Password", "Name"] },
        { name: "LinkedIn", date: "June 2023", type: "Credentials exposed", details: ["Email", "Password Hash"] }
    ];

    return (
        <div className="health-dashboard">
            <h2>Password Health Center</h2>
            <button onClick={handleBack} className="back-button">← Back to Analyzer</button>
            
            {/* Password Health Score Section */}
            <div className="health-score-section">
                <h3>Password Health Score</h3>
                <div className="score-bar">
                    <div className="score-bar-inner" style={{ width: `${passwordHealthScore}%` }}></div>
                </div>
                <p>{passwordHealthScore} / 100</p>
            </div>

            {/* Security Recommendations Section */}
            <div className="security-recommendations">
                <h3>Security Recommendations</h3>
                <div className="critical-issues">
                    <h4>Critical Issues</h4>
                    <div className="issue">
                        <p>Password reused on multiple sites</p>
                        <button className="action-button">Change password</button>
                    </div>
                    <div className="issue">
                        <p>Weak password detected</p>
                        <button className="action-button">Strengthen now</button>
                    </div>
                </div>

                <div className="warnings">
                    <h4>Warnings</h4>
                    <div className="issue">
                        <p>Password hasn't been updated in a year</p>
                        <button className="action-button">Update password</button>
                    </div>
                </div>

                <div className="good-practices">
                    <h4>Good Practices</h4>
                    <p>MFA enabled on critical accounts</p>
                    <p>Password manager in use</p>
                </div>
            </div>

            {/* Data Breach Alerts Section */}
            <div className="data-breach-alerts">
                <h3>Data Breach Alerts</h3>
                {dataBreachAlerts.map((alert, index) => (
                    <div key={index} className="breach-alert">
                        <p>{alert.name} - {alert.date}</p>
                        <p>{alert.type}</p>
                        <button className="action-button">View Details</button>
                    </div>
                ))}
                <button className="action-button">Check All Accounts</button>
            </div>
        </div>
    );
};

export default PasswordHealthDashboard;
