# Breach.AI - Password Security System Architecture

## System Overview

```mermaid
graph TB
    subgraph Frontend["Frontend (React)"]
        UI[User Interface]
        Auth[Authentication]
        Dashboard[Dashboard]
        Analysis[Password Analysis UI]
        Extension[Browser Extension]
    end

    subgraph Backend["Backend (Flask)"]
        API[API Server]
        AuthHandler[Auth Handler]
        PasswordAnalyzer[Password Analyzer]
        HashAnalyzer[Hash Analyzer]
        MLService[ML Service]
    end

    subgraph ML["Machine Learning"]
        MLModel[ML Models]
        FeatureExtractor[Feature Extraction]
        PatternDetector[Pattern Detection]
    end

    subgraph Storage["Storage & Services"]
        Firebase[Firebase]
        DB[(Database)]
        HIBP[HIBP API]
    end

    subgraph Security["Security Layer"]
        JWT[JWT Auth]
        RateLimit[Rate Limiting]
        Encryption[Encryption]
    end

    %% Frontend Connections
    UI --> Auth
    UI --> Dashboard
    UI --> Analysis
    UI --> Extension

    %% Backend Connections
    API --> AuthHandler
    API --> PasswordAnalyzer
    API --> HashAnalyzer
    API --> MLService

    %% ML Connections
    MLService --> MLModel
    MLService --> FeatureExtractor
    MLService --> PatternDetector

    %% Storage Connections
    AuthHandler --> Firebase
    PasswordAnalyzer --> DB
    HashAnalyzer --> HIBP

    %% Security Connections
    AuthHandler --> JWT
    API --> RateLimit
    PasswordAnalyzer --> Encryption

    %% Cross-Layer Connections
    Frontend --> Backend
    Backend --> ML
    Backend --> Storage
    Backend --> Security
```

## Component Details

### 1. Frontend Layer
- **User Interface**: React-based responsive web application
- **Authentication**: Firebase Auth integration
- **Dashboard**: Password health monitoring and management
- **Password Analysis UI**: Real-time strength analysis interface
- **Browser Extension**: Chrome extension for password management

### 2. Backend Layer
- **API Server**: Flask-based REST API
- **Auth Handler**: User authentication and authorization
- **Password Analyzer**: Core password strength analysis
- **Hash Analyzer**: Cryptographic hash analysis
- **ML Service**: Machine learning model integration

### 3. Machine Learning Layer
- **ML Models**: Ensemble of models (Gradient Boosting, Random Forest, Neural Networks)
- **Feature Extraction**: Password characteristics analysis
- **Pattern Detection**: Common pattern and vulnerability detection

### 4. Storage & Services
- **Firebase**: Authentication and real-time database
- **Database**: MySQL for persistent storage
- **HIBP API**: Password breach checking service

### 5. Security Layer
- **JWT Auth**: Token-based authentication
- **Rate Limiting**: API request throttling
- **Encryption**: Data encryption at rest and in transit

## Data Flow

```mermaid
sequenceDiagram
    participant User
    participant Frontend
    participant Backend
    participant ML
    participant Storage

    User->>Frontend: Enter Password
    Frontend->>Backend: Send Password for Analysis
    Backend->>ML: Request ML Analysis
    ML->>Backend: Return Analysis Results
    Backend->>Storage: Store Analysis (if authenticated)
    Backend->>Frontend: Return Analysis Results
    Frontend->>User: Display Results
```

## Security Implementation

```mermaid
graph LR
    subgraph Password["Password Security"]
        Entropy[Entropy Calculation]
        Patterns[Pattern Detection]
        BreachCheck[Breach Checking]
        HashAnalysis[Hash Analysis]
    end

    subgraph Authentication["Authentication"]
        JWT[JWT Tokens]
        Firebase[Firebase Auth]
        MFA[Multi-Factor Auth]
    end

    subgraph Data["Data Protection"]
        Encryption[Encryption]
        Hashing[Secure Hashing]
        RateLimit[Rate Limiting]
    end

    Password --> Authentication
    Authentication --> Data
```

## Integration Points

1. **Frontend-Backend Integration**
   - REST API endpoints
   - WebSocket for real-time updates
   - JWT authentication

2. **Backend-ML Integration**
   - Model serving
   - Feature extraction
   - Real-time predictions

3. **Storage Integration**
   - Firebase for auth and real-time data
   - MySQL for persistent storage
   - HIBP API for breach checking

4. **Security Integration**
   - JWT token validation
   - Rate limiting middleware
   - Encryption/decryption services

## Deployment Architecture

```mermaid
graph TB
    subgraph Production["Production Environment"]
        LoadBalancer[Load Balancer]
        FrontendServers[Frontend Servers]
        BackendServers[Backend Servers]
        MLServers[ML Servers]
        DBServers[Database Servers]
    end

    subgraph Monitoring["Monitoring"]
        Logs[Logging]
        Metrics[Metrics]
        Alerts[Alerts]
    end

    subgraph CDN["Content Delivery"]
        Static[Static Assets]
        Cache[Cache Layer]
    end

    LoadBalancer --> FrontendServers
    LoadBalancer --> BackendServers
    BackendServers --> MLServers
    BackendServers --> DBServers
    FrontendServers --> CDN
    BackendServers --> Monitoring
    MLServers --> Monitoring
    DBServers --> Monitoring
``` 
