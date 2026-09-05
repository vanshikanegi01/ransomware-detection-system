# TRINETRA — Ransomware Detection and Response Backend

TRINETRA is a multi-agent AI-powered ransomware defence system designed for early threat detection, real-time containment, and trusted data recovery.

This repository contains the backend services responsible for collecting system activity, analysing ransomware behaviour, making policy decisions, protecting recovery data, and executing response actions.

> **Project:** TRINETRA — Bharat’s Next Generation Cyber Resilience Platform  
> **Team:** Cipher Syndicate  
> **Event:** Smart India Hackathon 2026

## Backend Workflow

```text
Watchdog + Gatekeeper
          ↓
    Risk Analyser
          ↓
    Policy Engine
          ↓
Vaultkeeper + Enforcer
```

The backend follows a layered **Detect → Defend → Recover** approach.

## Core Features

- Behaviour-based ransomware detection
- Machine-learning-based risk analysis
- Real-time file and process monitoring
- Canary-file monitoring
- File and registry activity tracking
- Threat validation and risk scoring
- Policy-based response decisions
- Suspicious process containment
- File locking and quarantine support
- Protected backup and recovery support
- Recovery integrity verification
- Attack-sequence reconstruction
- Explainable risk scoring
- Controlled simulation and testing

## Multi-Agent Architecture

### 1. Watchdog

Watchdog continuously monitors endpoint activity and collects security events.

It observes:

- File creation, modification, and deletion
- File and registry changes
- Process behaviour
- System activity
- Canary-file activity
- Existing endpoint telemetry

When suspicious behaviour is observed, Watchdog forwards the collected events for validation and analysis.

### 2. Gatekeeper

Gatekeeper performs the first layer of threat screening and event validation.

Its responsibilities include:

- Validating incoming events
- Screening suspicious files and activity
- Checking URLs and file-related indicators
- Supporting phishing and DNS-related screening
- Performing initial entropy and activity checks
- Filtering irrelevant or invalid events

The validated events are then sent to the Risk Analyser.

### 3. Risk Analyser

The Risk Analyser evaluates system behaviour and estimates the likelihood of ransomware activity.

It combines behavioural indicators such as:

- File modification patterns
- File entropy
- Input/output activity velocity
- Process behaviour
- Anomalous system activity
- Correlated security signals

The backend uses a trained machine-learning model to produce a ransomware probability and convert it into a risk score.

```text
Ransomware Probability × 100 = Risk Score
```

The current ransomware risk threshold is:

```text
44
```

A score at or above this threshold can be forwarded to the Policy Engine for further action.

### 4. Policy Engine

The Policy Engine converts the risk analysis into an appropriate response decision.

Depending on the threat level, it can decide to:

- Allow normal activity
- Continue monitoring
- Raise a warning
- Increase the incident severity
- Trigger containment
- Initiate recovery-related actions

This separates detection from enforcement and ensures that response actions follow defined policies.

### 5. Vaultkeeper

Vaultkeeper manages protected recovery data and supports restoration after an incident.

Its responsibilities include:

- Maintaining protected backups
- Supporting versioned recovery
- Preserving clean file copies
- Checking recovery-data integrity
- Supporting secure restoration
- Helping restore the system to a trusted state

### 6. Enforcer

Enforcer executes the response actions selected by the Policy Engine.

Possible actions include:

- Stopping malicious processes
- Locking affected files
- Quarantining suspicious files
- Isolating affected resources
- Blocking suspicious connections
- Applying containment rules
- Starting approved recovery actions

The backend supports controlled testing so that response actions can be evaluated safely before being used in a real environment.

## Machine Learning

The Risk Analyser uses a Random Forest classification model implemented with scikit-learn.

The model is loaded from a saved file using Joblib and produces probability-based predictions.

### Model Pipeline

```text
System Activity
      ↓
Feature Collection
      ↓
Feature Processing
      ↓
Random Forest Model
      ↓
Ransomware Probability
      ↓
Risk Score
      ↓
Policy Decision
```

The model is intended to identify behavioural patterns associated with ransomware rather than relying only on known signatures.

## Detection and Recovery Approach

TRINETRA combines several security signals to improve detection:

- Behavioural analysis
- File entropy checks
- Anomaly detection
- Process monitoring
- File and registry monitoring
- Canary files
- Threat validation
- Risk scoring

For recovery, the system uses protected backup concepts, integrity checks, and controlled restoration to reduce data loss and recovery time.

## Technology Stack

- **Language:** Python
- **Machine Learning:** scikit-learn
- **Model:** Random Forest
- **Model Loading:** Joblib
- **Data Processing:** NumPy and Pandas
- **System Monitoring:** Watchdog and Psutil
- **Backend API:** FastAPI
- **Application Server:** Uvicorn
- **Real-Time Communication:** WebSockets
- **Data Validation:** Pydantic
- **Authentication:** Bcrypt and PyJWT
- **Configuration:** Python Dotenv

## Installation

### Clone the Repository

```bash
git clone https://github.com/vanshikanegi01/ransomware-detection-system.git
cd ransomware-detection-system
```

### Create a Virtual Environment

```bash
python -m venv venv
```

On Windows:

```bash
venv\Scripts\activate
```

On Linux or macOS:

```bash
source venv/bin/activate
```

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Configure Environment Variables

Create a `.env` file using the available environment configuration template and update the required values.

## Running the Backend

Start the FastAPI application using Uvicorn:

```bash
uvicorn <module_name>:app --reload
```

Replace `<module_name>` with the module containing the FastAPI application.

## Testing

The `tests/` directory contains test files for validating the individual agents and the complete backend workflow.

The test suite covers:

- Watchdog monitoring and event generation
- Gatekeeper event validation and filtering
- Risk Analyser predictions and risk-score calculation
- Policy Engine decision-making
- Vaultkeeper file protection and recovery operations
- Enforcer response and containment actions
- Communication between agents
- End-to-end ransomware detection and response workflow

### Run All Tests

```bash
pytest tests/
```

### Run Tests with Detailed Output

```bash
pytest tests/ -v
```

### Run a Specific Test File

```bash
pytest tests/<test_file_name>.py -v
```

Replace `<test_file_name>` with the required test file from the `tests/` directory.

### End-to-End Testing

The end-to-end tests validate the complete workflow:

```text
Watchdog + Gatekeeper
          ↓
    Risk Analyser
          ↓
    Policy Engine
          ↓
Vaultkeeper + Enforcer
```

These tests verify that suspicious activity is detected, analysed, converted into a policy decision, and followed by the appropriate protection, containment, or recovery action.

## Safety Notice

This project is intended for educational, research, and controlled cybersecurity testing.

Before running monitoring or enforcement components:

- Use a dedicated test environment
- Do not run ransomware samples on production systems
- Avoid monitoring personal or critical files
- Review configured paths and environment variables
- Use dry-run or simulation mode whenever possible
- Verify recovery procedures before relying on them

## Project Status

TRINETRA is an early-stage software prototype under active development.

The current backend focuses on:

- Early ransomware detection
- Multi-agent event processing
- Behaviour-based machine learning
- Risk-based policy decisions
- Real-time containment
- Protected recovery workflows
- Controlled attack simulation
- End-to-end validation

## Related Repositories

- [TRINETRA Website](https://trinetra-orpin.vercel.app/index.html)
- [TRINETRA Desktop Application](https://github.com/sainipalak0705/trinetra-desktop)

## Development Team

Developed by **Team Cipher Syndicate** for **Smart India Hackathon 2026**.

- [Priyanshi Saini](https://github.com/sainipriyanshi7284)
- [Vanshika Negi](https://github.com/vanshikanegi01)
- [Palak Saini](https://github.com/sainipalak0705)
- [Priya Aggarwal](https://github.com/Priya-30101)
- [Prakhar Srivastava](https://github.com/prakharsrivastava252734)
- [Ansh Dhawan](https://github.com/)

## Disclaimer

TRINETRA is an academic / development project and is currently under active development.

It should not be considered a replacement for a production-grade endpoint security solution.


## License

This project is intended for educational, research, and controlled cybersecurity testing purposes.
