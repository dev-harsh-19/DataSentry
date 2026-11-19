# DataSentry – Automated Sensitive Data Discovery and Classification System

A simple but practical college-level web application for scanning database schemas, identifying sensitive data, classifying risk, and demonstrating data masking recommendations.

## Stack
- Frontend: React.js + Vite
- Backend: Python + Flask
- Database: MySQL (with SQLite fallback for local demo/testing)
- Visualization: Basic dashboard cards and summary bars

## Features
- Admin login with password hashing
- MySQL connection testing and storage
- Database schema inspection and row sampling
- Sensitive data detection for email, phone, card numbers, Aadhaar-like identifiers, passwords, names, and addresses
- Risk classification and privacy recommendations
- Data masking preview
- Scan history and CSV export
- Basic new-column detection during rescan

## Folder Structure
- `backend/` – Flask API and data persistence
- `frontend/` – React + Vite dashboard UI

## Setup

### 1) Backend
```bash
cd backend
python -m venv .venv
# On Windows PowerShell
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env
```

Update `.env` with your MySQL credentials.

### 2) Frontend
```bash
cd frontend
npm install
```

## Run the Project

Start the backend API:
```bash
cd backend
python app.py
```

Start the frontend app:
```bash
cd frontend
npm run dev -- --host 0.0.0.0
```

Then open the frontend URL shown by Vite, typically:
`http://localhost:5173`

## Default Login
- Username: `admin`
- Password: `admin123`

## Notes
- The app scans databases in a read-only manner.
- The backend uses MySQL when configured; if no MySQL instance is available it can fall back to a local SQLite database for demo purposes.
- Sample scan logic relies on pattern matching and column-name heuristics, so it should be treated as a detection aid rather than a legal identity validator.
