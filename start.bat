@echo off
echo =======================================================
echo   Launching Sentinel AI — Security Gateway & Dashboard
echo =======================================================
echo.

echo Starting Python FastAPI backend server on port 8000...
start "Sentinel AI - FastAPI Backend" cmd /k "python backend/main.py"

timeout /t 2 /nobreak >nul

echo Starting Vite frontend development server on port 5173...
start "Sentinel AI - React Dashboard" cmd /k "npm run dev"

timeout /t 3 /nobreak >nul

echo Opening browser to http://localhost:5173...
start http://localhost:5173

echo.
echo Both services are now running!
echo - Frontend: http://localhost:5173
echo - Backend:  http://127.0.0.1:8000 (Docs at /docs)
echo =======================================================
