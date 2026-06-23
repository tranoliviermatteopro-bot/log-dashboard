@echo off
cd /d "D:\tous\Applications\site web\log-dashboard"
git add server.js package.json
git commit -m "Migrate from sql.js to PostgreSQL (pg)"
git push origin main
echo.
echo Push termine. Appuyez sur une touche pour fermer.
pause
