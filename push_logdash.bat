@echo off
cd /d "D:\tous\Applications\site web"
echo === Calcul du hash du sous-arbre log-dashboard ===
for /f %%i in ('git subtree split --prefix log-dashboard HEAD') do set HASH=%%i
echo Hash: %HASH%
echo.
echo === Push vers tranoliviermatteopro-bot/log-dashboard ===
git push https://github.com/tranoliviermatteopro-bot/log-dashboard.git %HASH%:main --force
echo.
echo Termine. Appuyez sur une touche pour fermer.
pause
