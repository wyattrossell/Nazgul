@echo off
rem Tauri's Windows signCommand wrapper. Kept free of $ and quotes so NSIS's
rem !finalize does not mangle it. Locates sign.ps1 next to this file via %~dp0.
rem %1 is the artifact path Tauri substitutes.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0sign.ps1" -Path "%~1"
exit /b %ERRORLEVEL%
