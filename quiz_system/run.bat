@echo off
chcp 65001 >nul
title Local Quiz Management System
cd /d "%~dp0"

echo ========================================
echo   Local Quiz Management System
echo ========================================
echo.

where python >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] ไม่พบ Python กรุณาติดตั้ง Python 3.8+ ก่อน
    echo ดาวน์โหลดได้ที่ https://www.python.org/downloads/
    pause
    exit /b 1
)

echo กำลังตรวจสอบ Dependencies...
pip install -r requirements.txt -q
if %errorlevel% neq 0 (
    echo [ERROR] ติดตั้ง dependencies ไม่สำเร็จ
    pause
    exit /b 1
)

echo.
echo เริ่มต้นระบบ...
echo.
echo   Player Website : http://127.0.0.1:5000/player
echo   Admin Dashboard: http://127.0.0.1:5000/admin
echo   Default Login  : admin / admin123
echo.
echo กด Ctrl+C เพื่อหยุดระบบ
echo ========================================
echo.

python app.py
pause
