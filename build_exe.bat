@echo off
cd /d "%~dp0"
echo ==========================================
echo Building Package 5 Warehouse Desktop EXE...
echo ==========================================

where py >nul 2>nul
if %errorlevel%==0 (
  set PY_CMD=py
) else (
  set PY_CMD=python
)

%PY_CMD% -m pip install --upgrade pip
%PY_CMD% -m pip install pyinstaller

%PY_CMD% -m PyInstaller --noconfirm --clean --onefile --windowed --name "Package5_Warehouse" warehouse_desktop.py

if exist dist\Package5_Warehouse.exe (
  echo.
  echo Build completed successfully.
  echo EXE file: %cd%\dist\Package5_Warehouse.exe
) else (
  echo.
  echo Build failed.
)

pause
