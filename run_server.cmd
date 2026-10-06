@echo off
setlocal
set "SCRIPT_DIR=%~dp0"

if defined PETRI_MCP_PYTHON (
  set "PYTHON_BIN=%PETRI_MCP_PYTHON%"
) else if exist "%SCRIPT_DIR%.venv\Scripts\python.exe" (
  set "PYTHON_BIN=%SCRIPT_DIR%.venv\Scripts\python.exe"
) else (
  set "PYTHON_BIN=python"
)

if defined PYTHONPATH (
  set "PYTHONPATH=%SCRIPT_DIR%;%PYTHONPATH%"
) else (
  set "PYTHONPATH=%SCRIPT_DIR%"
)

"%PYTHON_BIN%" -m petri_mcp.server
