@echo off
setlocal
cd /d "%~dp0"
rem FlashCopy MSVC build script. Usage: build.bat [full_path_of_vcvars64.bat]
rem Or simply run it inside "x64 Native Tools Command Prompt for VS".

set "VCVARS=%~1"
if defined VCVARS goto :havecv
set "VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
if exist "%VCVARS%" goto :havecv
set "VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
if exist "%VCVARS%" goto :havecv
set "VCVARS=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
if exist "%VCVARS%" goto :havecv
set "VCVARS="

:havecv
where cl >nul 2>nul
if not errorlevel 1 goto :build
if not defined VCVARS goto :nocl
call "%VCVARS%" >nul 2>nul
where cl >nul 2>nul
if not errorlevel 1 goto :build

:nocl
echo [X] cl.exe not found. Run build.bat from "x64 Native Tools Command Prompt for VS",
echo     or pass the full path of vcvars64.bat as the first argument.
exit /b 1

:build
cl /nologo /W3 /O2 /utf-8 /D_CRT_SECURE_NO_WARNINGS /Fe:FlashSend.exe FlashSend.c flash_common.c /link ws2_32.lib
if errorlevel 1 goto :fail
cl /nologo /W3 /O2 /utf-8 /D_CRT_SECURE_NO_WARNINGS /Fe:FlashReceive.exe FlashReceive.c flash_common.c /link ws2_32.lib
if errorlevel 1 goto :fail
cl /nologo /W3 /O2 /utf-8 /D_CRT_SECURE_NO_WARNINGS /Fe:selftest.exe selftest.c flash_common.c /link ws2_32.lib
if errorlevel 1 goto :fail
cl /nologo /W3 /O2 /utf-8 /D_CRT_SECURE_NO_WARNINGS /Fe:FlashPcap.exe FlashPcap.c flash_common.c /link ws2_32.lib
if errorlevel 1 goto :fail
cl /nologo /W3 /O2 /utf-8 /D_CRT_SECURE_NO_WARNINGS /Fe:FlashRecvPcap.exe FlashRecvPcap.c flash_common.c /link ws2_32.lib
if errorlevel 1 goto :fail
echo.
echo [OK] FlashSend.exe, FlashReceive.exe, selftest.exe, FlashPcap.exe, FlashRecvPcap.exe are ready.
echo [NOTE] FlashSend 经 nping.exe 发送；FlashReceive 需管理员权限(SIO_RCVALL 混杂抓包)。
echo [NOTE] FlashPcap 从 pcap 文件离线还原；FlashRecvPcap 用 Npcap 非混杂模式实时抓包还原。
echo [NOTE] 运行 selftest.exe 可执行接收端逻辑回归自测。
exit /b 0

:fail
echo [X] Build failed.
exit /b 1
