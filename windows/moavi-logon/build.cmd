@echo off
rem Build moavi-logon.exe and moavi-logon-cp.dll (x64, static CRT) with MSVC Build Tools 2022.
setlocal
set VCVARS=%ProgramFiles(x86)%\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat
if not exist "%VCVARS%" set VCVARS=%ProgramFiles%\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat
call "%VCVARS%" >nul || exit /b 1
cd /d "%~dp0"
if not exist out mkdir out
set CFLAGS=/nologo /O2 /MT /W4 /EHsc /utf-8 /DUNICODE /D_UNICODE /DWIN32_LEAN_AND_MEAN /D_WIN32_WINNT=0x0A00 /GS /guard:cf /Qspectre- /Foout\
cl %CFLAGS% moavi-logon.cpp common.cpp /Feout\moavi-logon.exe /link /DYNAMICBASE /NXCOMPAT /guard:cf || exit /b 1
cl %CFLAGS% /LD cp.cpp common.cpp /Feout\moavi-logon-cp.dll /link /DEF:cp.def /DYNAMICBASE /NXCOMPAT /guard:cf || exit /b 1
cl %CFLAGS% /LD ksp.cpp common.cpp /Feout\moavi-logon-ksp.dll /link /DEF:ksp.def /DYNAMICBASE /NXCOMPAT /guard:cf || exit /b 1
del out\*.obj out\*.exp out\*.lib 2>nul
rem the engine pushes these to the desktops (pegaprox/api/vlab_logon.py)
set AGENT=..\..\pegaprox\vlab\logon_agent
if not exist %AGENT% mkdir %AGENT%
copy /y out\moavi-logon.exe %AGENT%\ >nul
copy /y out\moavi-logon-cp.dll %AGENT%\ >nul
copy /y out\moavi-logon-ksp.dll %AGENT%\ >nul
copy /y install.ps1 %AGENT%\ >nul
echo built: out\moavi-logon.exe out\moavi-logon-cp.dll out\moavi-logon-ksp.dll
