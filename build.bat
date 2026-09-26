@echo off
rem builds podot.exe with the c# compiler that ships with windows, then runs the self check
cd /d "%~dp0"
"%windir%\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /nologo /target:winexe /out:podot.exe podot.cs || exit /b 1
start /wait "" podot.exe --selftest || (echo selftest failed & exit /b 1)
echo ok
