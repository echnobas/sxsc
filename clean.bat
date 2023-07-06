@echo off
del build.bat 2>NUL
del files.txt 2>NUL
del /f *.manifest 2>NUL
del /f update* 2>NUL
del /s /f /q .\disk1\*.* 2>NUL
rd /s /q .\disk1 2>NUL
del *.cab 2>NUL