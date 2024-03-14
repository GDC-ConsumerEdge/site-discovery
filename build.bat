REM this build file is to be run under Pycharm project
REM assuming python virtual environment is under venv directory

REM remember current working directory
set cwd=%CD%

REM get into the project directory
cd %~f0\..

REM enable python virtual environment by run venv\Scripts\activate.bat
CALL venv\Scripts\activate.bat

REM explicitly delete all the previous builds
rmdir build\siteDiscovery /s /q
rmdir dist\siteDiscovery /s /q
del dist\siteDiscovery.exe
del siteDiscovery.spec

REM build to one exe file
pyinstaller --clean --noconfirm --onefile main.py^
  --add-data playbook.yaml:. --add-data artifacts:artifacts^
  --icon=artifacts\siteDiscovery.ico^
  --name siteDiscovery

REM deactivate python virtual environment
venv\Scripts\deactivate.bat

REM get back to the original working directory
cd %cwd%