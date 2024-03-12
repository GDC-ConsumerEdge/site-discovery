REM firstly, enable python virtual environment by run venv\Scripts\activate.bat
pyinstaller main.py --add-data playbook.yaml:. --add-data artifacts:artifacts -n siteDiscovery