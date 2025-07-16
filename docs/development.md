# Overview

This document outlines how to build the script without pulling from a release

## Getting started
This tool can be compiled to a single standalone executable file on Windows or Linux platform.
However, if for any security reason the executable file cannot run, user could also install a python virtual environment, and run it as a python script.

## Prepare the workspace

### clone the code repository
```
git clone https://github.com/GDC-ConsumerEdge/site-discovery.git
cd site-discovery
```

### create a virtual environment
Assuming python3 is already installed. Now create a python virtual environment under the project directory.
If using Pycharm, the IDE probably already did this step. Please skip this step if virtual environment is already created.
- Linux System: create a virtual environment in local `.venv` folder
```
python3 -m venv .venv
```
- Windows System: create a virtual environment in local `venv` folder
```
python3 -m venv venv
```

#### activate virtual environment
- Linux System
```
source .venv/bin/activate
```
- Windows System
```
venv/Scripts/activate.bat
```
