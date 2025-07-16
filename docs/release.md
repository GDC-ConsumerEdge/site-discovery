# Overview

Releases consist of buildling a Windows and Linux executable, and tagging the git repository with a valid semver version.

## Build a standalone executables

1. Build executables
    - Linux System
    ```
    build.sh
    ```
    - Windows System
    ```
    build.bat
    ```

2. Binary executable is generated in `dist` folder

3. Create a new Release in GitHub with the `dist` generated binaries