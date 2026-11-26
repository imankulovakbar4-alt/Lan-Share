# Building LAN Share on Windows

## Requirements

- Windows 10 or newer
- Python 3.12 with the Python Launcher (`py.exe`)
- Internet access for the first dependency installation

## Build

1. Open the repository folder.
2. Run `build_exe.bat`.
3. The script creates a local `.venv`, installs the declared dependencies,
   compiles the Python sources, runs unit tests and invokes PyInstaller.
4. The executable is written to `dist\LAN Share.exe`.

The PyInstaller configuration is maintained in `LAN Share.spec`. Change that
file when adding package data, hidden imports or native binaries.

## Notes

- Tkinter is provided by the Python installation; it is not installed from pip.
- Runtime dependencies are listed in `requirements.txt`.
- Build-only dependencies are listed in `requirements-build.txt`.
- Build and test the executable on Windows. A successful Linux CI run does not
  verify Windows GUI startup, drag-and-drop, firewall behavior or LAN transfers.
- User settings and transfer history must remain outside the executable and
  its temporary extraction directory.
