## IDA Patcher
A user-friendly binary patch management plugin to replace Hex-Ray's IDA Pro default Patched Bytes view.

### Feature
Press `Ctrl-Alt-P` or navigate to `View/Open subviews/IDA Patcher` to enjoy.
- Import data (`Shift-I`), the invert of builtin Export data (`Shift-E`), supported input methods:
    - Hex string
    - Assembly
    - String literal
    - Binary file
- Comment editing for each continuous patch
- Patch export/import (mainly depend on symbols)

### Install
IDA Patcher depend on [Keystone](http://www.keystone-engine.org/) to compile assembly, just follow instructions on their's site. 

For Windows users, install by **Python module for Windows** is highly recommanded.

After installed Keystone, simply copy 'idapatcher.py' to IDA's plugins folder, it will be automatically loaded the next time you start IDA Pro.

Since I only test it on IDA Pro 7.0, if you encountered some bugs, please feel free to file an issue.

**Happy patching!**