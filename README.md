## IDA Patcher
A user-friendly binary patch management plugin to replace Hex-Ray's IDA Pro default *Patched Bytes view*. 

Works on IDA Pro 7.0.

### Feature
- Import data (`Shift-I`), the invert of builtin Export data (`Shift-E`), supported input methods:
    - Hex string
    - Assembly
    - String literal
    - Binary file

- IDA Patcher: a more informative *Patched bytes View*
    - Display patch address / function name / size / patch bytes / comments
    - Use comment as a quick note for each patch

- Patch export / import (mainly depend on symbols)
    - Quite useful while migrating patches between different version of game binary
    - Auto detect patch validity while importing
    - Auto fixup branch target address with correct symbol address (experimental, now only works on aarch64 patch)

### Usage
Press `Ctrl-Alt-P` or navigate to `View/Open subviews/IDA Patcher` to enjoy.

Import data window can be opened by pressing `Shift-I` on *IDA View*/*Hex View*.

Patch import/export menu is on the right click menu of *IDA Patcher View*

### Install
IDA Patcher depend on [Keystone](http://www.keystone-engine.org/) to compile assembly, just follow instructions on their's site. 

For Windows users, install by **Python module for Windows** is highly recommanded.

After installed Keystone, simply copy 'idapatcher.py' to IDA's plugins folder, it will be automatically loaded the next time you start IDA Pro.

Since I only test it on IDA Pro 7.0, if you encountered some bugs, please feel free to file an issue.

**Happy patching!**
