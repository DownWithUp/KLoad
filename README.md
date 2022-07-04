# KLoad
A simple command line utility to quickly load and unload Windows drivers. This is an improved version of my old C version of KLoad. The old C version can be found [here](https://github.com/DownWithUp/Kload_C).
## Usage
Basically, you just pass a path to the driver you want to load. For example: `KLoad.exe C:\Windows\System32\ARandomDriver.sys`<br>
In addition, <br>
To unload pass the `-u` argument. For example: `KLoad.exe -u Random.sys` This will target the registry `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Random.sys` and attempt to unload the driver at this key. <br> Please note that not all (especially filter) drivers are designed to be unloaded during runtime.