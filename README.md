# Python3 Implementation of Dll Injector and Ejector

Test:

```bash
$python pythonDllInjector.py
input keyword for process:
input pid for inject:
input dll keywords for eject:
```

Usage:

```python
import pythonDllInjector as pj
# list all processes and its id
pj.show_processes()
pj.inject_dll(12345, "xxx.dll")
pj.eject_dll(12345, "xxx.dll")
```

