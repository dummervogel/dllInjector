import ctypes
from ctypes import wintypes
import psutil

kernel32 = ctypes.WinDLL('kernel32.dll', use_last_error=True)
psapi = ctypes.WinDLL("Psapi.dll", use_last_error=True)

PROCESS_VM_OPERATION = 0x0008
PROCESS_VM_WRITE = 0x0020
PROCESS_CREATE_THREAD = 0x0002
PROCESS_ALL_ACCESS = (0x000F0000 | 0x00100000 | 0xFFFF)

MEM_COMMIT = 0x1000
MEM_RELEASE = 0x8000
PAGE_READWRITE = 0x0004
INFINITE = -1
LIST_MODULES_DEFAULT    = 0x00
LIST_MODULES_32BIT      = 0x01
LIST_MODULES_64BIT      = 0x02
LIST_MODULES_ALL        = 0x03

SIZE_T = ctypes.c_size_t
LPSIZE_T = ctypes.POINTER(SIZE_T)
WCHAR_SIZE = ctypes.sizeof(wintypes.WCHAR)
LPSECURITY_ATTRIBUTES = wintypes.LPVOID
LPTHREAD_START_ROUTINE = wintypes.LPVOID

class BOOL_CHECKED(ctypes._SimpleCData):
    _type_ = "l"
    def _check_retval_(self, retval):
        if retval == 0:
            raise ctypes.WinError(ctypes.get_last_error())
        return retval

class LPVOID_CHECKED(ctypes._SimpleCData):
    _type_ = "P"
    def _check_retval_(self, retval):
        if retval is None:
            raise ctypes.WinError(ctypes.get_last_error())
        return retval

class DWORD_CHECKED(ctypes._SimpleCData):
    _type_ = "g"
    def _check_retval_(self, retval):
        if retval == 0:
            raise ctypes.WinError(ctypes.get_last_error())
        return retval

HANDLE_CHECKED = LPVOID_CHECKED  # not file handles

kernel32.OpenProcess.restype = HANDLE_CHECKED
kernel32.OpenProcess.argtypes = (
    wintypes.DWORD, # dwDesiredAccess
    wintypes.BOOL,  # bInheritHandle
    wintypes.DWORD) # dwProcessId

kernel32.VirtualAllocEx.restype = LPVOID_CHECKED
kernel32.VirtualAllocEx.argtypes = (
    wintypes.HANDLE, # hProcess
    wintypes.LPVOID, # lpAddress
    SIZE_T,          # dwSize
    wintypes.DWORD,  # flAllocationType
    wintypes.DWORD)  # flProtect

kernel32.VirtualFreeEx.argtypes = (
    wintypes.HANDLE, # hProcess
    wintypes.LPVOID, # lpAddress
    SIZE_T,          # dwSize
    wintypes.DWORD)  # dwFreeType

kernel32.WriteProcessMemory.restype = BOOL_CHECKED
kernel32.WriteProcessMemory.argtypes = (
    wintypes.HANDLE,  # hProcess
    wintypes.LPVOID,  # lpBaseAddress
    wintypes.LPCVOID, # lpBuffer
    SIZE_T,           # nSize
    LPSIZE_T)         # lpNumberOfBytesWritten _Out_

kernel32.CreateRemoteThread.restype = HANDLE_CHECKED
kernel32.CreateRemoteThread.argtypes = (
    wintypes.HANDLE,        # hProcess
    LPSECURITY_ATTRIBUTES,  # lpThreadAttributes
    SIZE_T,                 # dwStackSize
    LPTHREAD_START_ROUTINE, # lpStartAddress
    wintypes.LPVOID,        # lpParameter
    wintypes.DWORD,         # dwCreationFlags
    wintypes.LPDWORD)       # lpThreadId _Out_

kernel32.WaitForSingleObject.argtypes = (
    wintypes.HANDLE, # hHandle
    wintypes.DWORD)  # dwMilliseconds

kernel32.CloseHandle.argtypes = (
    wintypes.HANDLE,) # hObject

psapi.EnumProcessModulesEx.argtypes = (
    wintypes.HANDLE, #hProcess
    wintypes.LPVOID, #lphModule
    wintypes.DWORD, #cb
    wintypes.LPDWORD, #lpcbNeeded
    wintypes.DWORD, #dwFilterFlag
)

psapi.EnumProcessModulesEx.restype = BOOL_CHECKED

psapi.GetModuleFileNameExA.argtypes = (
    wintypes.HANDLE,  #hProcess,
    wintypes.HMODULE, #hModule,
    wintypes.LPSTR,   #lpFilename,
    wintypes.DWORD,   #nSize
)

psapi.GetModuleFileNameExA.restype = DWORD_CHECKED

def inject_dll(pid, dllpath):
    size = (len(dllpath) + 1) * WCHAR_SIZE
    hproc = hthrd = addr = None
    try:
        hproc = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        addr = kernel32.VirtualAllocEx(
            hproc, None, size, MEM_COMMIT, PAGE_READWRITE)
        kernel32.WriteProcessMemory(
            hproc, addr, dllpath, size, None)
        hthrd = kernel32.CreateRemoteThread(
            hproc, None, 0, kernel32.LoadLibraryW, addr, 0, None)
        kernel32.WaitForSingleObject(hthrd, INFINITE)
    finally:
        if addr is not None:
            kernel32.VirtualFreeEx(hproc, addr, 0, MEM_RELEASE)
        if hthrd is not None:
            kernel32.CloseHandle(hthrd)
        if hproc is not None:
            kernel32.CloseHandle(hproc)

def eject_dll(pid: int, dllpath: str):
    hthrd = hproc = None
    try:
        hproc = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        
        # enumerate all modules
        size = 0x1000
        lpcbNeeded = wintypes.DWORD(size)
        unit = ctypes.sizeof(wintypes.HMODULE)
        # retrieve a list of modules
        while 1:
            lphModules = (wintypes.HMODULE * (size // unit))()
            psapi.EnumProcessModulesEx(hproc, ctypes.byref(lphModules), lpcbNeeded, ctypes.byref(lpcbNeeded), LIST_MODULES_DEFAULT)
            needed = lpcbNeeded.value
            if needed <= size:
                break
            size = needed
        

        # retrieve the name for each module
        filenamesize = ctypes.wintypes.MAX_PATH
        for index in range(0, (needed // unit)):
            while 1:
                lpFilename = ctypes.create_string_buffer(filenamesize)
                lphModule = wintypes.HMODULE(lphModules[index])
                nCopiedFilename = psapi.GetModuleFileNameExA(hproc, lphModule, lpFilename, filenamesize)
                if nCopiedFilename < (filenamesize - 1):
                    break
                filenamesize = filenamesize + ctypes.wintypes.MAX_PATH
            if dllpath in lpFilename.value.decode():
                hthrd = kernel32.CreateRemoteThread(hproc, None, 0, kernel32.FreeLibrary, lphModule, 0, None)
                kernel32.WaitForSingleObject(hthrd, INFINITE)
                break
    finally:
        if hthrd is not None:
            kernel32.CloseHandle(hthrd)
        if hproc is not None:
            kernel32.CloseHandle(hproc)

def show_processes(keyword: str=None):
    # Iterate over all running process
    for proc in psutil.process_iter():
        try:
            # Get process name & pid from process object.
            fullpath = ' '.join(proc.cmdline())
            if not keyword or keyword in fullpath: 
                print('%s:%s' % (proc.pid, fullpath ))
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

def show_dlls(pid: int):
    p = psutil.Process( pid )
    for dll in p.memory_maps():
        print(dll.path)
if __name__ == "__main__":
    keyword = input("input keyword for process:")

    show_processes(keyword)
    pid = input("input pid for inject:")
    pid = int(pid)

    dll = input("input dll for inject:")
    if dll is not None and dll != '':
        inject_dll(pid, dll)
    
    show_dlls(pid)
    dll = input("input dll keywords for eject:")
    if dll is not None and dll != '':
        eject_dll(pid, dll)
        print("finished unloading")