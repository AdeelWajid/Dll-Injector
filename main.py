import psutil
import ctypes
from ctypes import byref, wintypes
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

# Define some Windows API constants and functions
DLL_PROCESS_ATTACH = 1
TH32CS_SNAPPROCESS = 0x00000002
PROCESS_ALL_ACCESS = 0x001F0FFF

CreateToolhelp32Snapshot = ctypes.windll.kernel32.CreateToolhelp32Snapshot
Process32First = ctypes.windll.kernel32.Process32First
Process32Next = ctypes.windll.kernel32.Process32Next
OpenProcess = ctypes.windll.kernel32.OpenProcess
VirtualAllocEx = ctypes.windll.kernel32.VirtualAllocEx
WriteProcessMemory = ctypes.windll.kernel32.WriteProcessMemory
CreateRemoteThread = ctypes.windll.kernel32.CreateRemoteThread

# Function to handle process selection
def on_select_process(event):
    # Get the selected process
    process = processes[listbox.curselection()[0]]

    # Update the process details labels
    name_var.set(f"Name: {process.name()}")
    pid_var.set(f"PID: {process.pid}")
    status_var.set(f"Status: {process.status()}")
    memory_var.set(f"Memory: {process.memory_info().rss / 1024 / 1024:.2f} MB")

# Function to handle DLL injection
def on_inject_dll():
    # Get the selected process
    process = processes[listbox.curselection()[0]]

    # Ask the user for the path of the DLL to inject using a file dialog
    dll_path = filedialog.askopenfilename(title="Select DLL", filetypes=[("DLL files", "*.dll")])

    # Check if the user selected a file
    if dll_path:
        try:
            # Convert the DLL path to a null-terminated string of bytes
            dll_path_bytes = dll_path.encode('utf-8') + b'\x00'

            # Open the chosen process
            process_handle = OpenProcess(PROCESS_ALL_ACCESS, False, process.pid)

            # Allocate memory in the chosen process
            dll_address = VirtualAllocEx(process_handle, 0, len(dll_path_bytes), 0x1000, 0x04)

            # Write the DLL path into the allocated memory
            written = wintypes.SIZE_T(0)
            WriteProcessMemory(process_handle, dll_address, dll_path_bytes, len(dll_path_bytes), byref(written))

            # Create a remote thread in the chosen process that starts at LoadLibraryA and points to the DLL path
            thread_id = wintypes.DWORD(0)
            LoadLibraryA = ctypes.windll.kernel32.LoadLibraryA
            CreateRemoteThread(process_handle, None, 0, LoadLibraryA, dll_address, 0, byref(thread_id))

            # Show a success message
            messagebox.showinfo("Success", "DLL injected successfully!")
        except Exception as e:
            # Show an error message
            messagebox.showerror("Error", f"An error occurred: {e}")

# Create the main window
root = tk.Tk()
root.title("Process Injector")
root.geometry("400x300")

# Set a custom theme for ttk widgets
style = ttk.Style()
style.theme_use("clam")

# Create a frame for the listbox and scrollbar
list_frame = ttk.Frame(root)
list_frame.pack(fill=tk.BOTH, expand=1)

# Create a listbox to display the list of processes
listbox = tk.Listbox(list_frame)
listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=1)

# Create a scrollbar for the listbox
scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=listbox.yview)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

# Link the scrollbar and listbox together
listbox.config(yscrollcommand=scrollbar.set)

# Get the list of all processes and sort them by name
processes = sorted(psutil.process_iter(), key=lambda p: p.name())

# Add the processes to the listbox
for process in processes:
    listbox.insert(tk.END, process.name())

# Bind the listbox selection event to the on_select_process function
listbox.bind('<<ListboxSelect>>', on_select_process)

# Create a frame for the process details labels
details_frame = ttk.Frame(root)
details_frame.pack(fill=tk.X)

# Create variables for the process details labels
name_var = tk.StringVar()
pid_var = tk.StringVar()
status_var = tk.StringVar()
memory_var = tk.StringVar()

# Create labels for the process details and add them to the details frame
ttk.Label(details_frame, textvariable=name_var).pack(anchor=tk.W)
ttk.Label(details_frame, textvariable=pid_var).pack(anchor=tk.W)
ttk.Label(details_frame, textvariable=status_var).pack(anchor=tk.W)
ttk.Label(details_frame, textvariable=memory_var).pack(anchor=tk.W)

# Create a button to inject the DLL
inject_button = ttk.Button(root, text="Inject DLL", command=on_inject_dll)
inject_button.pack(pady=10)

# Start the main loop
root.mainloop()
