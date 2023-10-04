using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Windows;
using System.Windows.Input;
using CSharpDllInjectDemoWpf.Models;

namespace CSharpDllInjectDemoWpf.ViewModels
{
    public class DllInjectMainVm
    {
        public event PropertyChangedEventHandler? PropertyChanged;

        private ProcessInfo? _selectedProcessInfo;
        private DemoStep? _selectedDemoStep;
        private List<ProcessInfo>? _processInfos;
        private DemoInjector? _injector;
        private List<DemoStep>? _demoSteps;
        private ICommand? _executeCommand;

        public DllInjectMainVm()
        {
            DemoInjector = new DemoInjector();
            DemoSteps =  GetDemoSteps();
            ProcessInfos = GetProcesses();
        }

        private void OnPropertyChanged(string propertyName)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }

        public ProcessInfo? SelectedProcessInfo
        {
            get => _selectedProcessInfo;
            set
            {
                if (_selectedProcessInfo != value)
                {
                    _selectedProcessInfo = value;
                    _injector!.ProcessName = _selectedProcessInfo!.Name;
                    OnPropertyChanged(nameof(SelectedProcessInfo));
                }
            }
        }

        public DemoStep? SelectedDemoStep
        {
            get => _selectedDemoStep;
            set
            {
                if (_selectedDemoStep != value)
                {
                    _selectedDemoStep = value;
                    OnPropertyChanged(nameof(SelectedDemoStep));
                }
            }
        }

        public List<ProcessInfo>? ProcessInfos
        {
            get => _processInfos;
            set
            {
                _processInfos = value;
                OnPropertyChanged(nameof(ProcessInfos));
            }
        }

        public List<DemoStep>? DemoSteps
        {
            get => _demoSteps;
            set
            {
                _demoSteps = value;
                OnPropertyChanged(nameof(DemoSteps));
            }
        }

        public DemoInjector? DemoInjector
        { 
            get => _injector;
            set
            {
                _injector = value;
                OnPropertyChanged(nameof(DemoInjector));
            }
        }

        public ICommand ExecuteCommand
        {
            get
            {
                _executeCommand ??= new RelayCommand(Execute, CanExecute);
                return _executeCommand;
            }
        }

        private static List<ProcessInfo> GetProcesses()
        {
            var processList = Process.GetProcesses().ToList();
            var allInfos = processList.Select(p => new ProcessInfo(p));
            return allInfos.Where(i => i.ModuleName != null).OrderBy(i => i.Name).ToList();
        }

        private void Execute(object demoStep)
        {
            if (demoStep is DemoStep demoStepToExec)
            {
                DemoSteps!.ForEach(ds => ds.NextExecutable = false);
                demoStepToExec.NextExecutable = true;
                SelectedDemoStep = demoStepToExec;
                SelectedDemoStep!.Step!.Invoke();
                SelectedDemoStep!.NextExecutable = false;
                var currentIndex = DemoSteps!.IndexOf(SelectedDemoStep);
                if (currentIndex == DemoSteps.Count - 1)
                {
                    Application.Current.Shutdown();
                    return;
                }
                DemoSteps[currentIndex + 1].NextExecutable = true;
            }
            CommandManager.InvalidateRequerySuggested();
        }

        private bool CanExecute(object demoStep)
        {
            if (demoStep is DemoStep demoStepToExec)
            {
                return demoStepToExec.NextExecutable;
            }
            return false;
        }

        private List<DemoStep> GetDemoSteps()
        {
            var demoSteps = new List<DemoStep>();
            demoSteps.AddRange(GetNonExecSteps());
            demoSteps.AddRange(GetExecSteps());
            demoSteps.First(ds => ds.IsExecutable).NextExecutable = true;
            return demoSteps;
        }

        private List<DemoStep> GetNonExecSteps()
        {
            var demoSteps = new List<DemoStep>();
            demoSteps.Add(new DemoStep(null)
            {
                Code = "[DllImport(\"kernel32.dll\")]\r\n" +
                    "public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);",
                Description = "Declaration for the OpenProcess function of the Windows API",
                Hyperlink = @"https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess"
            });
            demoSteps.Add(new DemoStep(null)
            {
                Code = "[DllImport(\"kernel32.dll\", CharSet = CharSet.Auto)]\r\n" +
                    "public static extern IntPtr GetModuleHandle(string lpModuleName);",
                Description = "Declaration for the GetModuleHandle function of the Windows API",
                Hyperlink = @"https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandlea"
            });
            demoSteps.Add(new DemoStep(null)
            {
                Code = "[DllImport(\"kernel32\", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]" +
                    "static extern IntPtr GetProcAddress(IntPtr hModule, string procName);",
                Description = "Declaration for the GetProcAddress function of the Windows API",
                Hyperlink = @"https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress"
            });
            demoSteps.Add(new DemoStep(null)
            {
                Code = "[DllImport(\"kernel32.dll\", SetLastError = true, ExactSpelling = true)]\r\n" +
                    "static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress,\r\n" +
                    "uint dwSize, uint flAllocationType, uint flProtect);",
                Description = "Declaration for the VirtualAllocEx function of the Windows API",
                Hyperlink = @"https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex"
            });
            demoSteps.Add(new DemoStep(null)
            {
                Code = "[DllImport(\"kernel32.dll\", SetLastError = true)]\r\n" +
                    "static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);",
                Description = "Declaration for the WriteProcessMemory function of the Windows API",
                Hyperlink = @"https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory"
            });
            demoSteps.Add(new DemoStep(null)
            {
                Code = "[DllImport(\"kernel32.dll\")]\r\n" +
                    "static extern IntPtr CreateRemoteThread(IntPtr hProcess,\r\n" +
                    "IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);",
                Description = "Declaration for the CreateRemoteThread function of the Windows API",
                Hyperlink = @"https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread"
            });
            demoSteps.Add(new DemoStep(null)
            {
                Code = "const int PROCESS_CREATE_THREAD = 0x0002;",
                Description = "Constant for the access right to create threads in a process object",
                Hyperlink = @"https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights"
            });
            demoSteps.Add(new DemoStep(null)
            {
                Code = "const int PROCESS_QUERY_INFORMATION = 0x0400;",
                Description = "Constant for the access right to query certain information about a process object",
                Hyperlink = @"https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights"
            });
            demoSteps.Add(new DemoStep(null)
            {
                Code = "const int PROCESS_VM_OPERATION = 0x0008;",
                Description = "Constant for the access right to perform an operation on the address space of process object",
                Hyperlink = @"https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights"
            });
            demoSteps.Add(new DemoStep(null)
            {
                Code = "const int PROCESS_VM_WRITE = 0x0020;",
                Description = "Constant for the access right to write memory in a process using Windows API function WriteProcessMemory",
                Hyperlink = @"https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights"
            });
            demoSteps.Add(new DemoStep(null)
            {
                Code = "const int PROCESS_VM_READ = 0x0010;",
                Description = "Constant for the access right to read memory in a process using Windows API function ReadProcessMemory",
                Hyperlink = @"https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights"
            });
            demoSteps.Add(new DemoStep(null)
            {
                Code = "const uint MEM_COMMIT = 0x00001000;",
                Description = "Constant for use with VirtualAllocEx function to commit memory within the address space of a given process",
                Hyperlink = @"https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex"
            });
            demoSteps.Add(new DemoStep(null)
            {
                Code = "const uint MEM_RESERVE = 0x00002000;",
                Description = "Constant for use with VirtualAllocEx function to reserve memory within the address space of a given process",
                Hyperlink = @"https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex"
            });
            demoSteps.Add(new DemoStep(null)
            {
                Code = "const uint PAGE_READWRITE = 4;",
                Description = "Constant for specifying a read/write memory protection type for use with VirtualAllocEx function",
                Hyperlink = @"https://learn.microsoft.com/en-us/windows/win32/Memory/memory-protection-constants"
            });
            return demoSteps;
        }

        private List<DemoStep> GetExecSteps()
        {
            var demoSteps = new List<DemoStep>();
            demoSteps.Add(new DemoStep(_injector.SetTargetProcess)
            {
                Code = "Process targetProcess = Process.GetProcessesByName(ProcessName)[0];",
                Description = "Call System.Diagnostics.Process.GetProcessByName to return a System.Diagnostics.Process " +
                    "object representing the existing process with the chosen name. Note: how _processName is obtained is " +
                    "not represented in the sample code for brevity. For this app it's from the process you chose in the top left " +
                    "of the screen. That list was generated from System.Diagnostics.Process.GetProcesses.",
                Hyperlink = "https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.process.getprocessesbyname?view=net-7.0"
            });
            demoSteps.Add(new DemoStep(_injector.SetProcHandle)
            {
                Code = "IntPtr procHandle = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, false, targetProcess.Id);",
                Description = "Call OpenProcess API function to get the required process handle with necessary access rights.",
                Hyperlink = "https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess"
            });
            demoSteps.Add(new DemoStep(_injector.SetLoadLibraryAddr)
            {
                Code = "IntPtr loadLibraryAddr = GetProcAddress(GetModuleHandle(\"kernel32.dll\"), \"LoadLibraryA\");",
                Description = "Call GetProcAddress API function to get to the address of the LoadLibraryA function which will be" +
                    " called when creating the remote thread to load the DLL into the target process.",
                Hyperlink = "https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress"
            });
            demoSteps.Add(new DemoStep(_injector.SetDllName)
            {
                Code = "string dllName = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, \"MessageBoxDemo.dll\");",
                Description = "Calculate the full path to the native language DLL you want to inject. In this case we are" +
                    "using a C++ DLL which calls the MessageBox API function and is in the same folder as this injector.",
                Hyperlink = "https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-messagebox"
            });
            demoSteps.Add(new DemoStep(_injector.SetAllocMemAddr)
            {
                Code = "IntPtr allocMemAddress = VirtualAllocEx(procHandle, IntPtr.Zero, (uint)((dllName.Length + 1) * Marshal.SizeOf(typeof(char))), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);",
                Description = "Allocate memory in the address space of the target process. We need enough to store a terminated "
                    + "string the length of our DLL path.",
                Hyperlink = "https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex"
            });
            demoSteps.Add(new DemoStep(_injector.WriteProcessMemory)
            {
                Code = "WriteProcessMemory(procHandle, allocMemAddress, Encoding.Default.GetBytes(dllName), (uint)((dllName.Length + 1) * Marshal.SizeOf(typeof(char))), out _);",
                Description = "Write the DLL path to the allocated memory address in our target process memory space.",
                Hyperlink = "https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory"
            });
            demoSteps.Add(new DemoStep(_injector.CreateRemoteThread)
            {
                Code = "CreateRemoteThread(procHandle, IntPtr.Zero, 0, loadLibraryAddr, allocMemAddress, 0, IntPtr.Zero);",
                Description = "Final step. Create a thread in the target process that calls the LoadLibraryA function "
                    + "passing our DLL path we wrote to the process memory address. Our sample DLL's entry point "
                    + "has the code which will, after a ten second delay, display the messagebox. You might want to close "
                    + "this application before the ten seconds expires just to prove that it's not THIS app showing the "
                    + "messagebox.",
                Hyperlink = "https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread"
            });
            return demoSteps;
        }
    }
}
