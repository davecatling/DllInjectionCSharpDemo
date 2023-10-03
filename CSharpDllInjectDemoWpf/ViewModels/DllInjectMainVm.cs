using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Windows.Input;
using CSharpDllInjectDemoWpf.Models;

namespace CSharpDllInjectDemoWpf.ViewModels
{
    public class DllInjectMainVm
    {
        public event PropertyChangedEventHandler? PropertyChanged;
        
        private ProcessInfo? _selectedProcessInfo;
        private List<ProcessInfo>? _processInfos;
        private readonly DemoInjector _injector;
        private ICommand _startCommand;

        public DllInjectMainVm()
        {
            _injector = new DemoInjector();
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
                    OnPropertyChanged(nameof(SelectedProcessInfo));
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

        public ICommand StartCommand
        {
            get
            {
                _startCommand ??= new RelayCommand(exec => Start());
                return _startCommand;
            }
        }

        private static List<ProcessInfo> GetProcesses()
        {
            var processList = Process.GetProcesses().ToList();
            var allInfos = processList.Select(p => new ProcessInfo(p));
            return allInfos.Where(i => i.ModuleName != null).OrderBy(i => i.Name).ToList();
        }

        private void Start()
        {
            var demoSteps = new List<DemoStep>();
            LoadNonExecSteps(demoSteps);
            LoadExecSteps(demoSteps);
        }

        private static void LoadNonExecSteps(List<DemoStep> demoSteps)
        {
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
        }

        private void LoadExecSteps(List<DemoStep> demoSteps)
        {
            var execSteps = new List<DemoStep>();
            execSteps.Add(new DemoStep(_injector.SetTargetProcess)
            {
                Code = "Process targetProcess = Process.GetProcessesByName(ProcessName)[0];",
                Description = "Call System.Diagnostics.Process.GetProcessByName to return a System.Diagnostics.Process " +
                    "object representing the existing process with the chosen name. Note: how _processName is obtained is " +
                    "not represented in the sample code for brevity. For this app it's from the process you chose in the top left " +
                    "of the screen. That list was generated from System.Diagnostics.Process.GetProcesses.",
                Hyperlink = "https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.process.getprocessesbyname?view=net-7.0"
            });
            execSteps.Add(new DemoStep(_injector.SetProcHandle)
            {
                Code = "IntPtr procHandle = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, false, targetProcess.Id);",
                Description = "Call OpenProcess API function to get the required process handle with necessary access rights.",
                Hyperlink = "https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess"
            });
            execSteps.Add(new DemoStep(_injector.SetProcHandle)
            {
                Code = "IntPtr loadLibraryAddr = GetProcAddress(GetModuleHandle(\"kernel32.dll\"), \"LoadLibraryA\");",
                Description = "Call GetProcAddress API function to get to the address of the LoadLibraryA function which will be" +
                    " called when creating the remote thread to load the DLL into the target process.",
                Hyperlink = "https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress"
            });

            // name of the dll we want to inject
            string dllName = "C:\\Users\\Public\\MessageBoxDemo.dll";

            // alocating some memory on the target process - enough to store the name of the dll
            // and storing its address in a pointer
            IntPtr allocMemAddress = VirtualAllocEx(procHandle, IntPtr.Zero, (uint)((dllName.Length + 1) * Marshal.SizeOf(typeof(char))), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

            // writing the name of the dll there
            UIntPtr bytesWritten;
            WriteProcessMemory(procHandle, allocMemAddress, Encoding.Default.GetBytes(dllName), (uint)((dllName.Length + 1) * Marshal.SizeOf(typeof(char))), out bytesWritten);

            // creating a thread that will call LoadLibraryA with allocMemAddress as argument
            CreateRemoteThread(procHandle, IntPtr.Zero, 0, loadLibraryAddr, allocMemAddress, 0, IntPtr.Zero);
        }
}
