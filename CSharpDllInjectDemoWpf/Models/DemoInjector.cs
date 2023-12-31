﻿using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace CSharpDllInjectDemoWpf.Models
{
    public class DemoInjector : INotifyPropertyChanged
    {
        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress,
            uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess,
            IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        // privileges
        const int PROCESS_CREATE_THREAD = 0x0002;
        const int PROCESS_QUERY_INFORMATION = 0x0400;
        const int PROCESS_VM_OPERATION = 0x0008;
        const int PROCESS_VM_WRITE = 0x0020;
        const int PROCESS_VM_READ = 0x0010;

        // used for memory allocation
        const uint MEM_COMMIT = 0x00001000;
        const uint MEM_RESERVE = 0x00002000;
        const uint PAGE_READWRITE = 4;

        public event PropertyChangedEventHandler? PropertyChanged;

        private Process? _targetProcess;
        private IntPtr _procHandle;
        private IntPtr _loadLibraryAddr;
        private IntPtr _allocMemAddr;
        private string? _dllName;

        public string? ProcessName { get; set; }

        public IntPtr ProcessHandle
        {
            get => _procHandle;
            set
            {
                _procHandle = value;
                OnPropertyChanged(nameof(ProcessHandleString));
            }
        }

        public string ProcessHandleString
        {
            get { return _procHandle == 0 ? string.Empty : String.Format("{0:x}", _procHandle); }
        }

        public IntPtr LoadLibraryAddress
        {
            get => _loadLibraryAddr;
            set
            {
                _loadLibraryAddr = value;
                OnPropertyChanged(nameof(LoadLibraryAddressString));
            }
        }

        public string LoadLibraryAddressString
        {
            get { return _loadLibraryAddr == 0 ? string.Empty : String.Format("{0:x}", _loadLibraryAddr); }
        }

        public IntPtr AllocMemoryAddress
        {
            get => _allocMemAddr;
            set
            {
                _allocMemAddr = value;
                OnPropertyChanged(nameof(AllocMemoryAddressString));
            }
        }

        public string AllocMemoryAddressString
        {
            get { return _allocMemAddr == 0 ? string.Empty : String.Format("{0:x}", _allocMemAddr); }
        }

        private void OnPropertyChanged(string propertyName)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }

        public void SetTargetProcess()
        {
            _targetProcess = Process.GetProcessesByName(ProcessName)[0];
        }

        public void SetProcHandle()
        {
            ProcessHandle = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, false, _targetProcess!.Id);
        }

        public void SetLoadLibraryAddr()
        {
            LoadLibraryAddress = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
        }

        public void SetDllName()
        {
            _dllName = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "MessageBoxDemo.dll");
        }

        public void SetAllocMemAddr()
        {
            AllocMemoryAddress = VirtualAllocEx(ProcessHandle, IntPtr.Zero, (uint)((_dllName.Length + 1) * Marshal.SizeOf(typeof(char))), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        }

        public void WriteProcessMemory()
        {
            WriteProcessMemory(ProcessHandle, AllocMemoryAddress, Encoding.Default.GetBytes(_dllName), (uint)((_dllName.Length + 1) * Marshal.SizeOf(typeof(char))), out _);
        }

        public void CreateRemoteThread()
        {
            CreateRemoteThread(ProcessHandle, IntPtr.Zero, 0, LoadLibraryAddress, AllocMemoryAddress, 0, IntPtr.Zero);
        }            
    }
}