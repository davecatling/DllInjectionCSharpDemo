using System;
using System.ComponentModel;
using System.Diagnostics;

namespace CSharpDllInjectDemoWpf.Models
{
    public class ProcessInfo
    {
        private IntPtr? _baseAddress;

        public ProcessInfo(Process process)
        {
            Id = process.Id;
            Name = process.ProcessName;
            ProcessModule? mainModule;
            try
            {
                mainModule = process.MainModule;
            }
            catch (Exception)
            {
                mainModule = null;
            }
            if (mainModule != null)
            {
                ModuleName = process.MainModule?.ModuleName;
                FileName = process.MainModule?.FileName;
                _baseAddress = process.MainModule?.BaseAddress;
            }
        }

        public int Id { get; private set; }
        public string Name { get; private set; }
        public string? ModuleName { get; private set; }
        public string? FileName { get; private set; }

        public string BaseAddress
        {
            get
            {
                return String.Format("{0:x}", _baseAddress);
            }
        }
    }
}
