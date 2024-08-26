using GalaSoft.MvvmLight.Command;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;

namespace MemoryHackingTool.ViewModels
{
    public class MainViewModel : ViewModelBase
    {
        private const int PROCESS_QUERY_INFORMATION = 0x0400;
        private const int PROCESS_VM_READ = 0x0010;

        [StructLayout(LayoutKind.Sequential)]
        public struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint AllocationProtect;
            public UIntPtr RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        [DllImport("kernel32.dll")]
        private static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll")]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll")]
        private static extern IntPtr VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, UIntPtr dwLength);

        [DllImport("kernel32.dll")]
        private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, UIntPtr dwSize, out IntPtr lpNumberOfBytesRead);

        private List<(IntPtr Address, byte Value)> matchingBytes = new List<(IntPtr Address, byte Value)>();
        private List<(IntPtr Address, byte Value)> previousMatchingBytes = new List<(IntPtr Address, byte Value)>();

        private string processName;
        public string ProcessName
        {
            get => processName;
            set => SetProperty(ref processName, value);
        }

        private string valueToFindText;
        public string ValueToFindText
        {
            get => valueToFindText;
            set => SetProperty(ref valueToFindText, value);
        }

        private string selectedCriteria;
        public string SelectedCriteria
        {
            get => selectedCriteria;
            set => SetProperty(ref selectedCriteria, value);
        }

        private ICommand scanCommand;
        public ICommand ScanCommand
        {
            get
            {
                if (scanCommand == null)
                {
                    scanCommand = new RelayCommand(async () => await InitialScanAsync());
                }
                return scanCommand;
            }
        }

        private ICommand subScanCommand;
        public ICommand SubScanCommand
        {
            get
            {
                if (subScanCommand == null)
                {
                    subScanCommand = new RelayCommand(async () => await SubScanMemoryAsync());
                }
                return subScanCommand;
            }
        }

        private async Task InitialScanAsync()
        {
            Process[] processes = Process.GetProcessesByName(ProcessName);
            if (processes.Length == 0)
            {
                MessageBox.Show($"Process '{ProcessName}' not found.");
                return;
            }

            Process process = processes[0];
            IntPtr hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, process.Id);
            if (hProcess == IntPtr.Zero)
            {
                MessageBox.Show("Failed to open process. Try running the application as administrator.");
                return;
            }

            try
            {
                matchingBytes.Clear();
                await Task.Run(() => ScanMemory(hProcess));
                previousMatchingBytes = new List<(IntPtr Address, byte Value)>(matchingBytes);
                DisplayResults();
            }
            finally
            {
                CloseHandle(hProcess);
            }
        }

        private async Task SubScanMemoryAsync()
        {
            if (previousMatchingBytes.Count == 0)
            {
                MessageBox.Show("No previous scan data available.");
                return;
            }

            Process[] processes = Process.GetProcessesByName(ProcessName);
            if (processes.Length == 0)
            {
                MessageBox.Show($"Process '{ProcessName}' not found.");
                return;
            }

            Process process = processes[0];
            IntPtr hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, process.Id);
            if (hProcess == IntPtr.Zero)
            {
                MessageBox.Show("Failed to open process. Try running the application as administrator.");
                return;
            }

            try
            {
                matchingBytes.Clear();
                await Task.Run(() => SubScanMemory(hProcess));
                DisplayResults();
            }
            finally
            {
                CloseHandle(hProcess);
            }
        }

        private void ScanMemory(IntPtr hProcess)
        {
            IntPtr startAddress = new IntPtr(0x00400000);
            IntPtr endAddress = new IntPtr(0x7FFF0000);
            IntPtr address = startAddress;

            const int chunkSize = 65536;
            byte[] buffer = new byte[chunkSize];

            while (address.ToInt64() < endAddress.ToInt64())
            {
                MEMORY_BASIC_INFORMATION m;
                IntPtr result = VirtualQueryEx(hProcess, address, out m, new UIntPtr((uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION))));
                if (result == IntPtr.Zero)
                {
                    break;
                }

                bool isReadable = (m.State == 0x1000) &&
                                  ((m.Protect & 0x04) != 0 ||
                                   (m.Protect & 0x20) != 0 ||
                                   (m.Protect & 0x02) != 0 ||
                                   (m.Protect & 0x10) != 0);

                if (isReadable)
                {
                    long regionSize = (long)m.RegionSize;
                    IntPtr regionBase = m.BaseAddress;

                    for (long offset = 0; offset < regionSize; offset += chunkSize)
                    {
                        IntPtr currentAddress = new IntPtr(regionBase.ToInt64() + offset);

                        if (regionSize - offset < chunkSize)
                        {
                            buffer = new byte[regionSize - offset];
                        }

                        IntPtr bytesRead;
                        bool success = ReadProcessMemory(hProcess, currentAddress, buffer, new UIntPtr((uint)buffer.Length), out bytesRead);
                        if (success && bytesRead.ToInt64() > 0)
                        {
                            for (int i = 0; i < bytesRead.ToInt64(); i++)
                            {
                                matchingBytes.Add((new IntPtr(currentAddress.ToInt64() + i), buffer[i]));
                            }
                        }
                    }
                }

                address = new IntPtr(m.BaseAddress.ToInt64() + (long)m.RegionSize);
            }
        }

        private void SubScanMemory(IntPtr hProcess)
        {
            const int chunkSize = 65536;
            byte[] buffer = new byte[chunkSize];

            foreach (var entry in previousMatchingBytes)
            {
                IntPtr currentAddress = entry.Address;
                IntPtr bytesRead;
                bool success = ReadProcessMemory(hProcess, currentAddress, buffer, new UIntPtr(1), out bytesRead);

                if (success && bytesRead.ToInt64() > 0)
                {
                    byte currentValue = buffer[0];
                    bool matchesCriteria = false;

                    if (SelectedCriteria == "Increased")
                    {
                        matchesCriteria = currentValue > entry.Value;
                    }
                    else if (SelectedCriteria == "Decreased")
                    {
                        matchesCriteria = currentValue < entry.Value;
                    }
                    else if (SelectedCriteria == "Same as Before")
                    {
                        matchesCriteria = currentValue == entry.Value;
                    }
                    else if (SelectedCriteria == "Same as Original")
                    {
                        matchesCriteria = currentValue == matchingBytes.Find(m => m.Address == entry.Address).Value;
                    }

                    if (matchesCriteria)
                    {
                        matchingBytes.Add((currentAddress, currentValue));
                    }
                }
            }

            previousMatchingBytes = new List<(IntPtr Address, byte Value)>(matchingBytes);
        }

        private void DisplayResults()
        {
            MessageBox.Show($"Found {matchingBytes.Count} matching values.");
        }
    }
}
