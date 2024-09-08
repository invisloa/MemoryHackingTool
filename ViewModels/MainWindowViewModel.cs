using GalaSoft.MvvmLight.Command;
using MemoryHackingTool.MemmoryHelpers;
using MemoryHackingTool.Models;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Windows;

namespace MemoryHackingTool.ViewModels
{
    internal class MainWindowViewModel: ViewModelBase
    {
        //ctor  
        public MainWindowViewModel()
        {
            StartScanCommand = new RelayCommand(OnStartScanCommand);
            SubScanCommand = new RelayCommand(OnSubScanCommand);
            LockCommand = new RelayCommand(OnLockCommand);
            UnlockCommand = new RelayCommand(OnUnlockCommand);
        }

        private MemoryLocker _memoryLocker;

        private IntPtr _hProcess;
        Process _selectedProcess;
        const int PROCESS_QUERY_INFORMATION = 0x0400;
        const int PROCESS_VM_READ = 0x0010;
        private string _processName = "ares";
        private string _valueToFind;
        private bool _enableSameAsOriginal;
        private string _valueToLock;
        public string ValueToLock
        {
            get => _valueToLock;
            set
            {
                _valueToLock = value;
                OnPropertyChanged();
            }
        }
        public bool EnableSameAsOriginal
        {
            get => _enableSameAsOriginal;
            set
            {
                _enableSameAsOriginal = value;
                OnPropertyChanged();
            }
        }
        public string ValueToFind
        {
            get => _valueToFind;
            set
            {
                _valueToFind = value;
                OnPropertyChanged();
            }
        }
        public string ProcessName
        {
            get => _processName;
            set
            {
                _processName = value;
                OnPropertyChanged();
            }
        }

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
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll")]
        static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll")]
        static extern IntPtr VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, UIntPtr dwLength);

        [DllImport("kernel32.dll")]
        static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, UIntPtr dwSize, out IntPtr lpNumberOfBytesRead);

        private List<(IntPtr Address, byte Value)> _lastScanResoult = new List<(IntPtr Address, byte Value)>();
        private List<MemoryResult> _filteredResults = new List<MemoryResult>();
        public List<MemoryResult> FilteredResults
        {
            get => _filteredResults;
            set
            {
                _filteredResults = value;
                OnPropertyChanged();
            }
        }


        public RelayCommand StartScanCommand { get; set; }
        public RelayCommand SubScanCommand { get; set; }
        public RelayCommand LockCommand { get; set; }
        public RelayCommand UnlockCommand { get; set; }

        private async void OnStartScanCommand()
        {
            
            if (string.IsNullOrEmpty(ProcessName))
            {
                MessageBox.Show("Please enter a process name.");
                return;
            }

            Process[] processes = Process.GetProcessesByName(ProcessName);
            if (processes.Length == 0)
            {
                MessageBox.Show($"Process '{ProcessName}' not found.");
                return;
            }

            _selectedProcess = processes[0];
            _hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, _selectedProcess.Id);
            if (_hProcess == IntPtr.Zero)
            {
                MessageBox.Show("Failed to open process. Try running the application as administrator.");
                return;
            }


            // Capture the value to find before starting the task
            if (!byte.TryParse(ValueToFind, out byte valueToFind))
            {
                MessageBox.Show("Invalid value. Please enter a valid byte value.");
                return;
            }

            try
            {
                await Task.Run(() => ScanMemory(_hProcess, valueToFind));
                DisplayResults();
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
            }
        }
        private void OnSubScanCommand()
        {
            if (_lastScanResoult.Count == 0)
            {
                MessageBox.Show("No previous scan results to filter.");
                return;
            }

            if (!byte.TryParse(ValueToFind, out byte valueToFind))
            {
                MessageBox.Show("Invalid value. Please enter a valid byte value.");
                return;
            }

            try
            {
                // Filter the last scan results by reading the current memory value at each address
                var filteredResults = new List<(IntPtr Address, byte Value)>();

                foreach (var result in _lastScanResoult)
                {
                    byte[] buffer = new byte[1];
                    IntPtr bytesRead;

                    // Read the current memory value at the specified address
                    bool success = ReadProcessMemory(_hProcess, result.Address, buffer, new UIntPtr(1), out bytesRead);
                    if (success && bytesRead.ToInt64() > 0)
                    {
                        // Compare the current value with the user-specified value
                        if (buffer[0] == valueToFind)
                        {
                            filteredResults.Add((result.Address, buffer[0]));
                        }
                    }
                }

                // Update the last scan result list to the filtered results
                _lastScanResoult = filteredResults;

                // Display the filtered results
                DisplayResults();
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
            }
        }

        private void ScanMemory(IntPtr hProcess, byte valueToFind)
        {
            IntPtr startAddress = new IntPtr(0x00400000);
            IntPtr endAddress = new IntPtr(0x7FFF0000);
            IntPtr address = startAddress;

            const int chunkSize = 65536;  // Read 64 KB chunks at a time
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

                        int bytesToRead = (int)Math.Min(chunkSize, regionSize - offset);
                        IntPtr bytesRead;
                        bool success = ReadProcessMemory(hProcess, currentAddress, buffer, new UIntPtr((uint)bytesToRead), out bytesRead);
                        if (success && bytesRead.ToInt64() > 0)
                        {
                            for (int i = 0; i < bytesRead.ToInt64(); i++)
                            {
                                if (buffer[i] == valueToFind)
                                {
                                    _lastScanResoult.Add((new IntPtr(currentAddress.ToInt64() + i), buffer[i]));
                                }
                            }
                        }
                    }
                }

                address = new IntPtr(m.BaseAddress.ToInt64() + (long)m.RegionSize);
            }
            if (EnableSameAsOriginal)
            {
                FirstScanHelper.SaveFirstScanResults(_lastScanResoult);
            }
        }
        private void OnLockCommand()
        {
            try
            {
                _memoryLocker = new MemoryLocker(_selectedProcess.Id);

                foreach (var result in _filteredResults)
                {
                    byte.TryParse(ValueToLock, out byte lockByte);

                    try
                    {
                        // Convert the address from string to IntPtr assuming it's in hexadecimal format
                        IntPtr address = new IntPtr(Convert.ToInt64(result.Address, 16));
                        _memoryLocker.AddAddressToLock(address, lockByte);
                    }
                    catch (FormatException)
                    {
                        MessageBox.Show($"Invalid address format: {result.Address}");
                    }
                    catch (OverflowException)
                    {
                        MessageBox.Show($"Address value is too large: {result.Address}");
                    }
                }

                _memoryLocker.StartLocking();
                MessageBox.Show("Addresses are now locked to the specified value.");
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
            }
        }


        private void ShowResoults()
        {
            if (_lastScanResoult.Count < 30)
            {
                FilteredResults = _lastScanResoult
                    .Select(r => new MemoryResult { Address = r.Address.ToString(), Value = r.Value })
                    .ToList();
            }
        }

        private void OnUnlockCommand()
        {
            _memoryLocker?.StopLocking();
            MessageBox.Show("Locking stopped.");
        }
        private void DisplayResults()
        {
            MessageBox.Show($"Found {_lastScanResoult.Count} matching bytes.");
            ShowResoults();
        }
    }
}
