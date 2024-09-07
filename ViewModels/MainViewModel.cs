using GalaSoft.MvvmLight;
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

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out IntPtr lpNumberOfBytesWritten);

        private List<(IntPtr Address, byte Value)> matchingBytes = new List<(IntPtr Address, byte Value)>();
        private List<(IntPtr Address, byte Value)> _filteredResoult = new List<(IntPtr Address, byte Value)>();
        private List<(IntPtr Address, byte Value)> _lastScanResoult = new List<(IntPtr Address, byte Value)>();

        public List<(IntPtr Address, byte Value)> FilteredResoult
        {
            get => _filteredResoult;
            set
            {
                _filteredResoult = value;
                OnPropertyChanged();
            }
        }
        

        private string processName = "ares";
        private Process process;
        private IntPtr hProcess; // Store the process handle here

        public string ProcessName
        {
            get => processName;
            set
            {
                processName = value;
                OnPropertyChanged();
                InitializeProcess(); // Initialize process whenever the name changes
            }
        }

        private string valueToFindText;
        public string ValueToFindText
        {
            get => valueToFindText;
            set
            {
                valueToFindText = value;
                OnPropertyChanged();
            }
        }

        private string selectedCriteria;
        public string SelectedCriteria
        {
            get => selectedCriteria;
            set
            {
                selectedCriteria = value;
                OnPropertyChanged();
            }
        }

        private bool isLocking;
        public bool IsLocking
        {
            get => isLocking;
            set
            {
                isLocking = value;
                OnPropertyChanged();
            }
        }

        public ICommand ScanCommand { get; }
        public ICommand SubScanCommand { get; }
        public ICommand LockAddressValueCommand { get; }
        public ICommand StopLockingCommand { get; }

        public MainViewModel()
        {
            ScanCommand = new RelayCommand(async () => await InitialScanAsync());
            SubScanCommand = new RelayCommand(async () => await SubScanMemoryAsync());
            LockAddressValueCommand = new RelayCommand(async () => await LockAddressValueAsync());
            StopLockingCommand = new RelayCommand(StopLocking);
        }

        private void InitializeProcess()
        {
            if (process != null)
            {
                CloseHandle(hProcess); // Close the previous handle if it exists
                process = null;
                hProcess = IntPtr.Zero;
            }

            Process[] processes = Process.GetProcessesByName(ProcessName);
            if (processes.Length == 0)
            {
                MessageBox.Show($"Process '{ProcessName}' not found.");
                return;
            }

            process = processes[0];
            hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | 0x0020, false, process.Id);
            if (hProcess == IntPtr.Zero)
            {
                MessageBox.Show("Failed to open process. Try running the application as administrator.");
            }
        }

        private async Task InitialScanAsync()
        {
            if (hProcess == IntPtr.Zero)
            {
                MessageBox.Show("Process handle is invalid. Check the process name.");
                return;
            }

            matchingBytes.Clear();
            await Task.Run(() => ScanMemory(hProcess));
            _lastScanResoult = new List<(IntPtr Address, byte Value)>(matchingBytes);
            DisplayResults();
        }

        private async Task SubScanMemoryAsync()
        {
            if (hProcess == IntPtr.Zero)
            {
                MessageBox.Show("Process handle is invalid. Check the process name.");
                return;
            }

            if (_lastScanResoult.Count == 0)
            {
                MessageBox.Show("No previous scan data available.");
                return;
            }

            matchingBytes.Clear();
            await Task.Run(() => SubScanMemory(hProcess));
            DisplayResults();
        }

        private async Task LockAddressValueAsync()
        {
            if (hProcess == IntPtr.Zero)
            {
                MessageBox.Show("Process handle is invalid. Check the process name.");
                return;
            }

            IsLocking = true;

            try
            {
                byte[] buffer = new byte[] { byte.Parse(ValueToFindText) };
                IntPtr bytesWritten;

                while (IsLocking)
                {
                    // Write the value to the specified address
                    bool success = WriteProcessMemory(hProcess, matchingBytes[0].Address, buffer, (uint)buffer.Length, out bytesWritten);
                    if (!success || bytesWritten.ToInt64() != buffer.Length)
                    {
                        MessageBox.Show($"Failed to write to address {matchingBytes[0].Address.ToString("X")}. Error: {Marshal.GetLastWin32Error()}");
                        break;
                    }

                    await Task.Delay(100); // Adjust delay as needed
                }
            }
            finally
            {
                CloseHandle(hProcess); // Ensure we close the handle to the process
            }
        }

        private void StopLocking()
        {
            IsLocking = false; // Stop the locking loop
            MessageBox.Show("Stopped locking the address value.");
        }

        private void SubScanMemory(IntPtr hProcess)
        {
            const int chunkSize = 65536;
            byte[] buffer = new byte[chunkSize];

            foreach (var entry in _lastScanResoult)
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

            _lastScanResoult = new List<(IntPtr Address, byte Value)>(matchingBytes);
        }

        private void ScanMemory(IntPtr hProcess)
        {
           IntPtr startAddress = new IntPtr(0x00400000);
            IntPtr endAddress = new IntPtr(0x7FFF0000);
            IntPtr address = startAddress;

            const int chunkSize = 65536;  // Read 64 KB chunks at a time
            byte[] buffer = new byte[chunkSize];
            if (!byte.TryParse(SelectedCriteria, out byte valueToFind))

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
            FirstScanHelper.SaveFirstScanResults(_lastScanResoult);

        }

        private void DisplayResults()
        {
            MessageBox.Show($"Found {matchingBytes.Count} matching values.");
            if(matchingBytes.Count < 30)
            {
                FilteredResoult = matchingBytes; 
            }
        }
    }
}
