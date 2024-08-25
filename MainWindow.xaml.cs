using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;

namespace MemoryHackingTool
{
    public partial class MainWindow : Window
    {
        const int PROCESS_QUERY_INFORMATION = 0x0400;
        const int PROCESS_VM_READ = 0x0010;

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
        static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll")]
        static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll")]
        static extern IntPtr VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, UIntPtr dwLength);

        [DllImport("kernel32.dll")]
        static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, UIntPtr dwSize, out IntPtr lpNumberOfBytesRead);

        private List<(IntPtr Address, byte Value)> matchingBytes = new List<(IntPtr Address, byte Value)>();

        public MainWindow()
        {
            InitializeComponent();
        }


        private void SubScanButton_Click(object sender, RoutedEventArgs e)
        {
            // Implement subscan logic based on the selected criteria
        }
        private async void ScanButton_Click(object sender, RoutedEventArgs e)
        {
            string processName = ProcessNameTextBox.Text;
            if (string.IsNullOrEmpty(processName))
            {
                MessageBox.Show("Please enter a process name.");
                return;
            }

            Process[] processes = Process.GetProcessesByName(processName);
            if (processes.Length == 0)
            {
                MessageBox.Show($"Process '{processName}' not found.");
                return;
            }

            Process process = processes[0];
            IntPtr hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, process.Id);
            if (hProcess == IntPtr.Zero)
            {
                MessageBox.Show("Failed to open process. Try running the application as administrator.");
                return;
            }

            // Capture the value to find before starting the task
            if (!byte.TryParse(ValueTextBox.Text, out byte valueToFind))
            {
                MessageBox.Show("Invalid value. Please enter a valid byte value.");
                return;
            }

            try
            {
                matchingBytes.Clear();
                await Task.Run(() => ScanMemory(hProcess, valueToFind));
                DisplayResults();
            }
            finally
            {
                CloseHandle(hProcess);
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
                                if (buffer[i] == valueToFind)
                                {
                                    matchingBytes.Add((new IntPtr(currentAddress.ToInt64() + i), buffer[i]));
                                }
                            }
                        }
                    }
                }

                address = new IntPtr(m.BaseAddress.ToInt64() + (long)m.RegionSize);
            }
        }

        private void DisplayResults()
        {
            //Dispatcher.Invoke(() =>
            //{
            //    ResultsDataGrid.ItemsSource = null;  // Clear previous results

            //    if (matchingBytes.Count < 20)
            //    {
            //        ResultsDataGrid.ItemsSource = matchingBytes;  // Bind new results if less than 20 items
            //    }
            //    else
            //    {
            //        MessageBox.Show("Too many results. Please refine your search to display fewer than 20 results.", "Notice", MessageBoxButton.OK, MessageBoxImage.Information);
            //    }
            //});
        }

    }
}
