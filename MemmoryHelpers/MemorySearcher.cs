using MemoryHackingTool.ViewModels;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace MemoryHackingTool.MemmoryHelpers
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.Runtime.InteropServices;
    using System.Threading.Tasks;

    namespace MemmoryHelpers
    {
        internal class MemorySearcher
        {
            // Constants
            const int PROCESS_QUERY_INFORMATION = 0x0400;
            const int PROCESS_VM_READ = 0x0010;

            // Fields
            private IntPtr _hProcess;
            private List<(IntPtr Address, byte Value)> _lastScanResult = new List<(IntPtr Address, byte Value)>();

            // DLL Imports
            [DllImport("kernel32.dll")]
            static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

            [DllImport("kernel32.dll", SetLastError = true)]
            static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, UIntPtr dwSize, out IntPtr lpNumberOfBytesRead);

            [DllImport("kernel32.dll")]
            static extern IntPtr VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, UIntPtr dwLength);

            // Constructor
            public MemorySearcher() { }

            // Method to start scanning memory
            public async Task<List<(IntPtr Address, byte Value)>> StartScanAsync(Process selectedProcess, byte valueToFind, bool enableSameAsOriginal)
            {
                _hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, selectedProcess.Id);
                if (_hProcess == IntPtr.Zero)
                {
                    throw new Exception("Failed to open process. Try running the application as administrator.");
                }

                return await Task.Run(() => ScanMemory(valueToFind, enableSameAsOriginal));
            }

            private List<(IntPtr Address, byte Value)> ScanMemory(byte valueToFind, bool enableSameAsOriginal)
            {
                IntPtr startAddress = new IntPtr(0x00400000);
                IntPtr endAddress = new IntPtr(0x7FFF0000);
                IntPtr address = startAddress;

                const int chunkSize = 65536;
                byte[] buffer = new byte[chunkSize];

                while (address.ToInt64() < endAddress.ToInt64())
                {
                    MEMORY_BASIC_INFORMATION m;
                    IntPtr result = VirtualQueryEx(_hProcess, address, out m, new UIntPtr((uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION))));
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
                            bool success = ReadProcessMemory(_hProcess, currentAddress, buffer, new UIntPtr((uint)bytesToRead), out bytesRead);
                            if (success && bytesRead.ToInt64() > 0)
                            {
                                for (int i = 0; i < bytesRead.ToInt64(); i++)
                                {
                                    if (buffer[i] == valueToFind)
                                    {
                                        _lastScanResult.Add((new IntPtr(currentAddress.ToInt64() + i), buffer[i]));
                                    }
                                }
                            }
                        }
                    }

                    address = new IntPtr(m.BaseAddress.ToInt64() + (long)m.RegionSize);
                }

                if (enableSameAsOriginal)
                {
                    FirstScanHelper.SaveFirstScanResults(_lastScanResult);
                }

                return _lastScanResult;
            }

            // Method to filter results
            public List<(IntPtr Address, byte Value)> FilterResults(byte valueToFind, MemoryCriteria criteria)
            {
                var filteredResults = new List<(IntPtr Address, byte Value)>();

                foreach (var result in _lastScanResult)
                {
                    byte[] buffer = new byte[1];
                    IntPtr bytesRead;

                    bool success = ReadProcessMemory(_hProcess, result.Address, buffer, new UIntPtr(1), out bytesRead);
                    if (success && bytesRead.ToInt64() > 0)
                    {
                        bool addToResults = false;

                        switch (criteria)
                        {
                            case MemoryCriteria.Exact:
                                if (buffer[0] == valueToFind) addToResults = true;
                                break;
                            case MemoryCriteria.Increased:
                                if (buffer[0] > result.Value) addToResults = true;
                                break;
                            case MemoryCriteria.Decreased:
                                if (buffer[0] < result.Value) addToResults = true;
                                break;
                            case MemoryCriteria.SameAsBefore:
                                if (buffer[0] == result.Value) addToResults = true;
                                break;
                            case MemoryCriteria.SameAsOriginal:
                                if (FirstScanHelper.CheckOriginalValue(result.Address, buffer[0])) addToResults = true;
                                break;
                        }

                        if (addToResults)
                        {
                            filteredResults.Add((result.Address, buffer[0]));
                        }
                    }
                }

                _lastScanResult = filteredResults;
                return _lastScanResult;
            }
        }
    }
    public enum MemoryCriteria
    {
        Exact,
        Increased,
        Decreased,
        SameAsBefore,
        SameAsOriginal
    }

}
