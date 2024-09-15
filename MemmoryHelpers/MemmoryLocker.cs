using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace MemoryHackingTool.MemmoryHelpers
{
    public class MemoryLocker
    {
        private IntPtr _hProcess;
        private readonly List<(IntPtr Address, byte Value)> _addressesToLock = new List<(IntPtr Address, byte Value)>();
        private CancellationTokenSource _cancellationTokenSource;

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        private static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll")]
        private static extern bool CloseHandle(IntPtr hObject);

        const int PROCESS_ALL_ACCESS = 0x1F0FFF;

        public MemoryLocker(int processId)
        {
            _hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, processId);
            if (_hProcess == IntPtr.Zero)
            {
                throw new InvalidOperationException("Failed to open process. Make sure to run the application as administrator.");
            }
        }

        public void AddAddressToLock(IntPtr address, byte value)
        {
            _addressesToLock.Add((address, value));
        }
        public void ClearAddressToLoack()
        {
            _addressesToLock.Clear();
        }

        public async Task StartLocking()
        {
            if (_addressesToLock.Count == 0)
            {
                throw new InvalidOperationException("No addresses to lock. Please add at least one address before starting.");
            }

            _cancellationTokenSource = new CancellationTokenSource();
            var token = _cancellationTokenSource.Token;

            Task.Run(() =>
            {
                while (!token.IsCancellationRequested)
                {
                    foreach (var (address, value) in _addressesToLock)
                    {
                        byte[] buffer = { value };
                        WriteProcessMemory(_hProcess, address, buffer, 1, out _);
                    }

                    Thread.Sleep(1); // Adjust the interval as needed
                }
            }, token);
        }

        public void StopLocking()
        {
            _cancellationTokenSource?.Cancel();
        }

        public void Dispose()
        {
            StopLocking();
            if (_hProcess != IntPtr.Zero)
            {
                CloseHandle(_hProcess);
                _hProcess = IntPtr.Zero;
            }
        }
    }
}
