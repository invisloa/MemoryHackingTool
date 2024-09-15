using MemoryHackingTool.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;

namespace MemoryHackingTool.MemmoryHelpers
{
    public class MemoryLockHandler : IDisposable
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

        private const int PROCESS_ALL_ACCESS = 0x1F0FFF;

        // Constructor to initialize the process handle
        public MemoryLockHandler(int processId)
        {
            _hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, processId);
            if (_hProcess == IntPtr.Zero)
            {
                throw new InvalidOperationException("Failed to open process. Make sure to run the application as administrator.");
            }
        }

        /// <summary>
        /// Adds an address and value to the list of addresses to lock.
        /// </summary>
        public void AddAddressToLock(IntPtr address, byte value)
        {
            _addressesToLock.Add((address, value));
        }

        /// <summary>
        /// Clears all addresses to lock.
        /// </summary>
        public void ClearAddressesToLock()
        {
            _addressesToLock.Clear();
        }

        /// <summary>
        /// Starts locking the specified addresses and values in memory.
        /// </summary>
        public async Task StartLocking()
        {
            if (_addressesToLock.Count == 0)
            {
                MessageBox.Show("No addresses to lock. Please add at least one address before starting.");
                return;
            }

            _cancellationTokenSource = new CancellationTokenSource();
            var token = _cancellationTokenSource.Token;

            try
            {
                await Task.Run(async () =>
                {
                    while (!token.IsCancellationRequested)
                    {
                        foreach (var (address, value) in _addressesToLock)
                        {
                            byte[] buffer = { value };
                            WriteProcessMemory(_hProcess, address, buffer, 1, out _);
                        }

                        await Task.Delay(1, token); // Asynchronously delay instead of Thread.Sleep
                    }
                }, token);
            }
            catch (OperationCanceledException)
            {
                // Handle the cancellation if needed
            }
        }

        /// <summary>
        /// Stops locking the addresses in memory.
        /// </summary>
        public void StopLocking()
        {
            _cancellationTokenSource?.Cancel();
        }

        /// <summary>
        /// Locks the addresses with the specified value.
        /// </summary>
        public async void LockAddresses(List<MemoryResult> filteredResults, string valueToLock)
        {
            ClearAddressesToLock();
            foreach (var result in filteredResults)
            {
                if (byte.TryParse(valueToLock, out byte lockByte))
                {
                    try
                    {
                        ulong addressValue = Convert.ToUInt64(result.Address.Replace("0x", ""), 16);
                        IntPtr address = new IntPtr((long)addressValue);

                        AddAddressToLock(address, lockByte);
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
                else
                {
                    MessageBox.Show("Invalid value to lock. Please enter a valid byte value.");
                }
            }

            await StartLocking(); // Await here to complete StartLocking before showing the message box

            // Show message box on the UI thread after locking has started
            Application.Current.Dispatcher.Invoke(() =>
            {
                MessageBox.Show("Addresses are now locked to the specified value.");
            });
        }

        /// <summary>
        /// Unlocks all currently locked addresses.
        /// </summary>
        public void UnlockAddresses()
        {
            StopLocking();

            // Show message box on the UI thread
            Application.Current.Dispatcher.Invoke(() =>
            {
                MessageBox.Show("Locking stopped.");
            });
        }

        /// <summary>
        /// Releases all resources used by the MemoryManager.
        /// </summary>
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
