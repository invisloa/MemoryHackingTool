using GalaSoft.MvvmLight.Command;
using MemoryHackingTool.MemmoryHelpers;
using MemoryHackingTool.MemmoryHelpers.MemmoryHelpers;
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
    internal class MainWindowViewModel : ViewModelBase
    {
        // Fields
        private string _processName = "ares";
        private string _valueToFind;
        private bool _enableSameAsOriginal;
        private string _valueToLock;
        private Process _selectedProcess;
        private List<MemoryResult> _filteredResults = new List<MemoryResult>();
        private MemorySearcher _memorySearcher;
        private MemoryLockHandler _memoryLockHandler;

        // Properties
        public MemoryResult SelectedResoultItem { get; set; }

        private string _selectedCriteria;

        public string SelectedCriteria
        {
            get => _selectedCriteria;
            set
            {
                _selectedCriteria = value;
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

        public string ValueToFind
        {
            get => _valueToFind;
            set
            {
                _valueToFind = value;
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

        public string ValueToLock
        {
            get => _valueToLock;
            set
            {
                _valueToLock = value;
                OnPropertyChanged();
            }
        }

        public List<MemoryResult> FilteredResults
        {
            get => _filteredResults;
            set
            {
                _filteredResults = value;
                OnPropertyChanged();
            }
        }

        // Commands
        public RelayCommand StartScanCommand { get; set; }
        public RelayCommand SubScanCommand { get; set; }
        public RelayCommand LockCommand { get; set; }
        public RelayCommand UnlockCommand { get; set; }

        // Constructor
        public MainWindowViewModel()
        {
            _memorySearcher = new MemorySearcher();
            StartScanCommand = new RelayCommand(OnStartScanCommand);
            SubScanCommand = new RelayCommand(OnSubScanCommand);
            LockCommand = new RelayCommand(OnLockCommand);
            UnlockCommand = new RelayCommand(OnUnlockCommand);
        }

        // Methods
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

            if (!byte.TryParse(ValueToFind, out byte valueToFind))
            {
                MessageBox.Show("Invalid value. Please enter a valid byte value.");
                return;
            }

            try
            {
                var results = await _memorySearcher.StartScanAsync(_selectedProcess, valueToFind, EnableSameAsOriginal);
                DisplayResults(results);
                _memoryLockHandler = new MemoryLockHandler(_selectedProcess.Id);

            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
            }
        }

        private void OnSubScanCommand()
        {
            if (!byte.TryParse(ValueToFind, out byte valueToFind))
            {
                MessageBox.Show("Invalid value. Please enter a valid byte value.");
                return;
            }

            if (string.IsNullOrEmpty(SelectedCriteria))
            {
                MessageBox.Show("Please select a criteria for subscan.");
                return;
            }

            try
            {
                List<(IntPtr Address, byte Value)> filteredResults = null;
                switch (SelectedCriteria)
                {
                    case "System.Windows.Controls.ComboBoxItem: Exact Value":
                        filteredResults = _memorySearcher.FilterResults(valueToFind, MemoryCriteria.Exact);
                        break;
                    case "System.Windows.Controls.ComboBoxItem: Increased":
                        filteredResults = _memorySearcher.FilterResults(valueToFind, MemoryCriteria.Increased);
                        break;
                    case "System.Windows.Controls.ComboBoxItem: Decreased":
                        filteredResults = _memorySearcher.FilterResults(valueToFind, MemoryCriteria.Decreased);
                        break;
                    case "System.Windows.Controls.ComboBoxItem: Same as Before":
                        filteredResults = _memorySearcher.FilterResults(valueToFind, MemoryCriteria.SameAsBefore);
                        break;
                    case "System.Windows.Controls.ComboBoxItem: Same as Original":
                        filteredResults = _memorySearcher.FilterResults(valueToFind, MemoryCriteria.SameAsOriginal);
                        break;
                    default:
                        MessageBox.Show("Invalid criteria selected.");
                        return;
                }

                DisplayResults(filteredResults);
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
            }
        }

        private void OnLockCommand()
        {
            try
            {
                _memoryLockHandler.LockAddresses(_filteredResults, ValueToLock);
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
            }
        }

        private void OnUnlockCommand()
        {
            _memoryLockHandler?.UnlockAddresses();
        }

        private void ShowResults(List<(IntPtr Address, byte Value)> results)
        {
            if (results.Count < 30)
            {
                FilteredResults = results
                    .Select(r => new MemoryResult
                    {
                        Address = $"0x{r.Address.ToInt64():X}",
                        Value = r.Value
                    })
                    .ToList();
            }
        }

        private void DisplayResults(List<(IntPtr Address, byte Value)> results)
        {
            MessageBox.Show($"Found {results.Count} matching bytes.");
            ShowResults(results);
        }
    }
}
