using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;

namespace MemoryHackingTool
{
    internal class FirstScanHelper
    {
        private const string FirstScanFilePath = "FirstScanResults.txt"; // Define a path to save the first scan results

        // Dictionary to hold the first scan results in memory after loading from the file
        private static Dictionary<long, byte> _firstScanResults = new Dictionary<long, byte>();

        /// <summary>
        /// Saves the results of the first scan to a file.
        /// </summary>
        /// <param name="matchingBytes">List of addresses and values from the first scan.</param>
        public static void SaveFirstScanResults(List<(IntPtr Address, byte Value)> matchingBytes)
        {
            using (StreamWriter writer = new StreamWriter(FirstScanFilePath))
            {
                foreach (var (address, value) in matchingBytes)
                {
                    writer.WriteLine($"{address.ToInt64().ToString("X")},{value}");
                }
            }

            // Save in-memory for fast access
            _firstScanResults = matchingBytes.ToDictionary(mb => mb.Address.ToInt64(), mb => mb.Value);
        }

        /// <summary>
        /// Loads the first scan results from the file.
        /// </summary>
        /// <returns>A dictionary of addresses and their corresponding values from the first scan.</returns>
        public static Dictionary<long, byte> LoadFirstScanResults()
        {
            Dictionary<long, byte> firstScanResults = new Dictionary<long, byte>();

            if (File.Exists(FirstScanFilePath))
            {
                using (StreamReader reader = new StreamReader(FirstScanFilePath))
                {
                    string line;
                    while ((line = reader.ReadLine()) != null)
                    {
                        string[] parts = line.Split(',');
                        if (parts.Length == 2 &&
                            long.TryParse(parts[0], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out long address) &&
                            byte.TryParse(parts[1], out byte value))
                        {
                            firstScanResults[address] = value;
                        }
                    }
                }

                // Cache the loaded results in memory
                _firstScanResults = firstScanResults;
            }
            else
            {
                MessageBox.Show("No first scan results file found.");
            }

            return firstScanResults;
        }

        /// <summary>
        /// Checks if the current value matches the original value from the first scan.
        /// </summary>
        /// <param name="address">Memory address to check.</param>
        /// <param name="currentValue">Current value at the address.</param>
        /// <returns>True if the current value matches the original value; otherwise, false.</returns>
        public static bool CheckOriginalValue(IntPtr address, byte currentValue)
        {
            if (_firstScanResults.Count == 0)
            {
                LoadFirstScanResults(); // Ensure results are loaded
            }

            if (_firstScanResults.TryGetValue(address.ToInt64(), out byte originalValue))
            {
                return originalValue == currentValue;
            }
            return false;
        }

        /// <summary>
        /// Compares the current value to determine if it has increased from the original value.
        /// </summary>
        public static bool IsValueIncreased(IntPtr address, byte currentValue)
        {
            if (_firstScanResults.TryGetValue(address.ToInt64(), out byte originalValue))
            {
                return currentValue > originalValue;
            }
            return false;
        }

        /// <summary>
        /// Compares the current value to determine if it has decreased from the original value.
        /// </summary>
        public static bool IsValueDecreased(IntPtr address, byte currentValue)
        {
            if (_firstScanResults.TryGetValue(address.ToInt64(), out byte originalValue))
            {
                return currentValue < originalValue;
            }
            return false;
        }

        /// <summary>
        /// Compares the current value to determine if it is the same as before.
        /// </summary>
        public static bool IsValueSameAsBefore(IntPtr address, byte currentValue)
        {
            if (_firstScanResults.TryGetValue(address.ToInt64(), out byte originalValue))
            {
                return currentValue == originalValue;
            }
            return false;
        }

        /// <summary>
        /// Compares the current scan results with the original values from the first scan.
        /// </summary>
        /// <param name="currentScanResults">List of current addresses and values.</param>
        public void CompareWithFirstScanResults(List<(IntPtr Address, byte Value)> currentScanResults)
        {
            var firstScanResults = LoadFirstScanResults();
            if (firstScanResults.Count == 0)
            {
                MessageBox.Show("No data available to compare. Please perform a first scan and save the results.");
                return;
            }

            List<(IntPtr Address, byte OldValue, byte NewValue)> changedValues = new List<(IntPtr Address, byte OldValue, byte NewValue)>();

            foreach (var (address, value) in currentScanResults)
            {
                if (firstScanResults.TryGetValue(address.ToInt64(), out byte originalValue))
                {
                    if (originalValue != value)
                    {
                        changedValues.Add((address, originalValue, value));
                    }
                }
            }

            if (changedValues.Count > 0)
            {
                foreach (var (address, oldValue, newValue) in changedValues)
                {
                    Console.WriteLine($"Address: {address.ToInt64():X}, Original Value: {oldValue}, Current Value: {newValue}");
                }
            }
            else
            {
                MessageBox.Show("No changes detected from the first scan.");
            }
        }
    }
}
