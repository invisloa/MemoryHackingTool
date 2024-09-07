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

            MessageBox.Show("First scan results saved successfully.");
        }

        /// <summary>
        /// Loads the first scan results from the file.
        /// </summary>
        /// <returns>A dictionary of addresses and their corresponding values from the first scan.</returns>
        public Dictionary<long, byte> LoadFirstScanResults()
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
            }
            else
            {
                MessageBox.Show("No first scan results file found.");
            }

            return firstScanResults;
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