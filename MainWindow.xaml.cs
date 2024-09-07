using MemoryHackingTool.ViewModels;
using System.Windows;

namespace MemoryHackingTool
{
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
            DataContext = new MainViewModel(); // Set the DataContext to MainViewModel
        }
    }
}
