using MemoryHackingTool.ViewModels;
using System.Windows;

namespace MemoryHackingTool
{
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
            DataContext = new MainViewModel(); // Bind the ViewModel to the DataContext
        }
    }
}
