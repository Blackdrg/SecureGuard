using System;
using System.Windows;

namespace SecureGuard.UI
{
    public partial class App : Application
    {
        [STAThread]
        public static void Main()
        {
            var app = new App();
            app.InitializeComponent();
            app.Run();
        }
        
        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);
            Core.Logger.Info("SecureGuard application starting");
            
            // Create and show main window
            var mainWindow = new MainWindow();
            mainWindow.Show();
            
            // Global exception handling
            AppDomain.CurrentDomain.UnhandledException += (s, args) =>
            {
                var ex = args.ExceptionObject as Exception;
                Core.Logger.Fatal("Unhandled exception", ex);
                MessageBox.Show($"A critical error occurred: {ex?.Message}", "Error", 
                    MessageBoxButton.OK, MessageBoxImage.Error);
            };
            
            DispatcherUnhandledException += (s, args) =>
            {
                Core.Logger.Error("Dispatcher unhandled exception", args.Exception);
                args.Handled = true;
                MessageBox.Show($"An error occurred: {args.Exception.Message}", "Error", 
                    MessageBoxButton.OK, MessageBoxImage.Warning);
            };
        }

        protected override void OnExit(ExitEventArgs e)
        {
            Core.Logger.Info("SecureGuard application exiting");
            base.OnExit(e);
        }
    }
}
