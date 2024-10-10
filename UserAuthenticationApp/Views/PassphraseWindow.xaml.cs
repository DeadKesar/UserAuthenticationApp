using System.Windows;

namespace UserAuthenticationApp.Views
{
    public partial class PassphraseWindow : Window
    {
        public string Passphrase { get; private set; }

        public PassphraseWindow()
        {
            InitializeComponent();
        }

        private void OkButton_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrEmpty(PassphraseBox.Password))
            {
                MessageBox.Show("Пожалуйста, введите парольную фразу.", "Предупреждение", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            Passphrase = PassphraseBox.Password;
            DialogResult = true;
            Close();
        }

        private void CancelButton_Click(object sender, RoutedEventArgs e)
        {
            DialogResult = false;
            Close();
        }
    }
}
