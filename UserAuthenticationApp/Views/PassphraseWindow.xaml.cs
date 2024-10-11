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

        private void OKButton_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrEmpty(PassphraseBox.Password))
            {
                ErrorMessageTextBlock.Text = "Парольная фраза не может быть пустой.";
                return;
            }

            Passphrase = PassphraseBox.Password;
            this.DialogResult = true;
            this.Close();
        }

        private void CancelButton_Click(object sender, RoutedEventArgs e)
        {
            this.DialogResult = false;
            this.Close();
        }
    }
}
