using System;
using System.Linq;
using System.Windows;
using UserAuthenticationApp.Models;
using UserAuthenticationApp.Services;

namespace UserAuthenticationApp.Views
{
    public partial class AdminWindow : Window
    {
        private readonly UserRepository _userRepository;
        private readonly CryptoService _cryptoService;
        private readonly byte[] _key;
        private readonly byte[] _iv;

        public AdminWindow(UserRepository userRepository, CryptoService cryptoService, byte[] key, byte[] iv)
        {
            InitializeComponent();

            _userRepository = userRepository ?? throw new ArgumentNullException(nameof(userRepository));
            _cryptoService = cryptoService ?? throw new ArgumentNullException(nameof(cryptoService));
            _key = key ?? throw new ArgumentNullException(nameof(key));
            _iv = iv ?? throw new ArgumentNullException(nameof(iv));

            LoadUsers();
        }

        // Метод для загрузки пользователей и отображения в списке
        private void LoadUsers()
        {
            UsersListView.ItemsSource = null;
            UsersListView.ItemsSource = _userRepository.GetAllUsers();
        }

        // Обработчик для кнопки "Добавить пользователя"
        private void AddUserButton_Click(object sender, RoutedEventArgs e)
        {
            var newUserWindow = new NewUserWindow(_userRepository, _cryptoService, _key, _iv);
            if (newUserWindow.ShowDialog() == true)
            {
                LoadUsers(); // Перезагружаем список после добавления пользователя
            }
        }

        // Обработчик для кнопки "Блокировать/Разблокировать"
        private void BlockUnblockButton_Click(object sender, RoutedEventArgs e)
        {
            if (UsersListView.SelectedItem is User selectedUser)
            {
                // Нельзя заблокировать администратора
                if (selectedUser.Username.Equals("ADMIN", StringComparison.OrdinalIgnoreCase))
                {
                    MessageBox.Show("Нельзя заблокировать администратора.", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
                    return;
                }

                selectedUser.IsBlocked = !selectedUser.IsBlocked;
                _userRepository.UpdateUser(selectedUser);
                _userRepository.SaveUsers(_key, _iv);
                LoadUsers(); // Обновляем список пользователей
            }
            else
            {
                MessageBox.Show("Выберите пользователя для блокировки/разблокировки.", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        // Обработчик для кнопки "Ограничения на пароли"
        private void TogglePasswordRestrictionsButton_Click(object sender, RoutedEventArgs e)
        {
            if (UsersListView.SelectedItem is User selectedUser)
            {
                // Нельзя изменять ограничения на пароли администратора
                if (selectedUser.Username.Equals("ADMIN", StringComparison.OrdinalIgnoreCase))
                {
                    MessageBox.Show("Нельзя изменять ограничения на пароли для администратора.", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
                    return;
                }

                selectedUser.PasswordRestrictionsEnabled = !selectedUser.PasswordRestrictionsEnabled;
                _userRepository.UpdateUser(selectedUser);
                _userRepository.SaveUsers(_key, _iv);
                LoadUsers(); // Обновляем список пользователей
            }
            else
            {
                MessageBox.Show("Выберите пользователя для изменения ограничений на пароль.", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        // Обработчик для кнопки "Сменить пароль"
        private void ChangeAdminPasswordButton_Click(object sender, RoutedEventArgs e)
        {
            var changePasswordWindow = new ChangePasswordWindow(_userRepository, _cryptoService, _key, _iv, "ADMIN");
            changePasswordWindow.ShowDialog();
        }

        // Обработчик меню "Справка" -> "О программе"
        private void AboutMenuItem_Click(object sender, RoutedEventArgs e)
        {
            var aboutWindow = new AboutWindow();
            aboutWindow.ShowDialog();
        }

        // Обработчик меню "Файл" -> "Выйти"
        private void ExitMenuItem_Click(object sender, RoutedEventArgs e)
        {
            Application.Current.Shutdown();
        }
    }
}
