using System;
using System.Linq;
using System.Collections.Generic;
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
            var selectedUsers = UsersListView.SelectedItems.Cast<User>().ToList();

            if (selectedUsers.Any())
            {
                foreach (var user in selectedUsers)
                {
                    if (user.Username.Equals("ADMIN", StringComparison.OrdinalIgnoreCase))
                    {
                        MessageBox.Show("Нельзя заблокировать администратора.", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
                        continue;
                    }

                    user.IsBlocked = !user.IsBlocked;
                    _userRepository.UpdateUser(user);
                }

                _userRepository.SaveUsers(_key, _iv);
                LoadUsers(); // Обновляем список пользователей
            }
            else
            {
                MessageBox.Show("Выберите хотя бы одного пользователя.", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

        // Обработчик для кнопки "Ограничения на пароли"
        private void TogglePasswordRestrictionsButton_Click(object sender, RoutedEventArgs e)
        {
            var selectedUsers = UsersListView.SelectedItems.Cast<User>().ToList();

            if (selectedUsers.Any())
            {
                foreach (var user in selectedUsers)
                {
                    if (user.Username.Equals("ADMIN", StringComparison.OrdinalIgnoreCase))
                    {
                        MessageBox.Show("Нельзя изменять ограничения на пароли для администратора.", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Error);
                        continue;
                    }

                    user.PasswordRestrictionsEnabled = !user.PasswordRestrictionsEnabled;
                    _userRepository.UpdateUser(user);
                }

                _userRepository.SaveUsers(_key, _iv);
                LoadUsers(); // Обновляем список пользователей
            }
            else
            {
                MessageBox.Show("Выберите хотя бы одного пользователя.", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Warning);
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

        // Обработчик для кнопки "Вверх"
        private void MoveUpButton_Click(object sender, RoutedEventArgs e)
        {
            var selectedUsers = UsersListView.SelectedItems.Cast<User>().ToList();
            var usersList = _userRepository.GetAllUsers();

            foreach (var user in selectedUsers)
            {
                int index = usersList.IndexOf(user);
                if (index > 0)
                {
                    usersList.RemoveAt(index);
                    usersList.Insert(index - 1, user);
                }
            }

            _userRepository.SaveUsers(_key, _iv);
            LoadUsers();
        }

        // Обработчик для кнопки "Вниз"
        private void MoveDownButton_Click(object sender, RoutedEventArgs e)
        {
            var selectedUsers = UsersListView.SelectedItems.Cast<User>().ToList();
            var usersList = _userRepository.GetAllUsers();

            foreach (var user in selectedUsers)
            {
                int index = usersList.IndexOf(user);
                if (index < usersList.Count - 1)
                {
                    usersList.RemoveAt(index);
                    usersList.Insert(index + 1, user);
                }
            }

            _userRepository.SaveUsers(_key, _iv);
            LoadUsers();
        }
        private void ResetPasswordButton_Click(object sender, RoutedEventArgs e)
        {
            var selectedUsers = UsersListView.SelectedItems.Cast<User>().ToList();

            if (selectedUsers.Any())
            {
                foreach (var user in selectedUsers)
                {

                    // Генерируем новую соль и хешируем пустой пароль
                    byte[] newSalt = _cryptoService.GenerateSalt();
                    byte[] newPasswordHash = _cryptoService.HashPassword(string.Empty, newSalt);

                    // Обновляем данные пользователя
                    user.Salt = newSalt;
                    user.PasswordHash = newPasswordHash;

                    // Сохраняем обновленного пользователя
                    _userRepository.UpdateUser(user);
                }

                _userRepository.SaveUsers(_key, _iv);
                LoadUsers(); // Перезагружаем список пользователей
                MessageBox.Show("Пароль(и) успешно сброшены.", "Успех", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            else
            {
                MessageBox.Show("Выберите хотя бы одного пользователя.", "Ошибка", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }

    }
}
