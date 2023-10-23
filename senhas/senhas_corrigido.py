

from tkinter import ttk, simpledialog, messagebox, Toplevel, Label, Entry, Button, END
from cryptography.fernet import Fernet
import bcrypt
import hashlib
import base64
import os
import pyperclip
import pyotp
import qrcode
import tkinter as tk
from tkinter import filedialog
from ttkthemes import ThemedTk
import shutil
from database import (register_user, verify_user, store_password_db, retrieve_password_db, store_password_db, retrieve_password_db, store_master_salt,
                      get_master_salt, register_user, verify_user,
                      get_user_data, check_password_history, 
                      update_master_password_in_db, update_password_for_website, 
                      update_website_name, store_password_update_timestamp, has_fa, 
                      get_fa_secret, store_password_in_history, retrieve_all_passwords_for_user, check_password_in_history,
                      reset_failed_attempts, increment_failed_attempts)


# Função corrigida
def is_password_strong(password):
    if len(password) < 12:
        return False
    if not any(char.isupper() for char in password):  # Verifica letras maiúsculas
        return False
    if not any(char.islower() for char in password):  # Verifica letras minúsculas
        return False
    if not any(char.isdigit() for char in password):  # Verifica números
        return False
    if not any(char in '!@#$%^&*()-_+=' for char in password):  # Verifica caracteres especiais
        return False
    return True


class PasswordManager:
    def __init__(self, master_password):
        self.salt = self._get_or_create_salt()
        self.master_key = self._generate_key_from_password(master_password, self.salt)
        self.fernet = Fernet(self.master_key)

    def _get_or_create_salt(self):
        salt = get_master_salt()
        if not salt:
            salt = bcrypt.gensalt()
            store_master_salt(salt)
        return salt

    def _generate_key_from_password(self, password, salt):
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
        derived_key = hashlib.sha256(hashed_password).digest()
        return base64.urlsafe_b64encode(derived_key)

    def store_password(self, user_id, website, username, password):
        encrypted_password = self.fernet.encrypt(password.encode('utf-8'))
        store_password_db(user_id, website, username, encrypted_password)

    def retrieve_password(self, user_id, website):
        data = retrieve_password_db(user_id, website)
        if data:
            decrypted_password = self.fernet.decrypt(data['password']).decode('utf-8')
            return {'username': data['username'], 'password': decrypted_password}
        else:
            return None

    def generate_password(self, length=12):
        return os.urandom(length).hex()

    def authenticate_user(self, input_password):
        try:
            Fernet(self._generate_key_from_password(input_password, self.salt))
            return True
        except:
            return False

    def manage_passwords(manager, user_id):
        def copy_to_clipboard(text):
            pyperclip.copy(text)
            messagebox.showinfo("Copiado", "Texto copiado para a área de transferência!")
        
        def update_website(old_website):
            new_website = simpledialog.askstring("Atualizar URL", f"Digite a nova URL para {old_website}:")
            if new_website:
                update_website_name(user_id, old_website, new_website)
                manage_window.destroy()
                manage_passwords(manager, user_id)

        def update_password(website, old_username, old_password):
            new_username = simpledialog.askstring("Atualizar", f"Digite o novo nome de usuário para {website} (anteriormente {old_username}):")
            new_password = simpledialog.askstring("Atualizar", f"Digite a nova senha para {website}:")
            encrypted_new_password = manager.fernet.encrypt(new_password.encode('utf-8'))
            update_password_for_website(user_id, website, new_username, encrypted_new_password)
            messagebox.showinfo("Atualizado", f"Senha para {website} foi atualizada!")
            # Após atualizar a senha:
            store_password_update_timestamp(user_id, website)

            hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt_from_db)  # Substitua 'salt_from_db' pelo salt que você tem armazenado para esse usuário

            # Verificar se a senha já foi usada anteriormente
            if check_password_history(user_id, website, hashed_password):
                messagebox.showwarning("Erro", "Você já usou essa senha anteriormente. Por favor, escolha uma nova senha.")
                return


        manage_window = Toplevel()
        manage_window.title("Gerenciar Senhas")

        passwords = retrieve_all_passwords_for_user(user_id)

        for password_data in passwords:
            website = password_data['website']
            username = password_data['username']
            decrypted_password = manager.fernet.decrypt(password_data['password']).decode('utf-8')

            website_label = Label(manage_window, text=f"Website: {website}")
            website_label.pack(pady=5)

            username_label = Label(manage_window, text=f"Username: {username}")
            username_label.pack(pady=5)

            password_label = Label(manage_window, text=f"Password: {decrypted_password}")
            password_label.pack(pady=5)

            copy_button = Button(manage_window, text="Copiar", command=lambda password=decrypted_password: copy_to_clipboard(password))
            copy_button.pack(pady=5)

            update_button = Button(manage_window, text="Atualizar", command=lambda website=website, username=username, password=decrypted_password: update_password(website, username, password))
            update_button.pack(pady=5)
            
            update_website_button = Button(manage_window, text="Atualizar URL", command=lambda website=website: update_website(website))
            update_website_button.pack(pady=5)

        def is_password_strong(password):
            if len(password) < 12:
                return False
            if not any(char.isupper() for char in password):  # Verifica letras maiúsculas
                return False
            if not any(char.islower() for char in password):  # Verifica letras minúsculas
                return False
            if not any(char.isdigit() for char in password):  # Verifica números
                return False
            if not any(char in '!@#$%^&*()-_+=' for char in password):  # Verifica caracteres especiais
                return False
            return True

        def update_website(self, user_id, old_website, new_website):
            update_website_name(user_id, old_website, new_website)

        def update_username_password(self, user_id, website, new_username, new_password):
            encrypted_new_password = self.fernet.encrypt(new_password.encode('utf-8'))
            update_password_for_website(user_id, website, new_username, encrypted_new_password)

        def change_master_password(self, old_password, new_password):
            if self.authenticate_user(old_password):
                self.master_key = self._generate_key_from_password(new_password, self.salt)
                self.fernet = Fernet(self.master_key)
                # Aqui, você também pode atualizar a senha mestra no banco de dados
                return True
            else:
                return False

class ScreenManager:
    def __init__(self, master):
        self.master = master
        self.current_frame = None

    def switch_to(self, frame_class, *args, **kwargs):
        if self.current_frame:
            self.current_frame.destroy()
        self.current_frame = frame_class(self.master, *args, **kwargs)
        self.current_frame.pack(expand=True, fill=tk.BOTH)


class LoginScreen(tk.Frame):
    MAX_FAILED_ATTEMPTS = 3

    def __init__(self, master, screen_manager, manager=None, user_id=None):
        super().__init__(master)
        self.master = master
        self.screen_manager = screen_manager
        
        # Widgets
        username_label = Label(self, text="Nome de Usuário:")
        username_label.pack(pady=10)
        self.username_entry = Entry(self)
        self.username_entry.pack(pady=10)

        password_label = Label(self, text="Senha:")
        password_label.pack(pady=10)
        self.password_entry = Entry(self, show="*")
        self.password_entry.pack(pady=10)

        login_btn = Button(self, text="Login", command=self.login)
        login_btn.pack(pady=20)

        register_btn = Button(self, text="Registrar", command=self.open_register_window)
        register_btn.pack(pady=20)

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        user_data = get_user_data(username)

        if user_data and user_data['failed_attempts'] >= self.MAX_FAILED_ATTEMPTS:
            messagebox.showwarning("Bloqueado", "Muitas tentativas malsucedidas. Tente novamente mais tarde.")
            return

        user_id = verify_user(username, password)

        if not user_id:
            increment_failed_attempts(username)
            messagebox.showwarning("Erro", "Nome de usuário ou senha incorretos!")
            return
        
        if user_id:
            if has_fa(username):
                totp = pyotp.TOTP(get_fa_secret(username))
                otp = simpledialog.askstring("2FA", "Digite o código do seu aplicativo autenticador:", parent=self)
                if not totp.verify(otp):
                    messagebox.showwarning("Erro", "Código 2FA inválido!")
                    return
            reset_failed_attempts(username)
            manager = PasswordManager(password)  # Inicialize o PasswordManager aqui
            self.screen_manager.switch_to(MainScreen, self.screen_manager, manager, user_id)  # Mudando para a tela principal

    def open_register_window(self):
        def register():
            username = new_username_entry.get()
            password = new_password_entry.get()
            confirm_password = confirm_password_entry.get()

            if password != confirm_password:
                messagebox.showwarning("Erro", "As senhas não coincidem!")
                return

            # Verificação da força da senha
            if not is_password_strong(password):
                messagebox.showwarning("Erro", "A senha não é forte o suficiente. Certifique-se de que tenha pelo menos 8 caracteres, inclua números, letras e caracteres especiais.")
                return

            if register_user(username, password):
                messagebox.showinfo("Sucesso", "Registrado com sucesso!")
                register_window.destroy()
            else:
                messagebox.showwarning("Erro", "Nome de usuário já existe!")

        register_window = Toplevel(self)
        register_window.title("Registrar")

        new_username_label = Label(register_window, text="Nome de Usuário:")
        new_username_label.pack(pady=10)
        new_username_entry = Entry(register_window)
        new_username_entry.pack(pady=10)

        new_password_label = Label(register_window, text="Senha:")
        new_password_label.pack(pady=10)
        new_password_entry = Entry(register_window, show="*")
        new_password_entry.pack(pady=10)

        confirm_password_label = Label(register_window, text="Confirmar Senha:")
        confirm_password_label.pack(pady=10)
        confirm_password_entry = Entry(register_window, show="*")
        confirm_password_entry.pack(pady=10)

        register_btn = Button(register_window, text="Registrar", command=register)
        register_btn.pack(pady=20)

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        user_data = get_user_data(username)

        if user_data and user_data['failed_attempts'] >= self.MAX_FAILED_ATTEMPTS:
            messagebox.showwarning("Bloqueado", "Muitas tentativas malsucedidas. Tente novamente mais tarde.")
            return

        user_id = verify_user(username, password)

        if not user_id:
            increment_failed_attempts(username)
            messagebox.showwarning("Erro", "Nome de usuário ou senha incorretos!")
            return
        
        if user_id:
            if has_fa(username):
                totp = pyotp.TOTP(get_fa_secret(username))
                otp = simpledialog.askstring("2FA", "Digite o código do seu aplicativo autenticador:", parent=self)
                if not totp.verify(otp):
                    messagebox.showwarning("Erro", "Código 2FA inválido!")
                    return
            reset_failed_attempts(username)
            manager = PasswordManager(password)  # Inicialize o PasswordManager aqui
            self.screen_manager.switch_to(MainScreen, self.screen_manager, manager, user_id)  # Mudando para a tela principal

    def open_register_window(self):
        def register():
            username = new_username_entry.get()
            password = new_password_entry.get()
            confirm_password = confirm_password_entry.get()

            if password != confirm_password:
                messagebox.showwarning("Erro", "As senhas não coincidem!")
                return

            # Verificação da força da senha
            if not is_password_strong(password):
                messagebox.showwarning("Erro", "A senha não é forte o suficiente. Certifique-se de que tenha pelo menos 8 caracteres, inclua números, letras e caracteres especiais.")
                return

            if register_user(username, password):
                messagebox.showinfo("Sucesso", "Registrado com sucesso!")
                register_window.destroy()
            else:
                messagebox.showwarning("Erro", "Nome de usuário já existe!")

        register_window = Toplevel(self)
        register_window.title("Registrar")

        new_username_label = Label(register_window, text="Nome de Usuário:")
        new_username_label.pack(pady=10)
        new_username_entry = Entry(register_window)
        new_username_entry.pack(pady=10)

        new_password_label = Label(register_window, text="Senha:")
        new_password_label.pack(pady=10)
        new_password_entry = Entry(register_window, show="*")
        new_password_entry.pack(pady=10)

        confirm_password_label = Label(register_window, text="Confirmar Senha:")
        confirm_password_label.pack(pady=10)
        confirm_password_entry = Entry(register_window, show="*")
        confirm_password_entry.pack(pady=10)

        register_btn = Button(register_window, text="Registrar", command=register)
        register_btn.pack(pady=20)

pass

def toggle_2fa():
    username = "user_example"
    
    secret = get_2fa_secret(username)
    if secret:  # Se o 2FA estiver ativado, desative
        store_2fa_secret(username, None)
        messagebox.showinfo("2FA", "2FA desativado com sucesso!")
    else:  # Se o 2FA estiver desativado, ative
        secret = pyotp.random_base32()
        store_2fa_secret(username, secret)
        totp = pyotp.TOTP(secret)
        uri = totp.provisioning_uri(username, issuer_name="Asun Password Manager")
        img = qrcode.make(uri)
        img.show()
        messagebox.showinfo("2FA", "2FA ativado com sucesso! Escaneie o QR Code com seu aplicativo autenticador.")
    

class MainScreen(tk.Frame):
    def __init__(self, master, screen_manager, manager, user_id):
        super().__init__(master)
        self.master = master
        self.screen_manager = screen_manager
        self.manager = manager
        self.user_id = user_id

        # Widgets
        title_label = Label(self, text="Asun Password Manager", font=("Arial", 16, "bold"), bg="#FFFFFF")
        title_label.pack(pady=20)

        website_label = ttk.Label(self, text="Website:")
        website_label.pack(pady=5)
        self.website_entry = ttk.Entry(self, width=40)
        self.website_entry.pack(pady=5)

        username_label = ttk.Label(self, text="Username:")
        username_label.pack(pady=5)
        self.username_entry = ttk.Entry(self, width=40)
        self.username_entry.pack(pady=5)

        password_label = ttk.Label(self, text="Password:")
        password_label.pack(pady=5)
        self.password_entry = ttk.Entry(self, width=40)
        self.password_entry.pack(pady=5)

        store_btn = ttk.Button(self, text="Armazenar Senha", command=self.store_password)
        store_btn.pack(pady=10)

        retrieve_btn = ttk.Button(self, text="Recuperar Senha", command=self.retrieve_password)
        retrieve_btn.pack(pady=10)

        generate_btn = ttk.Button(self, text="Gerar Senha", command=self.generate_password)
        generate_btn.pack(pady=10)

        change_master_password_btn = ttk.Button(self, text="Alterar Senha Mestra", command=self.change_master_password)
        change_master_password_btn.pack(pady=10)

        manage_btn = ttk.Button(self, text="Gerenciar Senhas", command=self.manage_passwords)
        manage_btn.pack(pady=10)

        toggle_2fa_btn = ttk.Button(self, text="Ativar/Desativar 2FA", command=toggle_2fa)
        toggle_2fa_btn.pack(pady=10)
    
    def store_password(self):
        website = self.website_entry.get()
        username = self.username_entry.get()
        password = self.password_entry.get()
        if not website or not username or not password:
            messagebox.showwarning("Atenção", "Por favor, preencha todos os campos!")
            return
        self.manager.store_password(self.user_id, website, username, password)
        self.website_entry.delete(0, END)
        self.username_entry.delete(0, END)
        self.password_entry.delete(0, END)
        messagebox.showinfo("Sucesso", "Senha armazenada com sucesso!")

    
        
        # Verificando se a senha atende aos critérios de complexidade
        if not is_password_strong(password):
            messagebox.showwarning("Erro", "A senha não atende aos critérios de complexidade. Ela deve ter pelo menos 12 caracteres, combinar letras maiúsculas, minúsculas, números e caracteres especiais.")
            return

        # Verificando se a senha foi atualizada nos últimos 90 dias
        last_update = get_last_password_update_for_website(user_id, website)  # Esta função ainda não foi implementada!
        if last_update and (datetime.now() - last_update).days > 90:
            messagebox.showwarning("Atenção", f"Sua senha para o site {website} não é atualizada há mais de 90 dias. Você deve considerar atualizá-la.")
        # Após armazenar a senha:
        store_password_update_timestamp(user_id, website)  # Esta função armazena o momento da atualização da senha


    def retrieve_password():
        websites = get_all_websites(user_id)
        if not websites:
            messagebox.showinfo("Informação", "Nenhuma senha armazenada ainda!")
            return

        msg = "Selecione um site para recuperar a senha:\n\n"
        for idx, website in enumerate(websites, 1):
            msg += f"{idx}. {website}\n"

        site_number = simpledialog.askinteger("Recuperar Senha", msg)
        
        if not site_number or site_number < 1 or site_number > len(websites):
            messagebox.showwarning("Atenção", "Número inválido!")
            return

        website = websites[site_number - 1]
        password_data = manager.retrieve_password(user_id, website)
        if password_data:
            result_text = f"Website: {website}\nUsername: {password_data['username']}\nSenha: {password_data['password']}"
            messagebox.showinfo("Senha Recuperada", result_text)
        else:
            messagebox.showwarning("Atenção", "Senha não encontrada!")
            
    def generate_password():
        length = simpledialog.askinteger("Gerar Senha", "Tamanho da senha (padrão 12):", initialvalue=12)
        if not length:
            return
        generated_password = manager.generate_password(length)
        messagebox.showinfo("Senha Gerada", f"Senha: {generated_password}")

    def change_master_password(manager, user_id):
            current_password = simpledialog.askstring("Alterar Senha Mestra", "Digite sua senha atual:", show='*')
            if not manager.authenticate_user(current_password):
                messagebox.showwarning("Erro", "Senha atual incorreta!")
                return
            
            new_password = simpledialog.askstring("Alterar Senha Mestra", "Digite a nova senha:", show='*')
            confirm_new_password = simpledialog.askstring("Alterar Senha Mestra", "Confirme a nova senha:", show='*')
            
            if new_password != confirm_new_password:
                messagebox.showwarning("Erro", "As senhas não coincidem!")
                return

            if not is_password_strong(new_password):
                messagebox.showwarning("Erro", "A nova senha não é forte o suficiente. Certifique-se de que tenha pelo menos 8 caracteres, inclua números, letras e caracteres especiais.")
                return

            salt = bcrypt.gensalt()
            hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), salt)
            update_master_password_in_db(user_id, new_password) # Supondo que você tenha uma função assim no database.py

            messagebox.showinfo("Sucesso", "Senha mestra alterada com sucesso!")

            # Verificar se a nova senha é única
            new_salt = bcrypt.gensalt()
            new_hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), new_salt)
            if check_password_in_history(user_id, new_hashed_password):
                messagebox.showwarning("Erro", "Essa senha já foi usada anteriormente. Escolha uma nova senha.")
                return
        # Armazenar a senha mestra atual no histórico antes de atualizá-la
            current_hashed_password = bcrypt.hashpw(current_password.encode('utf-8'), manager.salt)
            store_password_in_history(user_id, current_hashed_password)

    def manage_passwords(self):
        manage_passwords(self.manager, self.user_id)

        def edit_website(old_website):
            new_website = simpledialog.askstring("Editar Website", "Digite o novo website:", initialvalue=old_website)
            if new_website and new_website != old_website:
                manager.update_website(user_id, old_website, new_website)
                manage_window.destroy()
                manage_passwords(manager, user_id)

    def edit_username_password(website, old_username, old_password):
        new_username = simpledialog.askstring("Editar Username", "Digite o novo nome de usuário:", initialvalue=old_username)
        new_password = simpledialog.askstring("Editar Senha", "Digite a nova senha:", show='*')
        
        if new_username and new_password and (new_username != old_username or new_password != old_password):
            if not is_password_strong(new_password):
                messagebox.showwarning("Erro", "A senha não é forte o suficiente!")
                return
            manager.update_username_password(user_id, website, new_username, new_password)
            manage_window.destroy()
            manage_passwords(manager, user_id)

    def change_master_password(self):
        current_password = simpledialog.askstring("Alterar Senha Mestra", "Digite sua senha atual:", show='*')
        if not self.manager.authenticate_user(current_password):
            messagebox.showwarning("Erro", "Senha atual incorreta!")
            return
        
        new_password = simpledialog.askstring("Alterar Senha Mestra", "Digite a nova senha:", show='*')
        confirm_new_password = simpledialog.askstring("Alterar Senha Mestra", "Confirme a nova senha:", show='*')
        
        if new_password != confirm_new_password:
            messagebox.showwarning("Erro", "As senhas não coincidem!")
            return

        if self.manager.change_master_password(current_password, new_password):
            messagebox.showinfo("Sucesso", "Senha mestra alterada com sucesso!")
        else:
            messagebox.showwarning("Erro", "Falha ao alterar a senha mestra!")


def main():
  def main():
    root = ThemedTk(theme="arc")
    root.title("Asun Password Manager")
    screen_manager = ScreenManager(root)
    screen_manager.switch_to(LoginScreen, screen_manager)
    root.mainloop()


if __name__ == "__main__":
    main()

