import datetime
from tkinter import BooleanVar, Checkbutton, StringVar, ttk, simpledialog, messagebox, Toplevel, Label, Entry, Button, END
from cryptography.fernet import Fernet
from tkinter import filedialog
import shutil
import bcrypt
import hashlib
import base64
import os
import pyperclip
import pyotp
import qrcode
import tkinter as tk
import random
import string
import torch
import time
from transformers import GPT2LMHeadModel, GPT2Tokenizer
from ttkthemes import ThemedTk
from database import (register_user, store_fa_secret, verify_user, store_password_db, retrieve_password_db, store_master_salt,
                      get_master_salt, get_user_data, check_password_history, restore_database, 
                      update_master_password_in_db, update_password_for_website, get_last_password_update,
                      update_website_name, store_password_db, backup_database, increment_failed_attempts,  get_all_websites, store_password_update_timestamp, has_fa, 
                      get_fa_secret, store_password_in_history, retrieve_all_passwords_for_user, check_password_in_history,
                      reset_failed_attempts, increment_failed_attempts)

class PasswordSuggester:
    def __init__(self):
        self.tokenizer = GPT2Tokenizer.from_pretrained("gpt2")
        self.model = GPT2LMHeadModel.from_pretrained("gpt2")
    
    def suggest_passwords(self, num_suggestions=1):
        # Base da senha
        password_base = "Asun" + random.choice(string.punctuation)
        
        # Gere palavras memoráveis
        input_text = random.choice(["fruta", "legume", "cor", "animal"])
        input_ids = self.tokenizer.encode(input_text, return_tensors='pt')
        attention_mask = torch.tensor([1] * len(input_ids[0])).unsqueeze(0)
        output = self.model.generate(
        input_ids, 
        attention_mask=attention_mask, 
        pad_token_id=self.tokenizer.eos_token_id, 
        max_length=12, 
        num_beams=5, 
        temperature=1.5, 
        do_sample=True,  # Adicione esta linha
        num_return_sequences=num_suggestions, 
        no_repeat_ngram_size=2
        )

        # Decodifica os IDs do modelo para obter as palavras memoráveis
        memorable_words = [self.tokenizer.decode(ids, skip_special_tokens=True) for ids in output]

        # Processa as palavras memoráveis para remover pontos ou quebras de linha
        processed_words = [word.split('.')[0].split('\n')[0] for word in memorable_words]
        
        # Junte tudo para criar as sugestões de senha
        passwords = [password_base + word + str(random.randint(100,999)) for word in processed_words]
        
        return passwords




    def is_password_strong(self, password):
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

    def generate_memorable_phrase(self, seed_word="segurança"):
        prompt = f"Uma frase memorável sobre {seed_word} é:"
        input_ids = self.tokenizer.encode(prompt, return_tensors='pt')
        attention_mask = torch.tensor([1] * len(input_ids[0])).unsqueeze(0)
        output = self.model.generate(
            input_ids, 
            attention_mask=attention_mask, 
            pad_token_id=self.tokenizer.eos_token_id, 
            max_length=50, 
            num_beams=5, 
            temperature=1.5,
            do_sample=True,
            no_repeat_ngram_size=2
        )
        phrase = self.tokenizer.decode(output[0], skip_special_tokens=True).split(":")[1].strip()
        return phrase
    
    def generate_security_question(self, keyword):
        prompt = f"Crie uma pergunta de segurança relacionada a {keyword}:"
        input_ids = self.tokenizer.encode(prompt, return_tensors='pt')
        attention_mask = torch.tensor([1] * len(input_ids[0])).unsqueeze(0)
        output = self.model.generate(
            input_ids, 
            attention_mask=attention_mask, 
            pad_token_id=self.tokenizer.eos_token_id, 
            max_length=100, 
            num_beams=5, 
            temperature=1.5,
            do_sample=True,
            no_repeat_ngram_size=2
        )
        question = self.tokenizer.decode(output[0], skip_special_tokens=True).split(":")[1].strip()
        return question

    def get_help_response(self, query):
        input_ids = self.tokenizer.encode(query, return_tensors='pt')
        attention_mask = torch.tensor([1] * len(input_ids[0])).unsqueeze(0)
        output = self.model.generate(
            input_ids, 
            attention_mask=attention_mask, 
            pad_token_id=self.tokenizer.eos_token_id, 
            max_length=100, 
            num_beams=5, 
            temperature=1.5,
            do_sample=True,
            no_repeat_ngram_size=2
        )
        response = self.tokenizer.decode(output[0], skip_special_tokens=True)
        return response



 # No seu código atual, adicione uma instância da classe PasswordSuggester
password_suggester = PasswordSuggester()
# Agora, quando você quiser gerar uma sugestão de senha, faça o seguinte:
suggested_passwords = password_suggester.suggest_passwords()
print(suggested_passwords)  # Isto é apenas para visualização. Na sua aplicação, você pode mostrar as sugestões ao usuário.

password_suggester = PasswordSuggester()

def toggle_2fa(username):
    secret = get_fa_secret(username)  # Recuperando o secret para verificar se o 2FA está ativado.
    
    if not secret:  # Se o 2FA estiver desativado, ative
        secret = pyotp.random_base32()
        store_fa_secret(username, secret)
        totp = pyotp.TOTP(secret)
        uri = totp.provisioning_uri(username, issuer_name="Gerenciador de Senhas Asun")
        img = qrcode.make(uri)
        img.show()
        messagebox.showinfo("2FA", "2FA ativado com sucesso! Escaneie o QR Code com seu aplicativo autenticador.")
    else:  # Se o 2FA estiver ativado, desative
        store_fa_secret(username, None)
        messagebox.showinfo("2FA", "2FA desativado com sucesso!")

    

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
        if length < 12:
            raise ValueError("Password length should be at least 12 characters")

        # Garantindo que todos os critérios sejam atendidos
        password = [
            random.choice(string.ascii_uppercase),   # uma letra maiúscula
            random.choice(string.ascii_lowercase),   # uma letra minúscula
            random.choice(string.digits),            # um número
            random.choice('!@#$%^&*()-_+=')          # um caractere especial
        ]

        # Preenchendo o restante da senha aleatoriamente
        for _ in range(length - 4):
            password.append(random.choice(string.ascii_letters + string.digits + '!@#$%^&*()-_+='))

        # Embaralhando a lista de caracteres para garantir aleatoriedade
        random.shuffle(password)

        # Convertendo a lista de caracteres para uma string
        return ''.join(password)
    
    def authenticate_user(self, input_password):
        try:
            Fernet(self._generate_key_from_password(input_password, self.salt))
            return True
        except:
            return False

    
    def update_website(old_website,self):
        new_website = simpledialog.askstring("Atualizar URL", f"Digite a nova URL para {old_website}:")
        if new_website:
            update_website_name(self.user_id, old_website, new_website)
            manage_window.destroy()
            self.manage_passwords(self.manager, self.user_id)

        

        manage_window = Toplevel()
        manage_window.title("Gerenciar Senhas")

        passwords = retrieve_all_passwords_for_user(self.user_id)

        for password_data in passwords:
            website = password_data['website']
            username = password_data['username']
            decrypted_password = self.manager.fernet.decrypt(password_data['password']).decode('utf-8')

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
            
            update_website_button = Button(manage_window, text="Atualizar URL", command=lambda website=website: self.update_website(website))
            update_website_button.pack(pady=5)

       
        
    def update_website(self, user_id, old_website, new_website):
        update_website_name(user_id, old_website, new_website)
    def update_username_password(self, user_id, website, new_username, new_password):
            encrypted_new_password = self.fernet.encrypt(new_password.encode('utf-8'))
            update_password_for_website(user_id, website, new_username, encrypted_new_password)
            encrypted_new_username = new_username  # Isso supõe que o nome de usuário não é criptografado
            update_password_for_website(user_id, website, encrypted_new_username, encrypted_new_password)


    def change_master_password(self, old_password, new_password):
        if self.authenticate_user(old_password):
            self.master_key = self._generate_key_from_password(new_password, self.salt)
            self.fernet = Fernet(self.master_key)
            # Aqui, você também pode atualizar a senha mestra no banco de dados
            return True
        else:
            return False
    
    def phrase_to_password(phrase):
        substitutions = {
            'a': '@',
            'o': '0',
            'e': '3',
            's': '$',
            'i': '!',
            ' ': '_'
        }
        password = ''.join([substitutions.get(c, c) for c in phrase.lower()])
        return password


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

        help_button = Button(self, text="Ajuda Interativa", command=self.open_help_window)
        help_button.pack(pady=10)


        login_btn = Button(self, text="Login", command=self.login)
        login_btn.pack(pady=20)

        register_btn = Button(self, text="Registrar", command=self.open_register_window)
        register_btn.pack(pady=20)

    def open_help_window(self):
        def get_help():
            user_question = help_entry.get()
            if not user_question.strip():  # if it's empty or just spaces
                messagebox.showwarning("Erro", "Por favor, insira uma pergunta.")
                return
            # Using GPT-2 to generate a response
            answer = self.generate_help_response(user_question)
            help_response_label.config(text=answer)

        help_window = Toplevel(self)
        help_window.title("Ajuda Interativa")

        help_label = Label(help_window, text="Como posso ajudar?")
        help_label.pack(pady=10)

        help_entry = Entry(help_window)
        help_entry.pack(pady=10)

        help_btn = Button(help_window, text="Obter Ajuda", command=get_help)
        help_btn.pack(pady=10)

        help_response_label = Label(help_window, text="")
        help_response_label.pack(pady=10)    


    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        user_data = get_user_data(username)

        if user_data and user_data['failed_attempts'] >= self.MAX_FAILED_ATTEMPTS:
            last_failed_time = user_data['last_failed_time']  # Supondo que você armazene o último tempo de falha no banco de dados
            if datetime.datetime.now() - last_failed_time < datetime.timedelta(minutes=15):
                remaining_time = 15 - (datetime.datetime.now() - last_failed_time).seconds // 60
                messagebox.showwarning("Bloqueado", f"Muitas tentativas malsucedidas. Tente novamente em {remaining_time} minutos.")
                return
        else:
            reset_failed_attempts(username)

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
            password = password_var.get()  # Atualizado para usar password_var
            confirm_password = confirm_password_entry.get()
           
            if password != confirm_password:
                messagebox.showwarning("Erro", "As senhas não coincidem!")
                return

            # Verificação da força da senha
            if not password_suggester.is_password_strong(password):
                messagebox.showwarning("Erro", "A senha não é forte o suficiente. Certifique-se de que tenha pelo menos 8 caracteres, inclua números, letras e caracteres especiais.")
                return

            if register_user(username, password):
                messagebox.showinfo("Sucesso", "Registrado com sucesso!")
                register_window.destroy()
            else:
                messagebox.showwarning("Erro", "Nome de usuário já existe!")

        register_window = Toplevel(self)
        register_window.title("Registrar")

        self.show_password_var = BooleanVar(value=False)

        def toggle_password_visibility():
            if self.show_password_var.get():
                new_password_entry.config(show='')  # Mostrar senha
            else:
                new_password_entry.config(show='*')  # Ocultar senha

        new_username_label = Label(register_window, text="Nome de Usuário:")
        new_username_label.pack(pady=10)
        new_username_entry = Entry(register_window)
        new_username_entry.pack(pady=10)

        suggested_password = password_suggester.suggest_passwords(num_suggestions=1)[0]  # Sugestão de senha
        password_var = StringVar()  # Variável tkinter
        password_var.set(suggested_password)  # Definindo a senha sugerida como valor padrão

        new_password_label = Label(register_window, text="Senha:")
        new_password_label.pack(pady=10)
        new_password_entry = Entry(register_window, show="*", textvariable=password_var)
        new_password_entry.pack(pady=10)

        show_password_check = Checkbutton(register_window, text="Mostrar Senha", variable=self.show_password_var, command=toggle_password_visibility)
        show_password_check.pack(pady=10)

        def suggest_and_show_password():
            suggested_password = password_suggester.suggest_passwords()[0]
            messagebox.showinfo("Sugestão de Senha", f"Sua sugestão de senha é: {suggested_password}")
            new_password_entry.delete(0, END)
            new_password_entry.insert(0, suggested_password)

        suggest_password_btn = Button(register_window, text="Sugerir Senha", command=suggest_and_show_password)
        suggest_password_btn.pack(pady=10)

        confirm_password_label = Label(register_window, text="Confirmar Senha:")
        confirm_password_label.pack(pady=10)
        confirm_password_entry = Entry(register_window, show="*")
        confirm_password_entry.pack(pady=10)

        register_btn = Button(register_window, text="Registrar", command=register)
        register_btn.pack(pady=20)

        def copy_to_clipboard(text):
            self.clipboard_clear()
            self.clipboard_append(text)
            self.update()  # Agora o texto está na área de transferência.
        def copy_suggested_password():
            password = new_password_entry.get()
            copy_to_clipboard(password)

        copy_password_btn = Button(register_window, text="Copiar Senha", command=copy_suggested_password)
        copy_password_btn.pack(pady=10)

    def generate_help_response(self, question):
        # Defina o prompt usando a pergunta do usuário
        prompt = f"Usuário: {question}\nResposta: "
        
        # Encode the prompt
        input_ids = password_suggester.tokenizer.encode(prompt, return_tensors='pt')
        attention_mask = torch.tensor([1] * len(input_ids[0])).unsqueeze(0)
        response = password_suggester.model.generate(
            input_ids, 
            attention_mask=attention_mask, 
            pad_token_id=password_suggester.tokenizer.eos_token_id, 
            max_length=200, 
            num_beams=5, 
            temperature=1.5,
            do_sample=True,
            no_repeat_ngram_size=2
        )
        # Decodificar a resposta gerada
        full_text = password_suggester.tokenizer.decode(response[0], skip_special_tokens=True)
        # Extrair apenas a parte da resposta
        answer = full_text.split("Resposta: ")[1].strip()

        return answer

    pass


class MainScreen(tk.Frame):
    def __init__(self, master, screen_manager, manager, user_id):
        super().__init__(master)
        self.master = master
        self.screen_manager = screen_manager
        self.manager = manager
        self.user_id = user_id
        self.manage_window = None

        # Widgets
        title_label = Label(self, text="Gerenciador de Senhas Asun", font=("Arial", 16, "bold"), bg="#FFFFFF")
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

        toggle_2fa_btn = ttk.Button(self, text="Ativar/Desativar 2FA", command=lambda: toggle_2fa(self.username_entry.get()))
        toggle_2fa_btn.pack(pady=10)
    
        backup_btn = ttk.Button(self, text="Backup do Banco de Dados", command=lambda: backup_database(self.manager))
        backup_btn.pack(pady=10)

        restore_btn = ttk.Button(self, text="Restaurar Banco de Dados", command=lambda: restore_database(self.manager))
        restore_btn.pack(pady=10)
    

    def store_password(self):
        website = self.website_entry.get()
        username = self.username_entry.get()
        password = self.password_entry.get()

        if not website or not username or not password:
            messagebox.showwarning("Atenção", "Por favor, preencha todos os campos!")
            return
        
        # Verificando se a senha atende aos critérios de complexidade
        if not password_suggester.is_password_strong(password):
            messagebox.showwarning("Erro", "A senha não atende aos critérios de complexidade. Ela deve ter pelo menos 12 caracteres, combinar letras maiúsculas, minúsculas, números e caracteres especiais.")
            return

        # Verificando se a senha foi atualizada nos últimos 90 dias
        #last_update = get_last_password_update(self.user_id, website)
        #if last_update and (datetime.datetime.now() - last_update).days > 90:
         #   messagebox.showwarning("Atenção", f"Sua senha para o site {website} não é atualizada há mais de 90 dias. Você deve considerar atualizá-la.")

        # Após armazenar a senha, atualiza o registro de tempo
        store_password_update_timestamp(self.user_id, website)

        self.manager.store_password(self.user_id, website, username, password)
        self.website_entry.delete(0, END)
        self.username_entry.delete(0, END)
        self.password_entry.delete(0, END)
        messagebox.showinfo("Sucesso", "Senha armazenada com sucesso!")
        
        # Após armazenar a senha, atualiza o registro de tempo
        store_password_update_timestamp(self.user_id, website)
        
        # Verificando se a senha atende aos critérios de complexidade
        if not password_suggester.is_password_strong(password):
            messagebox.showwarning("Erro", "A senha não atende aos critérios de complexidade. Ela deve ter pelo menos 12 caracteres, combinar letras maiúsculas, minúsculas, números e caracteres especiais.")
            return

        # Verificando se a senha foi atualizada nos últimos 90 dias
        last_update = get_last_password_update(self.user_id)  # Esta função ainda não foi implementada!
        if last_update and (datetime.now() - last_update).days > 90:
            messagebox.showwarning("Atenção", f"Sua senha para o site {website} não é atualizada há mais de 90 dias. Você deve considerar atualizá-la.")
        # Após armazenar a senha:
        store_password_update_timestamp(self.user_id, website)  # Esta função armazena o momento da atualização da senha


    def retrieve_password(self):
        websites = get_all_websites(self.user_id)

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
        password_data = self.manager.retrieve_password(self.user_id, website)

        if password_data:
            result_text = f"Website: {website}\nUsername: {password_data['username']}\nSenha: {password_data['password']}"
            messagebox.showinfo("Senha Recuperada", result_text)
        else:
            messagebox.showwarning("Atenção", "Senha não encontrada!")
            
    def generate_password(self):
        length = simpledialog.askinteger("Gerar Senha", "Tamanho da senha (padrão 12):", initialvalue=12)
        if not length:
            return
        suggested_passwords = password_suggester.suggest_passwords()
        generated_password = suggested_passwords[0]  # pegando a primeira sugestão


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

            if not password_suggester.is_password_strong(new_password):
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
        self.manage_window = Toplevel(self.master)
        self.manage_window.title("Gerenciar Senhas")
        websites = retrieve_all_passwords_for_user(self.user_id)
        
        # Se não houver senhas armazenadas
        if not websites:
            messagebox.showinfo("Informação", "Nenhuma senha armazenada ainda!")
            self.manage_window.destroy()
            return

        for website_data in websites:
            website = website_data['website']
            username = website_data['username']
            password = self.manager.fernet.decrypt(website_data['password']).decode('utf-8')
            
            website_label = Label(self.manage_window, text=f"Website: {website}")
            website_label.pack(pady=5)

            username_label = Label(self.manage_window, text=f"Username: {username}")
            username_label.pack(pady=5)

            password_label = Label(self.manage_window, text=f"Password: {password}")
            password_label.pack(pady=5)

            # Adicionar botões para editar website, nome de usuário e senha
            edit_website_btn = Button(self.manage_window, text="Editar Website", command=lambda: self.edit_website(website))
            edit_website_btn.pack(pady=5)

            edit_username_btn = Button(self.manage_window, text="Editar Nome de Usuário", command=lambda: self.edit_username(website, username))
            edit_username_btn.pack(pady=5)

            #edit_password_btn = Button(self.manage_window, text="Editar Senha", command=lambda: self.edit_password(website, password))
            #edit_password_btn.pack(pady=5)

            
    def edit_website(self, old_website):
        new_website = simpledialog.askstring("Editar Website", "Digite o novo website:", initialvalue=old_website)
        if new_website and new_website != old_website:
            self.manager.update_website(self.user_id, old_website, new_website)
            self.manage_window.destroy()
            self.manage_passwords()
    def edit_username(self, website, old_username):
        # Solicita ao usuário o novo nome de usuário
        new_username = simpledialog.askstring("Editar Nome de Usuário", "Digite o novo nome de usuário:", initialvalue=old_username)
        
        # Solicita ao usuário a nova senha
        new_password = simpledialog.askstring("Editar Senha", "Digite a nova senha:", show="*")
        
        # Verifica se o nome de usuário e a senha são válidos
        if new_username and new_password and (new_username != old_username or new_password): 
            # Verifica se a nova senha é forte
            if not password_suggester.is_password_strong(new_password):
                messagebox.showwarning("Erro", "A senha não é forte o suficiente!")
                return
            
            # Atualiza o nome de usuário e a senha
            self.manager.update_username_password(self.user_id, website, new_username, new_password)
            
            # Fecha a janela atual e abre a janela de gerenciamento de senhas novamente
            self.manage_window.destroy()
            self.manage_passwords()
            self.manage_passwords()

    def update_password(self, website, old_username, old_password):
        new_username = simpledialog.askstring("Atualizar", f"Digite o novo nome de usuário para {website} (anteriormente {old_username}):")
        new_password = simpledialog.askstring("Atualizar", f"Digite a nova senha para {website}:")

        # Verifica se a senha atende aos critérios de complexidade
        if not password_suggester.is_password_strong(new_password):
            messagebox.showwarning("Erro", "A senha não atende aos critérios de complexidade. Ela deve ter pelo menos 12 caracteres, combinar letras maiúsculas, minúsculas, números e caracteres especiais.")
            return

        # Verificar se a senha já foi usada anteriormente
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), salt)
        if check_password_in_history(self.user_id, hashed_password):
            messagebox.showwarning("Erro", "Você já usou essa senha anteriormente. Por favor, escolha uma nova senha.")
            return

        encrypted_new_password = self.manager.fernet.encrypt(new_password.encode('utf-8'))
        update_password_for_website(self.user_id, website, new_username, encrypted_new_password)
        messagebox.showinfo("Atualizado", f"Senha para {website} foi atualizada!")
        
        # Após atualizar a senha, atualiza o registro de tempo
        store_password_update_timestamp(self.user_id, website)


    def change_master_password(self):
        current_password = simpledialog.askstring("Alterar Senha Mestra", "Digite sua senha atual:", show='*')
        
        # Verifica a senha mestra atual
        if not self.manager.authenticate_user(current_password):
            messagebox.showwarning("Erro", "Senha atual incorreta!")
            return
        
        new_password = simpledialog.askstring("Alterar Senha Mestra", "Digite a nova senha:", show='*')
        confirm_new_password = simpledialog.askstring("Alterar Senha Mestra", "Confirme a nova senha:", show='*')
        
        # Verifica se as novas senhas coincidem
        if new_password != confirm_new_password:
            messagebox.showwarning("Erro", "As senhas não coincidem!")
            return

        # Verifica se a nova senha é forte o suficiente
        if not password_suggester.is_password_strong(new_password):
            messagebox.showwarning("Erro", "A nova senha não é forte o suficiente!")
            return

        # Verificar se a nova senha foi usada antes
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), salt)
        if check_password_in_history(self.user_id, hashed_password):
            messagebox.showwarning("Erro", "Essa senha já foi usada anteriormente. Escolha uma nova senha.")
            return

        # Atualizar a senha no banco de dados
        update_master_password_in_db(self.user_id, hashed_password)

        # Informa ao usuário que a senha mestra foi alterada com sucesso
        messagebox.showinfo("Sucesso", "Senha mestra alterada com sucesso!")

    def open_help_window(self):
        def get_response():
            query = query_entry.get()
            response = password_suggester.get_help_response(query)
            response_label.config(text=response)  # Atualiza a etiqueta com a resposta gerada

        help_window = Toplevel(self)
        help_window.title("Ajuda Interativa")

        Label(help_window, text="Digite sua pergunta:").pack(pady=10)
        query_entry = Entry(help_window, width=50)
        query_entry.pack(pady=10)

        Button(help_window, text="Obter Resposta", command=get_response).pack(pady=10)
        
        response_label = Label(help_window, text="", wraplength=400)
        response_label.pack(pady=20)

def backup_database(manager):
        """
        Faz o backup do banco de dados, criptografando-o antes de salvar.

        :param manager: Objeto PasswordManager para criptografia.
        """
        backup_file_path = filedialog.asksaveasfilename(defaultextension=".backup", filetypes=[("Backup Files", "*.backup")])
        if not backup_file_path:
            return

        # Ler o conteúdo do banco de dados
        with open('passwords.db', 'rb') as db_file:
            db_content = db_file.read()

        # Criptografar o conteúdo
        encrypted_content = manager.fernet.encrypt(db_content)

        # Salvar o conteúdo criptografado no arquivo de backup
        with open(backup_file_path, 'wb') as backup_file:
            backup_file.write(encrypted_content)

        messagebox.showinfo("Sucesso", "Backup realizado com sucesso!")

def restore_database(manager):
    """
    Restaura o banco de dados a partir de um arquivo de backup.

    :param manager: Objeto PasswordManager para descriptografia.
    """
    backup_file_path = filedialog.askopenfilename(filetypes=[("Backup Files", "*.backup")])
    if not backup_file_path:
        return

    # Ler o conteúdo criptografado do arquivo de backup
    with open(backup_file_path, 'rb') as backup_file:
        encrypted_content = backup_file.read()

    # Descriptografar o conteúdo
    decrypted_content = manager.fernet.decrypt(encrypted_content)

    # Sobrescrever o banco de dados atual com o conteúdo descriptografado
    with open('passwords.db', 'wb') as db_file:
        db_file.write(decrypted_content)

    messagebox.showinfo("Sucesso", "Banco de dados restaurado com sucesso!")


def edit_password(user_id, website, manager):
        """
        Permite ao usuário editar a senha armazenada para um determinado website.

        :param user_id: ID do usuário.
        :param website: Website para o qual a senha será editada.
        :param manager: Objeto que contém o método de criptografia.
        """
        # 1. Solicitar ao usuário que insira a nova senha
        new_password = simpledialog.askstring("Editar Senha", "Digite a nova senha:", show='*')

        if new_password:
            # 2. Verificar se a senha é forte o suficiente
            if not password_suggester.is_password_strong(new_password):
                messagebox.showwarning("Erro", "A senha não é forte o suficiente!")
                return

            # 3. Criptografar a nova senha
            encrypted_password = manager.fernet.encrypt(new_password.encode('utf-8'))

            # 4. Atualizar a senha no banco de dados
            update_password_for_website(user_id, website, encrypted_password)

            # 5. Mostrar uma mensagem de sucesso ao usuário
            messagebox.showinfo("Sucesso", "Senha atualizada com sucesso!")
        else:
            messagebox.showwarning("Erro", "Operação cancelada pelo usuário!")

def copy_to_clipboard(text):
    pyperclip.copy(text)
    messagebox.showinfo("Copiado", "Texto copiado para a área de transferência!")


def main():
    root = ThemedTk(theme="equilux")  # Tema alterado para equilux
    root.title("Gerenciador de Senhas Asun")
    # Estilização dos widgets
    style = ttk.Style(root)
    style.configure('TLabel', font=('Arial', 12), background="#2e2e2e", foreground="#d4d4d4")
    style.configure('TButton', font=('Arial', 12), padding=5, background="#424242", foreground="#d4d4d4")
    style.configure('TEntry', font=('Arial', 12), padding=5, fieldbackground="#424242", foreground="#d4d4d4", insertcolor="#d4d4d4")

    # Correção para que o fundo dos Labels padrão seja escuro
    Label(root, text="").config(bg="#2e2e2e")
    Button(root, text="").config(bg="#424242", fg="#d4d4d4")
   


    # Estilização dos widgets
    style = ttk.Style(root)
    style.configure('TLabel', font=('Arial', 12), background="#2e2e2e", foreground="#d4d4d4")
    style.configure('TButton', font=('Arial', 12), padding=5, background="#424242", foreground="#d4d4d4")
    style.configure('TEntry', font=('Arial', 12), padding=5, fieldbackground="#424242", foreground="#d4d4d4", insertcolor="#d4d4d4")

    # Correção para que o fundo dos Labels padrão seja escuro
    Label(root, text="").config(bg="#2e2e2e")
    Button(root, text="").config(bg="#424242", fg="#d4d4d4")

    screen_manager = ScreenManager(root)
    screen_manager.switch_to(LoginScreen, screen_manager)
    root.mainloop()

if __name__ == "__main__":
    main()
