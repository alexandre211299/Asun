import sqlite3
import bcrypt
from datetime import datetime  
import shutil
from keras.models import load_model
import numpy as np
import io
from keras.models import Sequential
from keras.layers import Dense, LSTM, Embedding
from keras.preprocessing.sequence import pad_sequences
import tensorflow
from transformers import GPT2LMHeadModel, GPT2Tokenizer

DATABASE_NAME = 'passwords.db'

# Inicialização do modelo GPT-2 e tokenizer
GPT2_MODEL_NAME = "gpt2-medium"
gpt2_model = GPT2LMHeadModel.from_pretrained(GPT2_MODEL_NAME)
gpt2_tokenizer = GPT2Tokenizer.from_pretrained(GPT2_MODEL_NAME)

def generate_password_from_hint(hint, max_length=15):
    """Gera uma senha usando o modelo GPT-2 com base em uma dica fornecida."""
    input_ids = gpt2_tokenizer.encode(hint, return_tensors="pt")
    output = gpt2_model.generate(input_ids, max_length=max_length, num_return_sequences=1, pad_token_id=gpt2_tokenizer.eos_token_id)
    generated_password = gpt2_tokenizer.decode(output[0], skip_special_tokens=True)
    
    # Removendo a dica do início da senha gerada
    password = generated_password.replace(hint, "").strip()
    return password
def backup_database(backup_path):
    shutil.copyfile(DATABASE_NAME, backup_path)

def restore_database(backup_path):
    shutil.copyfile(backup_path, DATABASE_NAME)

def get_unique_chars(data):
    """Retorna caracteres únicos em uma lista de strings."""
    return sorted(list(set(''.join(data))))

def encode_data(data, char_to_int, seq_length):
    """Codifica listas de senhas em sequências numéricas."""
    sequences = []
    for line in data:
        encoded_seq = [char_to_int[char] for char in line]
        sequences.append(encoded_seq)
    return pad_sequences(sequences, maxlen=seq_length, truncating='pre')

def decode_sequence(sequence, int_to_char):
    """Decodifica uma sequência numérica de volta em uma string."""
    return ''.join([int_to_char[int_val] for int_val in sequence])

def build_model(vocab_size, seq_length):
    model = Sequential()
    model.add(Embedding(vocab_size, 50, input_length=seq_length))
    model.add(LSTM(100, return_sequences=True))
    model.add(LSTM(100))
    model.add(Dense(100, activation='relu'))
    model.add(Dense(vocab_size, activation='softmax'))
    model.compile(loss='categorical_crossentropy', optimizer='adam', metrics=['accuracy'])
    return model

# Funções para salvar e carregar modelos LSTM do banco de dados
def save_lstm_model(user_id, model):
    """Salva o modelo LSTM no banco de dados."""
    # Serializar o modelo para um formato binário
    with io.BytesIO() as model_data:
        model.save(model_data)
        model_data.seek(0)
        with sqlite3.connect(DATABASE_NAME) as conn:
            cursor = conn.cursor()
            # Verificar se o modelo para esse user_id já existe
            cursor.execute('SELECT id FROM lstm_models WHERE user_id = ?', (user_id,))
            result = cursor.fetchone()
            if result:
                cursor.execute('UPDATE lstm_models SET model_data = ? WHERE user_id = ?', (model_data.read(), user_id))
            else:
                cursor.execute('INSERT INTO lstm_models (user_id, model_data) VALUES (?, ?)', (user_id, model_data.read()))
            conn.commit()

def load_lstm_model(user_id):
    """Carrega o modelo LSTM do banco de dados."""
    with sqlite3.connect(DATABASE_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT model_data FROM lstm_models WHERE user_id = ?', (user_id,))
        result = cursor.fetchone()
        if result and result[0]:
            model_data = io.BytesIO(result[0])
            return load_model(model_data)
    return None

# [Restante do código original...]
def initialize_db():
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()

    # Tabela de salt para senha mestra
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS master_salt (
        id INTEGER PRIMARY KEY,
        salt BLOB NOT NULL
    );
    ''')
   # Tabela de histórico de senhas
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS password_history (
        id INTEGER PRIMARY KEY,
        user_id INTEGER NOT NULL,
        website TEXT,
        hashed_password BLOB,
        password BLOB,
        timestamp TEXT NOT NULL,
        last_update TEXT,
        FOREIGN KEY (user_id) REFERENCES users(id)
    );
''')

    # Tabela de usuários
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        hashed_password BLOB NOT NULL,
        salt BLOB NOT NULL,
        failed_attempts INTEGER DEFAULT 0,
        last_failed TEXT DEFAULT NULL,
        fa_secret TEXT DEFAULT NULL,
        last_password_update TEXT DEFAULT NULL
    );
    ''')

    
   
     # Tabela de senhas
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS passwords (
        id INTEGER PRIMARY KEY,
        user_id INTEGER NOT NULL,
        website TEXT NOT NULL,
        username TEXT NOT NULL,
        password BLOB NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id)
    );
    ''')

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS activity_logs (
        id INTEGER PRIMARY KEY,
        user_id INTEGER,
        activity TEXT,
        timestamp DATETIME,
        FOREIGN KEY (user_id) REFERENCES users(id)
    );
    ''')

    conn.commit()
    conn.close()      



def modify_activity_logs_table():
    conn = sqlite3.connect(DATABASE_NAME)
    cursor = conn.cursor()

    # Adicionar colunas à tabela activity_logs
    cursor.execute('''
        ALTER TABLE activity_logs ADD COLUMN login_location TEXT DEFAULT NULL;
    ''')
    
    cursor.execute('''
        ALTER TABLE activity_logs ADD COLUMN login_status TEXT DEFAULT NULL;  -- "SUCCESS" ou "FAILED"
    ''')

    conn.commit()
    conn.close()

def log_login_activity(user_id, activity, location, status):
    current_time = datetime.now()
    with sqlite3.connect(DATABASE_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO activity_logs (user_id, activity, timestamp, login_location, login_status) 
            VALUES (?, ?, ?, ?, ?)
        """, (user_id, activity, current_time, location, status))
        conn.commit()

def detect_suspicious_activity(user_id, location):
    # Para simplificar, consideramos uma atividade suspeita se o local de login for diferente do local usual.
    # Esta é uma lógica básica; você pode expandir com outras verificações.
    
    with sqlite3.connect(DATABASE_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT login_location 
            FROM activity_logs 
            WHERE user_id = ? 
            ORDER BY timestamp DESC 
            LIMIT 10
        """, (user_id,))
        
        recent_locations = [row[0] for row in cursor.fetchall()]
        # Se o novo local não estiver nas 10 localizações recentes, consideramos suspeito.
        if location not in recent_locations:
            return True
        return False

def recommend_password_change(user_id):
    # Sugere a troca de senha se a senha não foi alterada nos últimos 90 dias.
    last_password_update = get_last_password_update(user_id)
    if not last_password_update:
        return True
    today = datetime.now()
    days_since_last_update = (today - last_password_update).days
    return days_since_last_update > 90



def store_master_salt(salt):
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    cursor.execute('INSERT INTO master_salt (salt) VALUES (?);', (salt,))
    conn.commit()
    conn.close()

def get_master_salt():
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    cursor.execute('SELECT salt FROM master_salt LIMIT 1;')
    result = cursor.fetchone()
    conn.close()
    return result[0] if result else None

def store_password_db(user_id, website, username, encrypted_password):
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    cursor.execute('''
    INSERT INTO passwords (user_id, website, username, password)
    VALUES (?, ?, ?, ?);
    ''', (user_id, website, username, encrypted_password))
    conn.commit()
    conn.close()

def retrieve_password_db(user_id, website):
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    cursor.execute('SELECT username, password FROM passwords WHERE user_id = ? AND website = ?', (user_id, website))
    result = cursor.fetchone()
    conn.close()
    if result:
        return {'username': result[0], 'password': result[1]}
    else:
        return None

def get_all_websites(user_id):
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    cursor.execute('SELECT DISTINCT website FROM passwords WHERE user_id = ?', (user_id,))
    websites = [row[0] for row in cursor.fetchall()]
    conn.close()
    return websites

def register_user(username, password):
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    try:
        cursor.execute('''
        INSERT INTO users (username, hashed_password, salt)
        VALUES (?, ?, ?);
        ''', (username, hashed_password, salt))
        conn.commit()
    except sqlite3.IntegrityError:  # username já existe
        conn.close()
        return False
    conn.close()
    return True

def verify_user(username, password):
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    cursor.execute('SELECT id, hashed_password, salt FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()
    conn.close()
    if user:
        user_id, hashed_password, salt = user
        if bcrypt.checkpw(password.encode('utf-8'), hashed_password):
            return user_id
    return None

def get_user_data(username):
    """Busca os dados do usuário."""
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    cursor.execute('SELECT id, failed_attempts, last_failed FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()
    conn.close()
    if user:
        user_id, failed_attempts, last_failed = user
        return {
            'user_id': user_id,
            'failed_attempts': failed_attempts,
            'last_failed': last_failed
        }
    return None

def reset_failed_attempts(username):
    """Redefine o número de tentativas malsucedidas."""
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    cursor.execute('UPDATE users SET failed_attempts = 0 WHERE username = ?', (username,))
    conn.commit()
    conn.close()

def increment_failed_attempts(username):
    """Incrementa o número de tentativas malsucedidas."""
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')  # Formatando a data e hora atual como string
    cursor.execute('UPDATE users SET failed_attempts = failed_attempts + 1, last_failed = ? WHERE username = ?', (current_time, username))
    conn.commit()
    conn.close()

def update_master_password_in_db(user_id, new_password):
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), salt)
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    cursor.execute('''
    UPDATE users 
    SET hashed_password = ?, salt = ?
    WHERE id = ?;
    ''', (hashed_password, salt, user_id))
    conn.commit()
    conn.close()

def get_all_passwords_for_user(user_id):
    """Busca todas as senhas para um usuário específico."""
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    cursor.execute('SELECT id, website, username, password FROM passwords WHERE user_id = ?', (user_id,))
    passwords = cursor.fetchall()
    conn.close()
    return passwords

def update_password_for_website(user_id, website, new_username, new_password):
    """Atualiza a senha para um site específico."""
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE passwords 
        SET username = ?, password = ?
        WHERE user_id = ? AND website = ?;
    ''', (new_username, new_password, user_id, website))
    conn.commit()
    conn.close()

def delete_password_for_website(user_id, website):
    """Exclui a senha para um site específico."""
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    cursor.execute('DELETE FROM passwords WHERE user_id = ? AND website = ?', (user_id, website))
    conn.commit()
    conn.close()

def update_website_name(user_id, old_website, new_website):
    """Atualiza o nome do site."""
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE passwords 
        SET website = ?
        WHERE user_id = ? AND website = ?;
    ''', (new_website, user_id, old_website))
    conn.commit()
    conn.close()

def retrieve_all_passwords_for_user(user_id):
    """Busca todas as senhas para um usuário específico."""
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    cursor.execute('SELECT website, username, password FROM passwords WHERE user_id = ?', (user_id,))
    passwords = [{'website': row[0], 'username': row[1], 'password': row[2]} for row in cursor.fetchall()]
    conn.close()
    return passwords

def store_fa_secret(username, secret):
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    cursor.execute('UPDATE users SET fa_secret = ? WHERE username = ?', (secret, username))
    conn.commit()
    conn.close()

def get_fa_secret(username):
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    cursor.execute('SELECT fa_secret FROM users WHERE username = ?', (username,))
    result = cursor.fetchone()
    conn.close()
    return result[0] if result else None

def has_fa(username):
    secret = get_fa_secret(username)
    return bool(secret)

def store_password_in_history(user_id, hashed_password):
    """Armazena a senha mestra no histórico de senhas."""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO password_history (user_id, hashed_password, timestamp)
        VALUES (?, ?, ?);
    ''', (user_id, hashed_password, timestamp))
    conn.commit()
    conn.close()

def check_password_in_history(user_id, hashed_password):
    """Verifica se a senha mestra existe no histórico de senhas."""
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    cursor.execute('SELECT id FROM password_history WHERE user_id = ? AND hashed_password = ?', (user_id, hashed_password))
    result = cursor.fetchone()
    conn.close()
    return bool(result)


def update_last_password_change(user_id):
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    cursor.execute('''
    UPDATE users SET last_password_update = ? WHERE id = ?;
    ''', (current_time, user_id))
    conn.commit()
    conn.close()


def store_password_update_timestamp(user_id, website):
    """Armazena o momento da atualização da senha."""
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    cursor.execute('''
    INSERT INTO password_history (user_id, website, timestamp) 
    VALUES (?, ?, ?);
    ''', (user_id, website, current_time))
    conn.commit()
    conn.close()
def get_last_password_update(user_id):
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    cursor.execute('SELECT MAX(last_update) FROM password_history WHERE user_id = ?', (user_id,))
    result = cursor.fetchone()
    conn.close()
    if result and result[0]:
        return datetime.strptime(result[0], '%Y-%m-%d %H:%M:%S')
    return None

def check_password_history(user_id, website, hashed_password):
    """Verifica se a senha já foi usada anteriormente."""
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    cursor.execute('SELECT id FROM password_history WHERE user_id = ? AND website = ? AND hashed_password = ?', (user_id, website, hashed_password))
    result = cursor.fetchone()
    conn.close()
    return True if result else False

def log_activity(user_id, activity):
    current_time = datetime.datetime.now()
    with sqlite3.connect('passwords.db') as conn:
        cursor = conn.cursor()
        cursor.execute("INSERT INTO activity_logs (user_id, activity, timestamp) VALUES (?, ?, ?)", (user_id, activity, current_time))
        conn.commit()

initialize_db()
