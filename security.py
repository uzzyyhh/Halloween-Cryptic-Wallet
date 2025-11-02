# security.py
import re
import os
from cryptography.fernet import Fernet

KEY_FILE = 'data/fernet.key'

def get_or_create_key():
    # prefer environment
    env_key = os.environ.get('FERNET_KEY')
    if env_key:
        return env_key.encode()
    os.makedirs('data', exist_ok=True)
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, 'rb') as f:
            return f.read()
    else:
        key = Fernet.generate_key()
        with open(KEY_FILE, 'wb') as f:
            f.write(key)
        return key

# instantiate a Fernet instance for encrypt/decrypt
_KEY = get_or_create_key()
_F = Fernet(_KEY)

def encrypt_data(b: bytes) -> bytes:
    """
    Returns encrypted bytes.
    Store as .hex() if you want a string field.
    """
    return _F.encrypt(b)

def decrypt_data(b: bytes) -> bytes:
    return _F.decrypt(b)

def sanitize_input(s: str) -> str:
    if s is None:
        return ''
    # remove leading/trailing whitespace, limit length, basic removal of suspicious characters
    out = s.strip()
    # remove NULL bytes
    out = out.replace('\x00', '')
    # limit to 512 chars for most inputs
    if len(out) > 512:
        out = out[:512]
    # a minimal safe allow-list: keep common printable characters
    # but do not overly mangle emails/filenames; preserve @ . _ - and spaces
    out = re.sub(r'[^\w\s@\.\-:,\(\)\/]', '', out)
    return out

def is_strong_password(pwd: str) -> bool:
    """
    Require:
      - at least 8 chars
      - at least one uppercase
      - at least one lowercase
      - at least one digit
      - at least one special symbol
    """
    if not pwd or len(pwd) < 8:
        return False
    if not re.search(r'[A-Z]', pwd):
        return False
    if not re.search(r'[a-z]', pwd):
        return False
    if not re.search(r'\d', pwd):
        return False
    if not re.search(r'[^A-Za-z0-9]', pwd):
        return False
    return True
