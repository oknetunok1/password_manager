"""Криптографические утилиты и генерация паролей."""

import base64
import hashlib
import secrets
import string

from cryptography.fernet import Fernet, InvalidToken


def generate_password(length: int = 16) -> str:
    """Сгенерировать криптографически стойкий случайный пароль.

    Пароль формируется из строчных и заглавных букв, цифр
    и специальных символов.

    Args:
        length: Длина генерируемого пароля (по умолчанию 16).

    Returns:
        Сгенерированная строка пароля.

    Raises:
        ValueError: Если запрошенная длина меньше 8 символов.
    """
    if length < 8:
        raise ValueError("Длина пароля должна быть не менее 8 символов")

    symbols = "!@#$%^&*()-_=+"
    alphabet = string.ascii_letters + string.digits + symbols

    return "".join(secrets.choice(alphabet) for _ in range(length))

def generate_salt(length: int = 16) -> bytes:
    """Сгенерировать случайную криптографическую соль.

    Args:
        length: Размер соли в байтах (по умолчанию 16).

    Returns:
        Случайная байтовая строка.
    """
    return secrets.token_bytes(length)


def hash_master_password(
    password: str, salt: bytes, iterations: int = 600_000
) -> str:
    """Вычислить проверочный хэш мастер-пароля с использованием PBKDF2-HMAC-SHA256.

    Args:
        password: Исходный текстовый пароль.
        salt: Случайная криптографическая соль в байтах.
        iterations: Количество раундов хэширования (по умолчанию 600 000).

    Returns:
        Шестнадцатеричная строка вычисленного хэша.
    """
    password_bytes = password.encode("utf-8")
    derived_hash = hashlib.pbkdf2_hmac(
        hash_name="sha256",
        password=password_bytes,
        salt=salt,
        iterations=iterations,
    )
    return derived_hash.hex()


def derive_fernet_key(
    password: str, salt: bytes, iterations: int = 600_000
) -> bytes:
    """Вывести 32-байтный ключ шифрования для Fernet из мастер-пароля.

    Args:
        password: Текстовый мастер-пароль.
        salt: Криптографическая соль в байтах.
        iterations: Количество итераций PBKDF2 (по умолчанию 600 000).

    Returns:
        32-байтный ключ, закодированный в URL-safe base64 (тип bytes).
    """
    raw_key = hashlib.pbkdf2_hmac(
        hash_name="sha256",
        password=password.encode("utf-8"),
        salt=salt,
        iterations=iterations,
        dklen=32,
    )
    return base64.urlsafe_b64encode(raw_key)


def encrypt_data(data: str, key: bytes) -> str:
    """Зашифровать строковые данные ключом Fernet.

    Args:
        data: Исходный открытый текст.
        key: Ключ Fernet в байтах.

    Returns:
        Зашифрованный токен в виде UTF-8 строки.
    """
    fernet = Fernet(key)
    encrypted_bytes = fernet.encrypt(data.encode("utf-8"))
    return encrypted_bytes.decode("utf-8")


class DecryptionError(Exception):
    """Исключение при ошибке дешифрования (неверный ключ или повреждённые данные)."""


def decrypt_data(token: str, key: bytes) -> str:
    """Расшифровать токен Fernet обратно в открытый текст.

    Args:
        token: Зашифрованная строка.
        key: Ключ Fernet в байтах.

    Returns:
        Исходный расшифрованный текст.

    Raises:
        DecryptionError: Если ключ не подходит или данные повреждены.
    """
    fernet = Fernet(key)
    try:
        decrypted_bytes = fernet.decrypt(token.encode("utf-8"))
    except InvalidToken as err:
        raise DecryptionError("Неверный ключ или повреждённый токен") from err

    return decrypted_bytes.decode("utf-8")