"""Тесты для криптографического модуля."""

import pytest

from password_manager.crypto import (
    DecryptionError,
    decrypt_data,
    derive_fernet_key,
    encrypt_data,
    generate_password,
    generate_salt,
    hash_master_password,
)


def test_generate_password_default_length() -> None:
    """Генератор по умолчанию создает пароль длиной 16 символов."""
    password = generate_password()
    assert len(password) == 16
    assert isinstance(password, str)


def test_generate_password_custom_length() -> None:
    """Генератор создает пароль запрошенной длины."""
    password = generate_password(length=24)
    assert len(password) == 24


def test_generate_password_too_short_raises_error() -> None:
    """Запрос длины менее 8 символов вызывает ValueError."""
    with pytest.raises(ValueError):
        generate_password(length=7)


def test_generate_salt() -> None:
    """Генерация соли возвращает байты нужной длины и уникальна при каждом вызове."""
    salt1 = generate_salt(16)
    salt2 = generate_salt(16)

    assert isinstance(salt1, bytes)
    assert len(salt1) == 16
    assert salt1 != salt2


def test_hash_master_password_deterministic() -> None:
    """Одинаковый пароль и соль дают одинаковый хэш."""
    salt = generate_salt()
    hash1 = hash_master_password("my_secret_pass", salt, iterations=10_000)
    hash2 = hash_master_password("my_secret_pass", salt, iterations=10_000)
    hash_diff = hash_master_password("other_pass", salt, iterations=10_000)

    assert hash1 == hash2
    assert hash1 != hash_diff


def test_encrypt_decrypt_roundtrip() -> None:
    """Зашифрованные данные успешно расшифровываются тем же ключом."""
    salt = generate_salt()
    key = derive_fernet_key("master_password", salt, iterations=10_000)
    original_text = "SuperSecretServicePassword123"

    encrypted_token = encrypt_data(original_text, key)
    assert encrypted_token != original_text

    decrypted_text = decrypt_data(encrypted_token, key)
    assert decrypted_text == original_text


def test_decrypt_with_wrong_key_raises_decryption_error() -> None:
    """Попытка расшифровать данные неверным ключом вызывает DecryptionError."""
    salt1 = generate_salt()
    salt2 = generate_salt()
    key_correct = derive_fernet_key("pass1", salt1, iterations=10_000)
    key_wrong = derive_fernet_key("pass2", salt2, iterations=10_000)

    encrypted_token = encrypt_data("secret", key_correct)

    with pytest.raises(DecryptionError):
        decrypt_data(encrypted_token, key_wrong)