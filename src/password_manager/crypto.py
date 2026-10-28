"""Криптографические утилиты и генерация паролей."""

import secrets
import string


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