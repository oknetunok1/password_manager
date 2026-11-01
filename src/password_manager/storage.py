"""Модуль работы со структурами данных и файловым хранилищем."""

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class StorageError(Exception):
    """Базовое исключение для ошибок хранилища."""


class VaultNotFoundError(StorageError):
    """Файл хранилища не найден на диске."""


class VaultAlreadyExistsError(StorageError):
    """Файл хранилища уже существует (защита от случайной перезаписи)."""


class VaultCorruptedError(StorageError):
    """Файл хранилища повреждён или содержит невалидную структуру."""


@dataclass
class VaultEntry:
    """Модель отдельной записи сервиса в хранилище."""

    service: str
    login: str
    password: str
    created_at: str

    def to_dict(self) -> dict[str, str]:
        """Преобразовать запись в словарь для сериализации в JSON."""
        return {
            "service": self.service,
            "login": self.login,
            "password": self.password,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "VaultEntry":
        """Собрать объект записи из словаря JSON."""
        return cls(
            service=str(data["service"]),
            login=str(data["login"]),
            password=str(data["password"]),
            created_at=str(data["created_at"]),
        )


@dataclass
class VaultData:
    """Модель содержимого всего хранилища."""

    salt: str
    master_hash: str
    entries: list[VaultEntry]

    def to_dict(self) -> dict[str, Any]:
        """Преобразовать базу данных в словарь для сохранения в JSON."""
        return {
            "salt": self.salt,
            "master_hash": self.master_hash,
            "entries": [entry.to_dict() for entry in self.entries],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "VaultData":
        """Собрать объект базы данных из словаря JSON."""
        raw_entries = data.get("entries", [])
        if not isinstance(raw_entries, list):
            raise VaultCorruptedError("Поле 'entries' должно быть списком")

        entries = [
            VaultEntry.from_dict(item)
            for item in raw_entries
            if isinstance(item, dict)
        ]
        return cls(
            salt=str(data["salt"]),
            master_hash=str(data["master_hash"]),
            entries=entries,
        )


def atomic_write_json(file_path: Path, data: dict[str, Any]) -> None:
    """Атомарно записать словарь в JSON-файл через временный файл."""
    temp_path = file_path.with_suffix(".tmp")

    with open(temp_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.flush()
        os.fsync(f.fileno())

    os.replace(temp_path, file_path)


class VaultStorage:
    """Управление файлом хранилища паролей на диске."""

    def __init__(self, file_path: Path) -> None:
        self.file_path = file_path

    def initialize(self, salt_hex: str, master_hash: str) -> None:
        """Создать новый файл хранилища с солью и хэшем мастер-пароля."""
        if self.file_path.exists():
            raise VaultAlreadyExistsError(
                f"Хранилище уже существует: {self.file_path}"
            )

        data = VaultData(
            salt=salt_hex,
            master_hash=master_hash,
            entries=[],
        )
        atomic_write_json(self.file_path, data.to_dict())

    def load(self) -> VaultData:
        """Загрузить и проверить данные хранилища из файла на диске."""
        if not self.file_path.exists():
            raise VaultNotFoundError(
                f"Файл хранилища не найден: {self.file_path}"
            )

        try:
            with open(self.file_path, encoding="utf-8") as f:
                raw_data = json.load(f)
        except json.JSONDecodeError as err:
            raise VaultCorruptedError(
                "Файл хранилища повреждён (невалидный JSON)"
            ) from err

        if not isinstance(raw_data, dict):
            raise VaultCorruptedError(
                "Корневая структура файла должна быть JSON-объектом"
            )

        try:
            return VaultData.from_dict(raw_data)
        except (KeyError, TypeError) as err:
            raise VaultCorruptedError(
                f"Отсутствует обязательное поле или неверный тип данных: {err}"
            ) from err

    def add_entry(self, entry: VaultEntry) -> None:
        """Добавить новую запись в хранилище или обновить существующую."""
        vault_data = self.load()

        for index, existing_entry in enumerate(vault_data.entries):
            if (
                existing_entry.service == entry.service
                and existing_entry.login == entry.login
            ):
                vault_data.entries[index] = entry
                break
        else:
            vault_data.entries.append(entry)

        atomic_write_json(self.file_path, vault_data.to_dict())

    def get_entry(
        self, service: str, login: str | None = None
    ) -> VaultEntry | None:
        """Найти запись по названию сервиса и опциональному логину."""
        vault_data = self.load()

        for entry in vault_data.entries:
            if entry.service == service:
                if login is None or entry.login == login:
                    return entry

        return None

    def delete_entry(self, service: str, login: str | None = None) -> bool:
        """Удалить запись по названию сервиса и опциональному логину."""
        vault_data = self.load()

        for index, entry in enumerate(vault_data.entries):
            if entry.service == service:
                if login is None or entry.login == login:
                    del vault_data.entries[index]
                    atomic_write_json(self.file_path, vault_data.to_dict())
                    return True

        return False

    def list_entries(self) -> list[VaultEntry]:
        """Получить список всех записей в хранилище."""
        vault_data = self.load()
        return list(vault_data.entries)