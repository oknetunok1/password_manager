"""Тесты для модуля работы с хранилищем."""

from pathlib import Path

import pytest

from password_manager.storage import (
    VaultAlreadyExistsError,
    VaultCorruptedError,
    VaultEntry,
    VaultNotFoundError,
    VaultStorage,
)


def test_initialize_creates_valid_vault(tmp_path: Path) -> None:
    """Проверка создания нового хранилища с солью и хэшем."""
    vault_file = tmp_path / "vault.json"
    storage = VaultStorage(vault_file)

    storage.initialize(salt_hex="aabbcc", master_hash="112233")

    assert vault_file.exists()
    data = storage.load()
    assert data.salt == "aabbcc"
    assert data.master_hash == "112233"
    assert data.entries == []


def test_initialize_already_exists_raises_error(tmp_path: Path) -> None:
    """Повторная инициализация существующего файла должна вызывать ошибку."""
    vault_file = tmp_path / "vault.json"
    storage = VaultStorage(vault_file)

    storage.initialize(salt_hex="aabbcc", master_hash="112233")

    with pytest.raises(VaultAlreadyExistsError):
        storage.initialize(salt_hex="other_salt", master_hash="other_hash")


def test_load_non_existent_file_raises_error(tmp_path: Path) -> None:
    """Чтение несуществующего файла вызывает VaultNotFoundError."""
    vault_file = tmp_path / "missing.json"
    storage = VaultStorage(vault_file)

    with pytest.raises(VaultNotFoundError):
        storage.load()


def test_load_corrupted_json_raises_error(tmp_path: Path) -> None:
    """Чтение битого JSON-файла вызывает VaultCorruptedError."""
    vault_file = tmp_path / "corrupted.json"
    vault_file.write_text("{ this is not a valid json", encoding="utf-8")

    storage = VaultStorage(vault_file)

    with pytest.raises(VaultCorruptedError):
        storage.load()


def test_add_and_get_entry(tmp_path: Path) -> None:
    """Добавление и последующий поиск записи по сервису."""
    vault_file = tmp_path / "vault.json"
    storage = VaultStorage(vault_file)
    storage.initialize(salt_hex="salt", master_hash="hash")

    entry = VaultEntry(
        service="github.com",
        login="octocat",
        password="encrypted_token_1",
        created_at="2026-11-01T12:00:00Z",
    )
    storage.add_entry(entry)

    found = storage.get_entry(service="github.com")
    assert found is not None
    assert found.login == "octocat"
    assert found.password == "encrypted_token_1"


def test_add_entry_updates_existing(tmp_path: Path) -> None:
    """Добавление записи с тем же сервисом и логином должно перезаписать её."""
    vault_file = tmp_path / "vault.json"
    storage = VaultStorage(vault_file)
    storage.initialize(salt_hex="salt", master_hash="hash")

    entry_v1 = VaultEntry(
        service="github.com",
        login="octocat",
        password="old_password",
        created_at="2026-11-01T10:00:00Z",
    )
    entry_v2 = VaultEntry(
        service="github.com",
        login="octocat",
        password="new_password",
        created_at="2026-11-01T11:00:00Z",
    )

    storage.add_entry(entry_v1)
    storage.add_entry(entry_v2)

    entries = storage.list_entries()
    assert len(entries) == 1
    assert entries[0].password == "new_password"


def test_delete_entry(tmp_path: Path) -> None:
    """Удаление существующей записи возвращает True, отсутствующей — False."""
    vault_file = tmp_path / "vault.json"
    storage = VaultStorage(vault_file)
    storage.initialize(salt_hex="salt", master_hash="hash")

    entry = VaultEntry(
        service="gitlab.com",
        login="developer",
        password="token",
        created_at="2026-11-01T12:00:00Z",
    )
    storage.add_entry(entry)

    assert storage.delete_entry(service="gitlab.com") is True
    assert storage.get_entry(service="gitlab.com") is None
    assert storage.delete_entry(service="gitlab.com") is False