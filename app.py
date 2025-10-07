"""Графическое приложение для безопасного хранения личных данных."""

from __future__ import annotations

import tkinter as tk
from dataclasses import dataclass
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Callable, Optional

from vault_manager import (
    VaultAuthenticationError,
    VaultInitializationError,
    VaultManager,
)


STORAGE_DIR = Path.home() / ".preland_vault"
STORAGE_DIR.mkdir(parents=True, exist_ok=True)


@dataclass
class EntryData:
    title: str
    username: str
    secret: str
    notes: str

    @classmethod
    def from_dict(cls, data: dict[str, str]) -> "EntryData":
        return cls(
            title=data.get("title", ""),
            username=data.get("username", ""),
            secret=data.get("secret", ""),
            notes=data.get("notes", ""),
        )

    def to_dict(self) -> dict[str, str]:
        return {
            "title": self.title,
            "username": self.username,
            "secret": self.secret,
            "notes": self.notes,
        }


class VaultApp(tk.Tk):
    """Главное окно приложения."""

    def __init__(self) -> None:
        super().__init__()
        self.title("Preland Secure Vault")
        self.geometry("800x500")
        self.resizable(False, False)
        self.vault = VaultManager(STORAGE_DIR)

        self._active_frame: Optional[tk.Frame] = None
        if self.vault.is_initialized():
            self._show_login_frame()
        else:
            self._show_setup_frame()

    # ---------- frame helpers ----------
    def _set_frame(self, frame: tk.Frame) -> None:
        if self._active_frame is not None:
            self._active_frame.destroy()
        self._active_frame = frame
        self._active_frame.pack(fill=tk.BOTH, expand=True)

    def _show_setup_frame(self) -> None:
        frame = SetupFrame(self, on_success=self._show_login_frame)
        self._set_frame(frame)

    def _show_login_frame(self) -> None:
        frame = LoginFrame(
            self,
            on_authenticated=self._show_vault_frame,
            on_reset=self._show_setup_frame,
        )
        self._set_frame(frame)

    def _show_vault_frame(self) -> None:
        frame = VaultFrame(self, self.vault, on_logout=self._show_login_frame)
        self._set_frame(frame)


class SetupFrame(ttk.Frame):
    """Форма первичной настройки и создания пароля."""

    def __init__(self, master: VaultApp, on_success: Callable[[], None]):
        super().__init__(master, padding=40)
        self.master = master
        self.on_success = on_success

        ttk.Label(self, text="Добро пожаловать в Preland Secure Vault", font=("Segoe UI", 16, "bold")).pack(
            pady=(0, 30)
        )
        ttk.Label(self, text="Создайте главный пароль", font=("Segoe UI", 12)).pack(pady=(0, 20))

        self.password_var = tk.StringVar()
        self.confirm_var = tk.StringVar()

        ttk.Label(self, text="Пароль:").pack(anchor="w")
        ttk.Entry(self, textvariable=self.password_var, show="*").pack(fill=tk.X, pady=(0, 10))

        ttk.Label(self, text="Повторите пароль:").pack(anchor="w")
        ttk.Entry(self, textvariable=self.confirm_var, show="*").pack(fill=tk.X, pady=(0, 20))

        ttk.Button(self, text="Создать", command=self._handle_create).pack()

    def _handle_create(self) -> None:
        password = self.password_var.get().strip()
        confirm = self.confirm_var.get().strip()

        if not password:
            messagebox.showerror("Ошибка", "Пароль не может быть пустым")
            return
        if password != confirm:
            messagebox.showerror("Ошибка", "Пароли не совпадают")
            return
        try:
            self.master.vault.initialize(password)
        except VaultInitializationError as exc:
            messagebox.showerror("Ошибка", str(exc))
            return
        messagebox.showinfo("Готово", "Главный пароль создан. Теперь войдите в хранилище.")
        self.on_success()


class LoginFrame(ttk.Frame):
    """Форма входа в хранилище."""

    def __init__(self, master: VaultApp, on_authenticated: Callable[[], None], on_reset: Callable[[], None]):
        super().__init__(master, padding=40)
        self.master = master
        self.on_authenticated = on_authenticated
        self.on_reset = on_reset

        ttk.Label(self, text="Введите пароль", font=("Segoe UI", 16, "bold")).pack(pady=(0, 20))
        self.password_var = tk.StringVar()
        entry = ttk.Entry(self, textvariable=self.password_var, show="*")
        entry.pack(fill=tk.X, pady=(0, 20))
        entry.focus_set()

        ttk.Button(self, text="Войти", command=self._handle_login).pack()
        ttk.Button(self, text="Сбросить и создать заново", command=self._handle_reset).pack(pady=(10, 0))

    def _handle_login(self) -> None:
        password = self.password_var.get()
        try:
            self.master.vault.authenticate(password)
        except VaultAuthenticationError as exc:
            messagebox.showerror("Ошибка", str(exc))
            return
        except VaultInitializationError as exc:
            messagebox.showerror("Ошибка", str(exc))
            return
        self.on_authenticated()

    def _handle_reset(self) -> None:
        if messagebox.askyesno("Подтверждение", "Это удалит текущее хранилище. Продолжить?"):
            try:
                if self.master.vault.config_path.exists():
                    self.master.vault.config_path.unlink()
                if self.master.vault.data_path.exists():
                    self.master.vault.data_path.unlink()
            except OSError as exc:
                messagebox.showerror("Ошибка", f"Не удалось удалить файлы: {exc}")
                return
            self.on_reset()


class VaultFrame(ttk.Frame):
    """Главный экран после авторизации."""

    def __init__(self, master: VaultApp, vault: VaultManager, on_logout: Callable[[], None]):
        super().__init__(master, padding=20)
        self.master = master
        self.vault = vault
        self.on_logout = on_logout

        self.columnconfigure(0, weight=1)
        self.columnconfigure(1, weight=2)

        header = ttk.Frame(self)
        header.grid(row=0, column=0, columnspan=2, sticky="ew")
        ttk.Label(header, text="Ваши записи", font=("Segoe UI", 16, "bold")).pack(side=tk.LEFT)
        ttk.Button(header, text="Выйти", command=self._logout).pack(side=tk.RIGHT)

        # List of entries
        list_frame = ttk.Frame(self)
        list_frame.grid(row=1, column=0, sticky="nsew", padx=(0, 10), pady=(20, 0))
        list_frame.rowconfigure(0, weight=1)
        list_frame.columnconfigure(0, weight=1)

        self.listbox = tk.Listbox(list_frame, height=20, exportselection=False)
        self.listbox.grid(row=0, column=0, sticky="nsew")
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.listbox.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.listbox.config(yscrollcommand=scrollbar.set)
        self.listbox.bind("<<ListboxSelect>>", lambda event: self._show_details())

        btn_frame = ttk.Frame(list_frame)
        btn_frame.grid(row=1, column=0, columnspan=2, pady=(10, 0))
        ttk.Button(btn_frame, text="Добавить", command=self._add_entry).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Изменить", command=self._edit_entry).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Удалить", command=self._delete_entry).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Экспорт", command=self._export_entries).pack(side=tk.LEFT, padx=5)

        # Detail panel
        detail_frame = ttk.LabelFrame(self, text="Детали")
        detail_frame.grid(row=1, column=1, sticky="nsew", pady=(20, 0))
        detail_frame.rowconfigure(3, weight=1)
        detail_frame.columnconfigure(1, weight=1)

        ttk.Label(detail_frame, text="Название:").grid(row=0, column=0, sticky="w", padx=10, pady=(10, 5))
        self.detail_title = ttk.Label(detail_frame, text="")
        self.detail_title.grid(row=0, column=1, sticky="w", padx=10, pady=(10, 5))

        ttk.Label(detail_frame, text="Логин/Имя:").grid(row=1, column=0, sticky="w", padx=10, pady=5)
        self.detail_username = ttk.Label(detail_frame, text="")
        self.detail_username.grid(row=1, column=1, sticky="w", padx=10, pady=5)

        ttk.Label(detail_frame, text="Пароль/Секрет:").grid(row=2, column=0, sticky="w", padx=10, pady=5)
        self.detail_secret = ttk.Label(detail_frame, text="")
        self.detail_secret.grid(row=2, column=1, sticky="w", padx=10, pady=5)

        ttk.Label(detail_frame, text="Заметки:").grid(row=3, column=0, sticky="nw", padx=10, pady=5)
        self.detail_notes = tk.Text(detail_frame, width=40, height=15, state="disabled", wrap="word")
        self.detail_notes.grid(row=3, column=1, sticky="nsew", padx=10, pady=(5, 10))

        self._refresh_entries()

    # ---------- helpers ----------
    def _refresh_entries(self) -> None:
        self.listbox.delete(0, tk.END)
        for entry in self.vault.data:
            self.listbox.insert(tk.END, entry.get("title") or "(без названия)")
        if self.vault.data:
            self.listbox.selection_set(0)
            self._show_details()
        else:
            self._clear_details()

    def _get_selected_index(self) -> Optional[int]:
        selected = self.listbox.curselection()
        return selected[0] if selected else None

    def _show_details(self) -> None:
        index = self._get_selected_index()
        if index is None:
            self._clear_details()
            return
        entry = EntryData.from_dict(self.vault.data[index])
        self.detail_title.config(text=entry.title)
        self.detail_username.config(text=entry.username)
        self.detail_secret.config(text=entry.secret)
        self.detail_notes.configure(state="normal")
        self.detail_notes.delete("1.0", tk.END)
        self.detail_notes.insert("1.0", entry.notes)
        self.detail_notes.configure(state="disabled")

    def _clear_details(self) -> None:
        self.detail_title.config(text="")
        self.detail_username.config(text="")
        self.detail_secret.config(text="")
        self.detail_notes.configure(state="normal")
        self.detail_notes.delete("1.0", tk.END)
        self.detail_notes.configure(state="disabled")

    def _add_entry(self) -> None:
        editor = EntryEditor(self.master, title="Новая запись")
        self.master.wait_window(editor)
        if editor.result is not None:
            self.vault.add_entry(editor.result.to_dict())
            self._refresh_entries()

    def _edit_entry(self) -> None:
        index = self._get_selected_index()
        if index is None:
            messagebox.showwarning("Нет выбора", "Выберите запись для изменения")
            return
        entry = EntryData.from_dict(self.vault.data[index])
        editor = EntryEditor(self.master, title="Редактировать запись", initial=entry)
        self.master.wait_window(editor)
        if editor.result is not None:
            self.vault.update_entry(index, editor.result.to_dict())
            self._refresh_entries()
            self.listbox.selection_set(index)
            self._show_details()

    def _delete_entry(self) -> None:
        index = self._get_selected_index()
        if index is None:
            messagebox.showwarning("Нет выбора", "Выберите запись для удаления")
            return
        if not messagebox.askyesno("Подтверждение", "Удалить выбранную запись?"):
            return
        self.vault.delete_entry(index)
        self._refresh_entries()

    def _export_entries(self) -> None:
        path = filedialog.asksaveasfilename(
            title="Экспортировать записи",
            defaultextension=".json",
            filetypes=[("JSON файлы", "*.json"), ("Все файлы", "*.*")],
        )
        if not path:
            return
        try:
            self.vault.export_to(Path(path))
        except OSError as exc:
            messagebox.showerror("Ошибка", f"Не удалось сохранить файл: {exc}")
            return
        messagebox.showinfo("Готово", "Записи успешно экспортированы")

    def _logout(self) -> None:
        self.master.vault._key = None  # type: ignore[attr-defined]
        self.master.vault._data = []  # type: ignore[attr-defined]
        self.on_logout()


class EntryEditor(tk.Toplevel):
    """Окно создания или редактирования записи."""

    def __init__(self, master: tk.Tk, title: str, initial: EntryData | None = None):
        super().__init__(master)
        self.title(title)
        self.resizable(False, False)
        self.result: EntryData | None = None

        ttk.Label(self, text="Название:").grid(row=0, column=0, sticky="w", padx=10, pady=(10, 5))
        self.title_var = tk.StringVar(value=initial.title if initial else "")
        ttk.Entry(self, textvariable=self.title_var).grid(row=0, column=1, padx=10, pady=(10, 5))

        ttk.Label(self, text="Логин/Имя:").grid(row=1, column=0, sticky="w", padx=10, pady=5)
        self.username_var = tk.StringVar(value=initial.username if initial else "")
        ttk.Entry(self, textvariable=self.username_var).grid(row=1, column=1, padx=10, pady=5)

        ttk.Label(self, text="Пароль/Секрет:").grid(row=2, column=0, sticky="w", padx=10, pady=5)
        self.secret_var = tk.StringVar(value=initial.secret if initial else "")
        ttk.Entry(self, textvariable=self.secret_var).grid(row=2, column=1, padx=10, pady=5)

        ttk.Label(self, text="Заметки:").grid(row=3, column=0, sticky="nw", padx=10, pady=5)
        self.notes_text = tk.Text(self, width=40, height=10, wrap="word")
        self.notes_text.grid(row=3, column=1, padx=10, pady=5)
        if initial:
            self.notes_text.insert("1.0", initial.notes)

        btn_frame = ttk.Frame(self)
        btn_frame.grid(row=4, column=0, columnspan=2, pady=(10, 10))
        ttk.Button(btn_frame, text="Сохранить", command=self._save).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Отмена", command=self.destroy).pack(side=tk.LEFT, padx=5)

        self.grab_set()
        self.transient(master)
        self.protocol("WM_DELETE_WINDOW", self.destroy)

    def _save(self) -> None:
        entry = EntryData(
            title=self.title_var.get().strip(),
            username=self.username_var.get().strip(),
            secret=self.secret_var.get().strip(),
            notes=self.notes_text.get("1.0", tk.END).strip(),
        )
        if not entry.title:
            messagebox.showerror("Ошибка", "Название не может быть пустым")
            return
        self.result = entry
        self.destroy()


def main() -> None:
    app = VaultApp()
    app.mainloop()


if __name__ == "__main__":
    main()
