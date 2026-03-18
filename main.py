#!/usr/bin/env python3
"""
Главное CLI-приложение для управления лабораторными работами.

Лабораторные работы по курсу «Системы передачи и защиты информации»
на основе модели алфавитной криптосистемы В.О. Осипяна:
    Σ₀ = (M*, Q, C*, E(m), D(c) | V(E(m), D(c)))

Задачи 1-3: помехоустойчивое кодирование (CLI-режим)
Задачи 4-6: криптосистемы с открытым ключом (GUI-режим, PyQt6)
"""

from __future__ import annotations

import sys
import random

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, IntPrompt
from rich.text import Text
from rich import box

console = Console()


# ───────────────────────────────────────────────────────────────────────────
#  Утилиты
# ───────────────────────────────────────────────────────────────────────────

def read_bits(prompt: str) -> list[int]:
    """Считывает двоичную строку от пользователя и возвращает список бит."""
    raw = Prompt.ask(prompt).strip().replace(" ", "").replace(",", "")
    if not raw:
        raise ValueError("Пустой ввод")
    if not all(c in "01" for c in raw):
        raise ValueError("Допускаются только символы 0 и 1")
    return [int(c) for c in raw]


def bits_to_str(bits: list[int]) -> str:
    """Превращает список бит в строку."""
    return "".join(map(str, bits))


def success(msg: str) -> None:
    console.print(f"  [bold green]{msg}[/]")


def error(msg: str) -> None:
    console.print(f"  [bold red]{msg}[/]")


def info(msg: str) -> None:
    console.print(f"  [cyan]{msg}[/]")


def result_panel(title: str, content: str) -> None:
    console.print(Panel(content, title=title, border_style="green", padding=(0, 2)))


def ask_action(choices: list[tuple[str, str, str]], *, back: str = "Назад") -> str:
    """Показывает таблицу действий и запрашивает выбор. Возвращает ключ."""
    table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    table.add_column("Клавиша", style="bold yellow", width=6)
    table.add_column("Действие", style="white")

    for key, label, style in choices:
        table.add_row(f"[{key}]", f"[{style}]{label}[/]")
    table.add_row("[0]", f"[dim]{back}[/]")

    console.print(table)
    return Prompt.ask("  Действие", choices=[c[0] for c in choices] + ["0"], show_choices=False)


# ───────────────────────────────────────────────────────────────────────────
#  Задача 1: Код Хэмминга C(n, k)
# ───────────────────────────────────────────────────────────────────────────

def run_task_1() -> None:
    from task_1.hamming_code import HammingCodeSystem

    console.print(Panel(
        "[bold]Код Хэмминга C(n, k)[/]\n"
        "[dim]Исправление одной симметричной ошибки в двоичном канале[/]",
        title="Задача 1", border_style="blue", padding=(1, 2),
    ))

    actions = [
        ("1", "Кодирование E(m)", "green"),
        ("2", "Декодирование D(c)", "yellow"),
        ("3", "Внесение ошибки и исправление", "red"),
        ("4", "Верификация V(E(m), D(c))", "magenta"),
        ("5", "Демонстрация (пример C(7,4))", "cyan"),
    ]

    while True:
        console.print()
        choice = ask_action(actions)

        try:
            if choice == "1":
                k = IntPrompt.ask("  Число информационных бит k")
                hamming = HammingCodeSystem(k=k)
                info(f"Система: {hamming}")
                m = read_bits(f"  Введите {k} бит сообщения")
                c = hamming.encode(m)
                result_panel("E(m) — Кодирование",
                    f"Сообщение m  = [bold]{bits_to_str(m)}[/]\n"
                    f"Кодовое слово c = E(m) = [bold green]{bits_to_str(c)}[/]"
                )

            elif choice == "2":
                k = IntPrompt.ask("  Число информационных бит k")
                hamming = HammingCodeSystem(k=k)
                info(f"Длина кодового слова n = {hamming.n}")
                c = read_bits(f"  Введите {hamming.n} бит кодового слова")
                decoded, err_pos = hamming.decode(c)
                lines = f"Декодировано D(c) = [bold]{bits_to_str(decoded)}[/]\n"
                if err_pos == 0:
                    lines += "[green]Ошибок не обнаружено[/]"
                else:
                    lines += f"[yellow]Исправлена ошибка на позиции {err_pos}[/]"
                result_panel("D(c) — Декодирование", lines)

            elif choice == "3":
                k = IntPrompt.ask("  Число информационных бит k")
                hamming = HammingCodeSystem(k=k)
                m = read_bits(f"  Введите {k} бит сообщения")
                c = hamming.encode(m)
                info(f"Кодовое слово c = E(m) = {bits_to_str(c)}")

                pos = IntPrompt.ask(f"  Позиция ошибки (1-{hamming.n})")
                c_err = list(c)
                c_err[pos - 1] ^= 1

                decoded, err_pos = hamming.decode(c_err)
                match = decoded == m
                result_panel("Исправление ошибки",
                    f"Слово с ошибкой c' = [bold red]{bits_to_str(c_err)}[/]\n"
                    f"Декодировано D(c') = [bold]{bits_to_str(decoded)}[/]\n"
                    f"Ошибка на позиции: [yellow]{err_pos}[/]\n"
                    f"Совпадает с m: [{'green' if match else 'red'}]{match}[/]"
                )

            elif choice == "4":
                k = IntPrompt.ask("  Число информационных бит k")
                hamming = HammingCodeSystem(k=k)
                m = read_bits(f"  Введите {k} бит сообщения")
                res = hamming.verify(m)
                if res:
                    success(f"V: D(E(m)) == m ? True")
                else:
                    error(f"V: D(E(m)) == m ? False")

            elif choice == "5":
                hamming = HammingCodeSystem(k=4)
                m = [1, 0, 1, 1]
                c = hamming.encode(m)
                c_err = list(c)
                c_err[4] ^= 1
                decoded, err_pos = hamming.decode(c_err)
                result_panel("Демонстрация C(7,4)",
                    f"Система: [bold]{hamming}[/]\n"
                    f"Сообщение m = [bold]{bits_to_str(m)}[/]\n"
                    f"Кодовое слово c = E(m) = [bold green]{bits_to_str(c)}[/]\n"
                    f"Слово с ошибкой c' = [bold red]{bits_to_str(c_err)}[/]  (позиция 5)\n"
                    f"Декодировано D(c') = [bold]{bits_to_str(decoded)}[/], позиция ошибки: [yellow]{err_pos}[/]\n"
                    f"Верификация V: [bold green]{hamming.verify(m)}[/]"
                )

            elif choice == "0":
                return
        except (ValueError, IndexError) as e:
            error(f"Ошибка: {e}")
        except KeyboardInterrupt:
            console.print()
            return


# ───────────────────────────────────────────────────────────────────────────
#  Задача 2: Расширенный код Хэмминга C[n+1, k]
# ───────────────────────────────────────────────────────────────────────────

def run_task_2() -> None:
    from task_2.hamming_extended import ExtendedHammingCodeSystem

    console.print(Panel(
        "[bold]Расширенный код Хэмминга C[n+1, k][/]\n"
        "[dim]Исправление 1 ошибки, обнаружение 2 ошибок[/]",
        title="Задача 2", border_style="blue", padding=(1, 2),
    ))

    actions = [
        ("1", "Кодирование E(m)", "green"),
        ("2", "Декодирование D(c)", "yellow"),
        ("3", "Одиночная ошибка (исправление)", "red"),
        ("4", "Двойная ошибка (обнаружение)", "bold red"),
        ("5", "Верификация V(E(m), D(c))", "magenta"),
        ("6", "Демонстрация (пример C[8,4])", "cyan"),
    ]

    while True:
        console.print()
        choice = ask_action(actions)

        try:
            if choice == "1":
                k = IntPrompt.ask("  Число информационных бит k")
                hamming = ExtendedHammingCodeSystem(k=k)
                info(f"Система: {hamming}")
                m = read_bits(f"  Введите {k} бит сообщения")
                c = hamming.encode(m)
                result_panel("E(m) — Кодирование",
                    f"Расширенное кодовое слово c = E(m) = [bold green]{bits_to_str(c)}[/]\n"
                    f"[p_overall | c_1...c_n] = [[bold yellow]{c[0]}[/] | {bits_to_str(c[1:])}]"
                )

            elif choice == "2":
                k = IntPrompt.ask("  Число информационных бит k")
                hamming = ExtendedHammingCodeSystem(k=k)
                info(f"Длина расширенного слова n_ext = {hamming.n_ext}")
                c = read_bits(f"  Введите {hamming.n_ext} бит")
                decoded, err_pos, status = hamming.decode(c)
                status_color = {"no_error": "green", "corrected": "yellow", "double_error": "red"}
                result_panel("D(c) — Декодирование",
                    f"Декодировано D(c) = [bold]{bits_to_str(decoded)}[/]\n"
                    f"Статус: [{status_color.get(status, 'white')}]{status}[/], позиция ошибки: {err_pos}"
                )

            elif choice == "3":
                k = IntPrompt.ask("  Число информационных бит k")
                hamming = ExtendedHammingCodeSystem(k=k)
                m = read_bits(f"  Введите {k} бит сообщения")
                c = hamming.encode(m)
                info(f"c = E(m) = {bits_to_str(c)}")
                pos = IntPrompt.ask(f"  Позиция ошибки (0-{hamming.n_ext - 1})")
                c_err = list(c)
                c_err[pos] ^= 1
                decoded, err_pos, status = hamming.decode(c_err)
                match = decoded == m
                result_panel("Одиночная ошибка",
                    f"Слово с ошибкой c' = [bold red]{bits_to_str(c_err)}[/]\n"
                    f"D(c') = [bold]{bits_to_str(decoded)}[/]\n"
                    f"Статус: [yellow]{status}[/], позиция: {err_pos}\n"
                    f"Совпадает с m: [{'green' if match else 'red'}]{match}[/]"
                )

            elif choice == "4":
                k = IntPrompt.ask("  Число информационных бит k")
                hamming = ExtendedHammingCodeSystem(k=k)
                m = read_bits(f"  Введите {k} бит сообщения")
                c = hamming.encode(m)
                info(f"c = E(m) = {bits_to_str(c)}")
                pos1 = IntPrompt.ask(f"  Позиция 1-й ошибки (0-{hamming.n_ext - 1})")
                pos2 = IntPrompt.ask(f"  Позиция 2-й ошибки (0-{hamming.n_ext - 1})")
                c_err = list(c)
                c_err[pos1] ^= 1
                c_err[pos2] ^= 1
                decoded, err_pos, status = hamming.decode(c_err)
                color = "red" if status == "double_error" else "yellow"
                msg = "ДВОЙНАЯ ОШИБКА ОБНАРУЖЕНА (не исправляема)" if status == "double_error" else status
                result_panel("Двойная ошибка",
                    f"Слово с ошибкой c' = [bold red]{bits_to_str(c_err)}[/]\n"
                    f"Статус: [bold {color}]{msg}[/]"
                )

            elif choice == "5":
                k = IntPrompt.ask("  Число информационных бит k")
                hamming = ExtendedHammingCodeSystem(k=k)
                m = read_bits(f"  Введите {k} бит сообщения")
                res = hamming.verify(m)
                if res:
                    success(f"V: D(E(m)) == m ? True")
                else:
                    error(f"V: D(E(m)) == m ? False")

            elif choice == "6":
                hamming = ExtendedHammingCodeSystem(k=4)
                m = [1, 0, 1, 1]
                c = hamming.encode(m)
                c_err1 = list(c)
                c_err1[5] ^= 1
                decoded1, pos1, st1 = hamming.decode(c_err1)
                c_err2 = list(c)
                c_err2[2] ^= 1
                c_err2[5] ^= 1
                _, _, st2 = hamming.decode(c_err2)
                result_panel("Демонстрация C[8,4]",
                    f"Система: [bold]{hamming}[/]\n"
                    f"m = [bold]{bits_to_str(m)}[/], c = E(m) = [bold green]{bits_to_str(c)}[/]\n\n"
                    f"[underline]Одиночная ошибка (позиция 5):[/]\n"
                    f"  c' = [bold red]{bits_to_str(c_err1)}[/]\n"
                    f"  D(c') = [bold]{bits_to_str(decoded1)}[/], статус: [yellow]{st1}[/]\n\n"
                    f"[underline]Двойная ошибка (позиции 2, 5):[/]\n"
                    f"  c' = [bold red]{bits_to_str(c_err2)}[/]\n"
                    f"  Статус: [bold red]{st2}[/]\n\n"
                    f"Верификация V: [bold green]{hamming.verify(m)}[/]"
                )

            elif choice == "0":
                return
        except (ValueError, IndexError) as e:
            error(f"Ошибка: {e}")
        except KeyboardInterrupt:
            console.print()
            return


# ───────────────────────────────────────────────────────────────────────────
#  Задача 3: Код Варшамова-Тененгольца VT_a(n)
# ───────────────────────────────────────────────────────────────────────────

def run_task_3() -> None:
    from task_3.varshamov_code import VarshamovCodeSystem, _varshamov_syndrome

    console.print(Panel(
        "[bold]Код Варшамова-Тененгольца VT_a(n)[/]\n"
        "[dim]Исправление одной асимметричной ошибки (Z-канал)[/]",
        title="Задача 3", border_style="blue", padding=(1, 2),
    ))

    actions = [
        ("1", "Создать код и показать параметры", "blue"),
        ("2", "Кодирование E(m)", "green"),
        ("3", "Декодирование D(c)", "yellow"),
        ("4", "Имитация ошибки и исправление", "red"),
        ("5", "Верификация V(E(m), D(c))", "magenta"),
        ("6", "Демонстрация (пример VT_0(7))", "cyan"),
    ]

    while True:
        console.print()
        choice = ask_action(actions)

        try:
            if choice == "1":
                n = IntPrompt.ask("  Длина кодового слова n")
                a = IntPrompt.ask(f"  Параметр кода a (0-{n})")
                vt = VarshamovCodeSystem(n=n, a=a)
                code_info = vt.code_info()
                result_panel(f"VT_{a}({n}) — Параметры",
                    f"Система: [bold]{vt}[/]\n"
                    f"Всего кодовых слов |C*| = [cyan]{code_info['total_codewords']}[/]\n"
                    f"Используемых (2^k)      = [cyan]{code_info['usable_codewords']}[/]\n"
                    f"k = [bold]{code_info['k']}[/], R = [bold]{code_info['code_rate']}[/]"
                )

            elif choice == "2":
                n = IntPrompt.ask("  Длина кодового слова n")
                a = IntPrompt.ask(f"  Параметр кода a (0-{n})")
                vt = VarshamovCodeSystem(n=n, a=a)
                info(f"k = {vt.k}")
                m = read_bits(f"  Введите {vt.k} бит сообщения")
                c = vt.encode(m)
                result_panel("E(m) — Кодирование",
                    f"Сообщение m = [bold]{bits_to_str(m)}[/]\n"
                    f"Кодовое слово c = E(m) = [bold green]{bits_to_str(c)}[/]\n"
                    f"Синдром S(c) = [cyan]{_varshamov_syndrome(c, n)}[/] (ожидается {a})"
                )

            elif choice == "3":
                n = IntPrompt.ask("  Длина кодового слова n")
                a = IntPrompt.ask(f"  Параметр кода a (0-{n})")
                vt = VarshamovCodeSystem(n=n, a=a)
                c = read_bits(f"  Введите {n} бит кодового слова")
                ch_type = Prompt.ask("  Тип канала", choices=["1->0", "0->1"])
                decoded, err_pos, err_type = vt.decode(c, ch_type)
                result_panel("D(c) — Декодирование",
                    f"Декодировано D(c) = [bold]{bits_to_str(decoded)}[/]\n"
                    f"Ошибка: [yellow]{err_type}[/], позиция: {err_pos}"
                )

            elif choice == "4":
                n = IntPrompt.ask("  Длина кодового слова n")
                a = IntPrompt.ask(f"  Параметр кода a (0-{n})")
                vt = VarshamovCodeSystem(n=n, a=a)
                info(f"k = {vt.k}")
                m = read_bits(f"  Введите {vt.k} бит сообщения")
                c = vt.encode(m)
                info(f"c = E(m) = {bits_to_str(c)}")
                err_type = Prompt.ask("  Тип ошибки", choices=["1->0", "0->1"])
                c_err, pos = vt.introduce_error(c, err_type)
                if pos is None:
                    error("Невозможно внести ошибку данного типа (нет подходящих бит)")
                else:
                    decoded, det_pos, det_type = vt.decode(c_err, err_type)
                    match = decoded == m
                    result_panel("Имитация ошибки",
                        f"Слово с ошибкой c' = [bold red]{bits_to_str(c_err)}[/]  (позиция {pos})\n"
                        f"Обнаружена ошибка: тип [yellow]{det_type}[/], позиция [yellow]{det_pos}[/]\n"
                        f"D(c') = [bold]{bits_to_str(decoded)}[/]\n"
                        f"Совпадает с m: [{'green' if match else 'red'}]{match}[/]"
                    )

            elif choice == "5":
                n = IntPrompt.ask("  Длина кодового слова n")
                a = IntPrompt.ask(f"  Параметр кода a (0-{n})")
                vt = VarshamovCodeSystem(n=n, a=a)
                info(f"k = {vt.k}")
                m = read_bits(f"  Введите {vt.k} бит сообщения")
                res = vt.verify(m)
                if res:
                    success(f"V: D(E(m)) == m ? True")
                else:
                    error(f"V: D(E(m)) == m ? False")

            elif choice == "6":
                n, a = 7, 0
                vt = VarshamovCodeSystem(n=n, a=a)
                code_info = vt.code_info()
                m = [1, 0, 1, 1]
                c = vt.encode(m)
                random.seed(42)
                c_err, pos = vt.introduce_error(c, "1->0")
                decoded, _, _ = vt.decode(c_err, "1->0")
                match = decoded == m
                result_panel("Демонстрация VT_0(7)",
                    f"Система: [bold]{vt}[/]\n"
                    f"|C*| = {code_info['total_codewords']}, k = {code_info['k']}\n\n"
                    f"m = [bold]{bits_to_str(m)}[/]\n"
                    f"c = E(m) = [bold green]{bits_to_str(c)}[/]\n"
                    f"S(c) = [cyan]{_varshamov_syndrome(c, n)}[/]\n\n"
                    f"[underline]Z-канал (1->0):[/]\n"
                    f"  c' = [bold red]{bits_to_str(c_err)}[/]  (ошибка на позиции {pos})\n"
                    f"  D(c') = [bold]{bits_to_str(decoded)}[/]\n"
                    f"  Совпадает с m: [{'green' if match else 'red'}]{match}[/]\n\n"
                    f"Верификация V: [bold green]{vt.verify(m)}[/]"
                )

            elif choice == "0":
                return
        except (ValueError, IndexError) as e:
            error(f"Ошибка: {e}")
        except KeyboardInterrupt:
            console.print()
            return


# ───────────────────────────────────────────────────────────────────────────
#  Задачи 4-6: запуск GUI (PyQt6)
# ───────────────────────────────────────────────────────────────────────────

def _launch_gui(window_class, title: str) -> None:
    """Запускает PyQt6-окно заданного класса."""
    try:
        from PyQt6.QtWidgets import QApplication
    except ImportError:
        error("PyQt6 не установлен. Установите: pip install PyQt6")
        return

    console.print(f"  Запуск GUI: [bold cyan]{title}[/]...")
    app = QApplication(sys.argv)
    window = window_class()
    window.show()
    app.exec()
    console.print(f"  [dim]GUI закрыт.[/]")


def run_task_4() -> None:
    """Задача 4: RSA — криптосистема с открытым ключом."""
    from task_4.rsa_crypto import RSAMainWindow
    _launch_gui(RSAMainWindow, "RSA — криптосистема (факторизация — NP)")


def run_task_5() -> None:
    """Задача 5: Аддитивный рюкзак (АВКР, Меркл-Хеллман)."""
    from task_5.knapsack_crypto import KnapsackMainWindow
    _launch_gui(KnapsackMainWindow, "АВКР — аддитивный рюкзак (Subset Sum — NP)")


def run_task_6() -> None:
    """Задача 6: Мультипликативный рюкзак (МВКР)."""
    from task_6.multiplicative_knapsack_crypto import MKnapsackMainWindow
    _launch_gui(MKnapsackMainWindow, "МВКР — мультипликативный рюкзак (Subset Product — NP)")


# ───────────────────────────────────────────────────────────────────────────
#  Главное меню
# ───────────────────────────────────────────────────────────────────────────

TASKS = {
    "1": ("Код Хэмминга C(n, k)", "Исправление 1 симметричной ошибки", "CLI", run_task_1),
    "2": ("Расширенный код Хэмминга C[n+1, k]", "Исправление 1 + обнаружение 2 ошибок", "CLI", run_task_2),
    "3": ("Код Варшамова-Тененгольца VT_a(n)", "Исправление 1 асимметричной ошибки", "CLI", run_task_3),
    "4": ("RSA", "Факторизация — NP", "GUI", run_task_4),
    "5": ("Аддитивный рюкзак (АВКР)", "Subset Sum — NP", "GUI", run_task_5),
    "6": ("Мультипликативный рюкзак (МВКР)", "Subset Product — NP", "GUI", run_task_6),
}


def show_main_menu() -> None:
    console.clear()

    title = Text()
    title.append("Лабораторные работы — криптосистемы Осипяна\n", style="bold white")
    title.append("Σ₀ = (M*, Q, C*, E(m), D(c) | V(E(m), D(c)))", style="dim italic")

    console.print(Panel(title, border_style="bright_blue", padding=(1, 4), box=box.DOUBLE))

    # Таблица задач
    table = Table(box=box.ROUNDED, border_style="bright_blue", title_style="bold", padding=(0, 1))
    table.add_column("#", style="bold yellow", width=3, justify="center")
    table.add_column("Задача", style="bold white", min_width=38)
    table.add_column("Описание", style="dim")
    table.add_column("Режим", justify="center", width=5)

    table.add_row("", "[underline bright_blue]Помехоустойчивое кодирование[/]", "", "")
    table.add_row("1", "Код Хэмминга C(n, k)", "1 симметричная ошибка", "[green]CLI[/]")
    table.add_row("2", "Расширенный код Хэмминга C[n+1, k]", "1 исправление + 2 обнаружение", "[green]CLI[/]")
    table.add_row("3", "Код Варшамова-Тененгольца VT_a(n)", "1 асимметричная ошибка", "[green]CLI[/]")
    table.add_row("", "[underline bright_blue]Криптосистемы с открытым ключом[/]", "", "")
    table.add_row("4", "RSA", "Факторизация — NP", "[magenta]GUI[/]")
    table.add_row("5", "Аддитивный рюкзак (АВКР)", "Subset Sum — NP", "[magenta]GUI[/]")
    table.add_row("6", "Мультипликативный рюкзак (МВКР)", "Subset Product — NP", "[magenta]GUI[/]")

    console.print(table)
    console.print()


def main() -> None:
    while True:
        try:
            show_main_menu()
            choice = Prompt.ask(
                "  Выберите задачу [dim](0 — выход)[/]",
                choices=["0", "1", "2", "3", "4", "5", "6"],
                show_choices=False,
            )

            if choice == "0":
                console.print("\n  [bold bright_blue]До свидания![/]\n")
                break

            _, _, _, func = TASKS[choice]
            try:
                func()
            except KeyboardInterrupt:
                console.print("\n  [dim]Прервано пользователем[/]")

        except KeyboardInterrupt:
            console.print("\n\n  [bold bright_blue]До свидания![/]\n")
            break


if __name__ == "__main__":
    main()
