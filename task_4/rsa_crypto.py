"""
Алгоритм RSA — асимметричная криптосистема с открытым ключом.

Оформлено в соответствии с моделью алфавитной криптосистемы
В.О. Осипяна: Σ₀ = (M*, Q, C*, E(m), D(c) | V(E(m), D(c))).

NP-сложная задача в основе RSA — задача факторизации целых чисел:
разложение большого числа n = p·q на простые множители.

Литература: Осипян В.О. Разработка методов построения систем передачи
            и защиты информации. Монография. КубГУ, 2004.
"""

from __future__ import annotations

import math
import random
import sys
from dataclasses import dataclass, field

from PyQt6.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QTextEdit,
    QGroupBox,
    QSpinBox,
    QMessageBox,
    QTabWidget,
    QGridLayout,
    QComboBox,
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont


# ---------------------------------------------------------------------------
#  Вспомогательные функции теории чисел
# ---------------------------------------------------------------------------

def is_prime(n: int) -> bool:
    """Проверяет, является ли число простым (детерминистический тест).

    Для чисел до ~10^18 достаточно перебора делителей до √n.
    Для учебных целей (ключи до нескольких сотен бит) этого достаточно.
    """
    if n < 2:
        return False
    if n < 4:
        return True
    if n % 2 == 0 or n % 3 == 0:
        return False
    # Проверяем делители вида 6k±1 до √n
    i = 5
    while i * i <= n:
        if n % i == 0 or n % (i + 2) == 0:
            return False
        i += 6
    return True


def generate_prime(bits: int) -> int:
    """Генерирует случайное простое число заданной битовой длины.

    Используется вероятностный подход: генерируем нечётные числа
    нужной длины и проверяем на простоту.
    """
    if bits < 2:
        raise ValueError("Битовая длина должна быть >= 2")
    while True:
        # Старший бит = 1 (гарантируем нужную длину), младший = 1 (нечётное)
        n = random.getrandbits(bits)
        n |= (1 << (bits - 1)) | 1
        if is_prime(n):
            return n


def gcd(a: int, b: int) -> int:
    """Наибольший общий делитель (алгоритм Евклида)."""
    while b:
        a, b = b, a % b
    return a


def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    """Расширенный алгоритм Евклида.

    Возвращает (g, x, y) такие, что a·x + b·y = g = gcd(a, b).

    Это ключевой алгоритм для нахождения секретной экспоненты d,
    поскольку d = e⁻¹ mod φ(n), т.е. нужно решить e·d ≡ 1 (mod φ(n)).
    """
    if a == 0:
        return b, 0, 1
    g, x, y = extended_gcd(b % a, a)
    return g, y - (b // a) * x, x


def mod_inverse(e: int, phi: int) -> int:
    """Вычисляет мультипликативный обратный элемент: d = e⁻¹ mod φ.

    Использует расширенный алгоритм Евклида.
    Если обратный не существует (gcd(e, φ) ≠ 1), выбрасывает исключение.
    """
    g, x, _ = extended_gcd(e % phi, phi)
    if g != 1:
        raise ValueError(
            f"Обратный элемент не существует: gcd({e}, {phi}) = {g} ≠ 1"
        )
    return x % phi


def mod_pow(base: int, exp: int, mod: int) -> int:
    """Быстрое модульное возведение в степень (метод двоичного разложения).

    Вычисляет base^exp mod mod за O(log exp) умножений.
    Это основная операция шифрования и дешифрования RSA:
      c = m^e mod n  (шифрование)
      m = c^d mod n  (дешифрование)
    """
    # Используем встроенную функцию Python pow(base, exp, mod),
    # которая реализует тот же алгоритм, но оптимизирована на уровне C
    return pow(base, exp, mod)


# ---------------------------------------------------------------------------
#  Класс-криптосистема RSA
# ---------------------------------------------------------------------------

@dataclass
class RSACryptoSystem:
    """Реализация криптосистемы Σ₀ = (M*, Q, C*, E(m), D(c) | V(E(m), D(c)))
    на основе алгоритма RSA.

    Алгоритм RSA основан на NP-сложной задаче факторизации:
    зная n = p·q, вычислительно невозможно найти p и q за полиномиальное
    время при достаточно больших простых числах.

    Атрибуты
    ---------
    p : int
        Первое простое число.
    q : int
        Второе простое число (p ≠ q).
    e : int
        Открытая экспонента (часть открытого ключа).
    n : int
        Модуль RSA: n = p·q (часть открытого ключа).
    d : int
        Секретная экспонента (закрытый ключ).
    phi : int
        Функция Эйлера: φ(n) = (p−1)(q−1).

    В терминологии Осипяна
    ----------------------
    M*   — множество всех открытых текстов (целых чисел от 0 до n−1).
    Q    — алфавит {0, 1, ..., n−1} (числовые эквиваленты сообщений).
    C*   — множество шифротекстов (целых чисел от 0 до n−1).
    E(m) — алгоритм шифрования: c = m^e mod n.
    D(c) — алгоритм дешифрования: m = c^d mod n.
    V(E(m), D(c)) — верификация: D(E(m)) = m для любого m ∈ M*.
    """

    p: int
    q: int
    e: int = 0
    n: int = field(init=False, default=0)
    d: int = field(init=False, default=0)
    phi: int = field(init=False, default=0)

    def __post_init__(self) -> None:
        """Генерация ключей RSA из заданных простых чисел p и q."""
        # Валидация входных данных
        if not is_prime(self.p):
            raise ValueError(f"p = {self.p} не является простым числом")
        if not is_prime(self.q):
            raise ValueError(f"q = {self.q} не является простым числом")
        if self.p == self.q:
            raise ValueError("p и q должны быть различными простыми числами")

        # Шаг 1: вычисляем модуль n = p·q
        self.n = self.p * self.q

        # Шаг 2: вычисляем функцию Эйлера φ(n) = (p−1)(q−1)
        # Это количество чисел от 1 до n, взаимно простых с n.
        # Знание φ(n) эквивалентно знанию факторизации n.
        self.phi = (self.p - 1) * (self.q - 1)

        # Шаг 3: выбираем открытую экспоненту e
        if self.e == 0:
            # Стандартное значение e = 65537 (простое число Ферма F4 = 2^16 + 1)
            # Если оно не подходит, ищем другое
            self.e = self._choose_e()
        else:
            if gcd(self.e, self.phi) != 1:
                raise ValueError(
                    f"e = {self.e} не взаимно просто с φ(n) = {self.phi}"
                )

        # Шаг 4: вычисляем секретную экспоненту d = e⁻¹ mod φ(n)
        # Это возможно, т.к. gcd(e, φ(n)) = 1 (по выбору e)
        self.d = mod_inverse(self.e, self.phi)

    def _choose_e(self) -> int:
        """Выбирает открытую экспоненту e: 1 < e < φ(n), gcd(e, φ(n)) = 1.

        Сначала пробуем стандартное значение 65537, затем 3, 5, 17, 257.
        Если ни одно не подходит — перебираем нечётные числа.
        """
        # Стандартные кандидаты (простые числа Ферма)
        candidates = [65537, 3, 5, 17, 257]
        for candidate in candidates:
            if 1 < candidate < self.phi and gcd(candidate, self.phi) == 1:
                return candidate

        # Если стандартные не подошли, ищем перебором
        for candidate in range(3, self.phi, 2):
            if gcd(candidate, self.phi) == 1:
                return candidate

        raise ValueError("Не удалось подобрать e")

    # ---- E(m): шифрование ----------------------------------------------------

    def encrypt(self, m: int) -> int:
        """Шифрует число m: c = m^e mod n.

        Это функция E(m) криптосистемы — прямое преобразование.

        Параметры
        ---------
        m : int
            Открытый текст — целое число, 0 ≤ m < n.

        Возвращает
        ----------
        int
            Шифротекст c = m^e mod n.
        """
        self._validate_message(m)
        # Основная формула RSA-шифрования: c = m^e mod n
        return mod_pow(m, self.e, self.n)

    # ---- D(c): дешифрование --------------------------------------------------

    def decrypt(self, c: int) -> int:
        """Дешифрует число c: m = c^d mod n.

        Это функция D(c) криптосистемы — обратное преобразование.

        Корректность гарантируется теоремой Эйлера:
        m^(e·d) ≡ m^(1 + k·φ(n)) ≡ m · (m^φ(n))^k ≡ m · 1^k ≡ m (mod n)

        Параметры
        ---------
        c : int
            Шифротекст — целое число, 0 ≤ c < n.

        Возвращает
        ----------
        int
            Расшифрованный открытый текст m = c^d mod n.
        """
        self._validate_ciphertext(c)
        # Основная формула RSA-дешифрования: m = c^d mod n
        return mod_pow(c, self.d, self.n)

    # ---- Шифрование/дешифрование текстовых сообщений -------------------------

    def encrypt_text(self, text: str) -> list[int]:
        """Шифрует текстовую строку посимвольно.

        Каждый символ преобразуется в его Unicode-код (числовой эквивалент
        элементарного сообщения m_i), затем шифруется: c_i = m_i^e mod n.

        Параметры
        ---------
        text : str
            Текст для шифрования. Каждый символ должен иметь
            Unicode-код < n.

        Возвращает
        ----------
        list[int]
            Список шифротекстов (по одному на символ).
        """
        if not text:
            raise ValueError("Текст не может быть пустым")
        result = []
        for char in text:
            code = ord(char)
            if code >= self.n:
                raise ValueError(
                    f"Символ '{char}' (код {code}) не помещается "
                    f"в диапазон [0, {self.n - 1}]"
                )
            result.append(self.encrypt(code))
        return result

    def decrypt_text(self, ciphertext: list[int]) -> str:
        """Дешифрует список шифротекстов обратно в строку.

        Каждый шифротекст c_i расшифровывается: m_i = c_i^d mod n,
        затем m_i интерпретируется как Unicode-код символа.

        Параметры
        ---------
        ciphertext : list[int]
            Список зашифрованных кодов символов.

        Возвращает
        ----------
        str
            Расшифрованная строка.
        """
        if not ciphertext:
            raise ValueError("Шифротекст не может быть пустым")
        chars = []
        for c in ciphertext:
            m = self.decrypt(c)
            chars.append(chr(m))
        return "".join(chars)

    # ---- V(E(m), D(c)): верификация ------------------------------------------

    def verify(self, m: int) -> bool:
        """Проверяет свойство криптосистемы: D(E(m)) == m.

        Это функция V(E(m), D(c)) — верификация корректности.
        Основана на теореме Эйлера: m^(e·d) ≡ m (mod n).
        """
        self._validate_message(m)
        c = self.encrypt(m)
        return self.decrypt(c) == m

    # ---- Информация о ключах -------------------------------------------------

    def public_key(self) -> tuple[int, int]:
        """Возвращает открытый ключ (e, n)."""
        return (self.e, self.n)

    def private_key(self) -> tuple[int, int]:
        """Возвращает закрытый ключ (d, n)."""
        return (self.d, self.n)

    def key_info(self) -> dict[str, int]:
        """Возвращает полную информацию о ключах."""
        return {
            "p": self.p,
            "q": self.q,
            "n": self.n,
            "phi": self.phi,
            "e": self.e,
            "d": self.d,
            "key_bits": self.n.bit_length(),
        }

    # ---- Вспомогательные методы ----------------------------------------------

    def _validate_message(self, m: int) -> None:
        if not isinstance(m, int) or m < 0:
            raise ValueError(f"Сообщение должно быть неотрицательным целым, получено {m}")
        if m >= self.n:
            raise ValueError(
                f"Сообщение m = {m} должно быть < n = {self.n}"
            )

    def _validate_ciphertext(self, c: int) -> None:
        if not isinstance(c, int) or c < 0:
            raise ValueError(f"Шифротекст должен быть неотрицательным целым, получено {c}")
        if c >= self.n:
            raise ValueError(
                f"Шифротекст c = {c} должен быть < n = {self.n}"
            )

    def __repr__(self) -> str:
        return (
            f"RSACryptoSystem(n={self.n} [{self.n.bit_length()} бит], "
            f"e={self.e}, d={self.d})"
        )


# ---------------------------------------------------------------------------
#  Попытка факторизации (демонстрация NP-сложности)
# ---------------------------------------------------------------------------

def trial_factorize(n: int, limit: int = 10**6) -> tuple[int, int] | None:
    """Пробная факторизация числа n перебором делителей до limit.

    Демонстрирует вычислительную сложность задачи факторизации:
    для больших n (сотни бит) перебор невозможен за разумное время.

    Возвращает (p, q) или None, если факторизация не найдена.
    """
    if n < 4:
        return None
    if n % 2 == 0:
        return (2, n // 2)
    for i in range(3, min(limit, int(n**0.5) + 1), 2):
        if n % i == 0:
            return (i, n // i)
    return None


# ---------------------------------------------------------------------------
#  GUI на PyQt6
# ---------------------------------------------------------------------------

class RSAMainWindow(QMainWindow):
    """Главное окно приложения RSA-криптосистемы."""

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(
            "RSA — криптосистема Σ₀ = (M*, Q, C*, E(m), D(c) | V(E(m), D(c)))"
        )
        self.setMinimumSize(900, 700)

        self.rsa: RSACryptoSystem | None = None

        # Моноширинный шрифт для вывода
        self.mono_font = QFont("Monospace", 10)
        self.mono_font.setStyleHint(QFont.StyleHint.Monospace)

        self._build_ui()

    def _build_ui(self) -> None:
        """Строит интерфейс приложения."""
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)

        tabs = QTabWidget()
        layout.addWidget(tabs)

        # Вкладка 1: Генерация ключей
        tabs.addTab(self._build_keygen_tab(), "Генерация ключей")

        # Вкладка 2: Шифрование/Дешифрование чисел
        tabs.addTab(self._build_numeric_tab(), "Числа E(m)/D(c)")

        # Вкладка 3: Шифрование/Дешифрование текста
        tabs.addTab(self._build_text_tab(), "Текст E(m)/D(c)")

        # Вкладка 4: Факторизация (NP-сложность)
        tabs.addTab(self._build_factor_tab(), "Факторизация (NP)")

        # Лог
        self.log = QTextEdit()
        self.log.setReadOnly(True)
        self.log.setFont(self.mono_font)
        self.log.setMaximumHeight(200)
        layout.addWidget(QLabel("Лог операций:"))
        layout.addWidget(self.log)

    # ---- Вкладка: Генерация ключей -------------------------------------------

    def _build_keygen_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Способ задания: ручной ввод p, q или автогенерация
        mode_group = QGroupBox("Способ задания простых чисел")
        mode_layout = QVBoxLayout(mode_group)

        # Ручной ввод
        manual_layout = QHBoxLayout()
        manual_layout.addWidget(QLabel("p ="))
        self.input_p = QLineEdit("61")
        manual_layout.addWidget(self.input_p)
        manual_layout.addWidget(QLabel("q ="))
        self.input_q = QLineEdit("53")
        manual_layout.addWidget(self.input_q)
        manual_layout.addWidget(QLabel("e ="))
        self.input_e = QLineEdit("17")
        self.input_e.setToolTip("Оставьте пустым для автовыбора")
        manual_layout.addWidget(self.input_e)
        btn_manual = QPushButton("Сгенерировать ключи")
        btn_manual.clicked.connect(self._on_keygen_manual)
        manual_layout.addWidget(btn_manual)
        mode_layout.addLayout(manual_layout)

        # Автогенерация
        auto_layout = QHBoxLayout()
        auto_layout.addWidget(QLabel("Битовая длина p, q:"))
        self.spin_bits = QSpinBox()
        self.spin_bits.setRange(4, 512)
        self.spin_bits.setValue(16)
        auto_layout.addWidget(self.spin_bits)
        btn_auto = QPushButton("Автогенерация")
        btn_auto.clicked.connect(self._on_keygen_auto)
        auto_layout.addWidget(btn_auto)
        mode_layout.addLayout(auto_layout)

        layout.addWidget(mode_group)

        # Информация о ключах
        self.key_info_text = QTextEdit()
        self.key_info_text.setReadOnly(True)
        self.key_info_text.setFont(self.mono_font)
        layout.addWidget(QLabel("Параметры криптосистемы:"))
        layout.addWidget(self.key_info_text)

        return tab

    # ---- Вкладка: Числа E(m)/D(c) -------------------------------------------

    def _build_numeric_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Шифрование числа
        enc_group = QGroupBox("E(m): Шифрование числа — c = m^e mod n")
        enc_layout = QHBoxLayout(enc_group)
        enc_layout.addWidget(QLabel("m ="))
        self.input_m = QLineEdit("42")
        enc_layout.addWidget(self.input_m)
        btn_enc = QPushButton("Зашифровать E(m)")
        btn_enc.clicked.connect(self._on_encrypt_num)
        enc_layout.addWidget(btn_enc)
        self.label_c = QLabel("c = ?")
        self.label_c.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
        )
        enc_layout.addWidget(self.label_c)
        layout.addWidget(enc_group)

        # Дешифрование числа
        dec_group = QGroupBox("D(c): Дешифрование числа — m = c^d mod n")
        dec_layout = QHBoxLayout(dec_group)
        dec_layout.addWidget(QLabel("c ="))
        self.input_c = QLineEdit()
        dec_layout.addWidget(self.input_c)
        btn_dec = QPushButton("Расшифровать D(c)")
        btn_dec.clicked.connect(self._on_decrypt_num)
        dec_layout.addWidget(btn_dec)
        self.label_m = QLabel("m = ?")
        self.label_m.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
        )
        dec_layout.addWidget(self.label_m)
        layout.addWidget(dec_group)

        # Верификация
        ver_group = QGroupBox("V(E(m), D(c)): Верификация D(E(m)) == m")
        ver_layout = QHBoxLayout(ver_group)
        ver_layout.addWidget(QLabel("m ="))
        self.input_v = QLineEdit("42")
        ver_layout.addWidget(self.input_v)
        btn_ver = QPushButton("Проверить V")
        btn_ver.clicked.connect(self._on_verify)
        ver_layout.addWidget(btn_ver)
        self.label_v = QLabel("результат: ?")
        ver_layout.addWidget(self.label_v)
        layout.addWidget(ver_group)

        layout.addStretch()
        return tab

    # ---- Вкладка: Текст E(m)/D(c) -------------------------------------------

    def _build_text_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Шифрование текста
        enc_group = QGroupBox("E(m): Посимвольное шифрование текста")
        enc_layout = QVBoxLayout(enc_group)
        self.input_text = QLineEdit("Привет, RSA!")
        enc_layout.addWidget(self.input_text)
        btn_enc_text = QPushButton("Зашифровать текст")
        btn_enc_text.clicked.connect(self._on_encrypt_text)
        enc_layout.addWidget(btn_enc_text)
        self.enc_text_result = QTextEdit()
        self.enc_text_result.setReadOnly(True)
        self.enc_text_result.setFont(self.mono_font)
        self.enc_text_result.setMaximumHeight(100)
        enc_layout.addWidget(self.enc_text_result)
        layout.addWidget(enc_group)

        # Дешифрование текста
        dec_group = QGroupBox("D(c): Дешифрование из шифротекста")
        dec_layout = QVBoxLayout(dec_group)
        self.input_cipher_text = QTextEdit()
        self.input_cipher_text.setFont(self.mono_font)
        self.input_cipher_text.setMaximumHeight(100)
        self.input_cipher_text.setPlaceholderText(
            "Введите шифротекст (числа через запятую) или "
            "нажмите 'Зашифровать текст' выше"
        )
        dec_layout.addWidget(self.input_cipher_text)
        btn_dec_text = QPushButton("Расшифровать текст")
        btn_dec_text.clicked.connect(self._on_decrypt_text)
        dec_layout.addWidget(btn_dec_text)
        self.dec_text_result = QLineEdit()
        self.dec_text_result.setReadOnly(True)
        dec_layout.addWidget(self.dec_text_result)
        layout.addWidget(dec_group)

        layout.addStretch()
        return tab

    # ---- Вкладка: Факторизация -----------------------------------------------

    def _build_factor_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)

        info_label = QLabel(
            "NP-сложная задача факторизации: зная n = p·q, найти p и q.\n"
            "Криптостойкость RSA основана на том, что при достаточно\n"
            "больших p и q (≥ 1024 бит каждый) факторизация n\n"
            "вычислительно неосуществима за полиномиальное время."
        )
        info_label.setWordWrap(True)
        layout.addWidget(info_label)

        factor_group = QGroupBox("Попытка факторизации n (пробное деление)")
        factor_layout = QHBoxLayout(factor_group)
        factor_layout.addWidget(QLabel("n ="))
        self.input_factor_n = QLineEdit()
        self.input_factor_n.setPlaceholderText(
            "Введите число или используйте текущий n"
        )
        factor_layout.addWidget(self.input_factor_n)
        btn_use_n = QPushButton("Подставить текущий n")
        btn_use_n.clicked.connect(self._on_use_current_n)
        factor_layout.addWidget(btn_use_n)
        btn_factor = QPushButton("Факторизовать")
        btn_factor.clicked.connect(self._on_factorize)
        factor_layout.addWidget(btn_factor)
        layout.addWidget(factor_group)

        self.factor_result = QTextEdit()
        self.factor_result.setReadOnly(True)
        self.factor_result.setFont(self.mono_font)
        layout.addWidget(self.factor_result)

        layout.addStretch()
        return tab

    # ---- Обработчики событий -------------------------------------------------

    def _on_keygen_manual(self) -> None:
        """Генерация ключей из вручную заданных p и q."""
        try:
            p = int(self.input_p.text().strip())
            q = int(self.input_q.text().strip())
            e_text = self.input_e.text().strip()
            e = int(e_text) if e_text else 0
            self.rsa = RSACryptoSystem(p=p, q=q, e=e)
            self._display_key_info()
            self._log(f"Ключи сгенерированы: p={p}, q={q}, e={self.rsa.e}")
        except ValueError as ex:
            QMessageBox.warning(self, "Ошибка", str(ex))

    def _on_keygen_auto(self) -> None:
        """Автоматическая генерация ключей."""
        try:
            bits = self.spin_bits.value()
            p = generate_prime(bits)
            q = generate_prime(bits)
            while q == p:
                q = generate_prime(bits)
            self.rsa = RSACryptoSystem(p=p, q=q)
            self.input_p.setText(str(p))
            self.input_q.setText(str(q))
            self.input_e.setText(str(self.rsa.e))
            self._display_key_info()
            self._log(
                f"Автогенерация: p={p}, q={q}, "
                f"n={self.rsa.n} [{self.rsa.n.bit_length()} бит]"
            )
        except ValueError as ex:
            QMessageBox.warning(self, "Ошибка", str(ex))

    def _display_key_info(self) -> None:
        """Отображает информацию о сгенерированных ключах."""
        if self.rsa is None:
            return
        info = self.rsa.key_info()
        text = (
            f"Криптосистема Σ₀ = (M*, Q, C*, E(m), D(c) | V(E(m), D(c)))\n"
            f"{'─' * 60}\n"
            f"  p = {info['p']}\n"
            f"  q = {info['q']}\n"
            f"  n = p·q = {info['n']}  [{info['key_bits']} бит]\n"
            f"  φ(n) = (p−1)(q−1) = {info['phi']}\n"
            f"{'─' * 60}\n"
            f"  Открытый ключ  K_F (e, n): ({info['e']}, {info['n']})\n"
            f"  Закрытый ключ  K_F⁻¹(d, n): ({info['d']}, {info['n']})\n"
            f"{'─' * 60}\n"
            f"  M* = {{0, 1, ..., {info['n'] - 1}}}  "
            f"(множество открытых текстов)\n"
            f"  Q  = {{0, 1, ..., {info['n'] - 1}}}  "
            f"(числовые эквиваленты)\n"
            f"  C* = {{0, 1, ..., {info['n'] - 1}}}  "
            f"(множество шифротекстов)\n"
            f"  E(m) = m^{info['e']} mod {info['n']}\n"
            f"  D(c) = c^{info['d']} mod {info['n']}\n"
        )
        self.key_info_text.setText(text)

    def _on_encrypt_num(self) -> None:
        """Шифрование числа."""
        if not self._check_keys():
            return
        try:
            m = int(self.input_m.text().strip())
            c = self.rsa.encrypt(m)
            self.label_c.setText(f"c = {c}")
            self.input_c.setText(str(c))
            self._log(f"E({m}) = {m}^{self.rsa.e} mod {self.rsa.n} = {c}")
        except ValueError as ex:
            QMessageBox.warning(self, "Ошибка", str(ex))

    def _on_decrypt_num(self) -> None:
        """Дешифрование числа."""
        if not self._check_keys():
            return
        try:
            c = int(self.input_c.text().strip())
            m = self.rsa.decrypt(c)
            self.label_m.setText(f"m = {m}")
            self._log(f"D({c}) = {c}^{self.rsa.d} mod {self.rsa.n} = {m}")
        except ValueError as ex:
            QMessageBox.warning(self, "Ошибка", str(ex))

    def _on_verify(self) -> None:
        """Верификация D(E(m)) == m."""
        if not self._check_keys():
            return
        try:
            m = int(self.input_v.text().strip())
            result = self.rsa.verify(m)
            c = self.rsa.encrypt(m)
            m2 = self.rsa.decrypt(c)
            status = "ВЕРНО" if result else "ОШИБКА"
            self.label_v.setText(f"результат: {status}")
            self._log(
                f"V: m={m} → E(m)={c} → D(E(m))={m2} → "
                f"D(E(m))==m ? {status}"
            )
        except ValueError as ex:
            QMessageBox.warning(self, "Ошибка", str(ex))

    def _on_encrypt_text(self) -> None:
        """Шифрование текста."""
        if not self._check_keys():
            return
        try:
            text = self.input_text.text()
            cipher = self.rsa.encrypt_text(text)
            cipher_str = ", ".join(map(str, cipher))
            self.enc_text_result.setText(cipher_str)
            self.input_cipher_text.setText(cipher_str)
            self._log(f"Зашифрован текст ({len(text)} символов)")
        except ValueError as ex:
            QMessageBox.warning(self, "Ошибка", str(ex))

    def _on_decrypt_text(self) -> None:
        """Дешифрование текста."""
        if not self._check_keys():
            return
        try:
            cipher_str = self.input_cipher_text.toPlainText().strip()
            cipher = [int(x.strip()) for x in cipher_str.split(",") if x.strip()]
            text = self.rsa.decrypt_text(cipher)
            self.dec_text_result.setText(text)
            self._log(f"Расшифрован текст: '{text}'")
        except ValueError as ex:
            QMessageBox.warning(self, "Ошибка", str(ex))

    def _on_use_current_n(self) -> None:
        """Подставляет текущий n в поле факторизации."""
        if self.rsa is None:
            QMessageBox.warning(
                self, "Ошибка", "Сначала сгенерируйте ключи"
            )
            return
        self.input_factor_n.setText(str(self.rsa.n))

    def _on_factorize(self) -> None:
        """Попытка факторизации числа n."""
        try:
            n = int(self.input_factor_n.text().strip())
            if n < 4:
                self.factor_result.setText("Число слишком маленькое для факторизации")
                return

            import time
            start = time.perf_counter()
            result = trial_factorize(n, limit=10**7)
            elapsed = time.perf_counter() - start

            bits = n.bit_length()
            text = f"n = {n}  [{bits} бит]\n\n"

            if result:
                p, q = result
                text += (
                    f"Факторизация найдена за {elapsed:.4f} с:\n"
                    f"  n = {p} × {q}\n\n"
                    f"При малых числах факторизация тривиальна.\n"
                )
            else:
                text += (
                    f"Факторизация НЕ найдена за {elapsed:.4f} с\n"
                    f"(перебор делителей до 10^7).\n\n"
                )

            text += (
                f"{'─' * 60}\n"
                f"NP-сложность задачи факторизации:\n\n"
                f"Наилучший известный алгоритм — решето числового поля\n"
                f"(General Number Field Sieve, GNFS) имеет субэкспоненциальную\n"
                f"сложность:\n\n"
                f"  T(n) = exp(c · (ln n)^(1/3) · (ln ln n)^(2/3))\n\n"
                f"где c ≈ 1.923.\n\n"
                f"Для n из {bits} бит это {'легко' if bits < 64 else 'сложно' if bits < 256 else 'практически невозможно'}.\n"
                f"Рекомендуемый размер ключа RSA: ≥ 2048 бит.\n"
            )

            self.factor_result.setText(text)
            self._log(
                f"Факторизация n={n} [{bits} бит]: "
                f"{'успех' if result else 'не найдена'} за {elapsed:.4f} с"
            )
        except ValueError:
            QMessageBox.warning(self, "Ошибка", "Введите корректное целое число")

    # ---- Утилиты -------------------------------------------------------------

    def _check_keys(self) -> bool:
        if self.rsa is None:
            QMessageBox.warning(
                self, "Ошибка",
                "Сначала сгенерируйте ключи (вкладка «Генерация ключей»)"
            )
            return False
        return True

    def _log(self, message: str) -> None:
        self.log.append(message)


# ---------------------------------------------------------------------------
#  Демонстрация (консольная)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Если есть аргумент --cli, запускаем консольный режим
    if "--cli" in sys.argv:
        print("=" * 65)
        print("  Алгоритм RSA — модель криптосистемы Осипяна")
        print("  Σ₀ = (M*, Q, C*, E(m), D(c) | V(E(m), D(c)))")
        print("=" * 65)

        # Генерация ключей
        p, q = 61, 53
        rsa = RSACryptoSystem(p=p, q=q, e=17)
        info = rsa.key_info()

        print(f"\n  p = {info['p']},  q = {info['q']}")
        print(f"  n = p·q = {info['n']}  [{info['key_bits']} бит]")
        print(f"  φ(n) = (p−1)(q−1) = {info['phi']}")
        print(f"  e = {info['e']}  (открытая экспонента)")
        print(f"  d = {info['d']}  (секретная экспонента)")
        print(f"\n  Открытый ключ  K_F:   ({info['e']}, {info['n']})")
        print(f"  Закрытый ключ  K_F⁻¹: ({info['d']}, {info['n']})")

        # Шифрование числа
        m = 42
        print(f"\n{'─' * 65}")
        print(f"  E(m): Шифрование")
        print(f"{'─' * 65}")
        c = rsa.encrypt(m)
        print(f"  m = {m}")
        print(f"  c = E(m) = m^e mod n = {m}^{rsa.e} mod {rsa.n} = {c}")

        # Дешифрование
        print(f"\n{'─' * 65}")
        print(f"  D(c): Дешифрование")
        print(f"{'─' * 65}")
        m2 = rsa.decrypt(c)
        print(f"  c = {c}")
        print(f"  m = D(c) = c^d mod n = {c}^{rsa.d} mod {rsa.n} = {m2}")

        # Верификация
        print(f"\n{'─' * 65}")
        print(f"  V(E(m), D(c)): Верификация")
        print(f"{'─' * 65}")
        print(f"  D(E({m})) == {m} ? {rsa.verify(m)}")

        # Текстовое сообщение
        print(f"\n{'─' * 65}")
        print(f"  Шифрование текста (посимвольно)")
        print(f"{'─' * 65}")
        text = "Hello"
        cipher = rsa.encrypt_text(text)
        print(f"  Текст: '{text}'")
        print(f"  Шифр:  {cipher}")
        decrypted = rsa.decrypt_text(cipher)
        print(f"  Расшифровано: '{decrypted}'")

        # Факторизация
        print(f"\n{'─' * 65}")
        print(f"  NP-сложная задача: факторизация n = {rsa.n}")
        print(f"{'─' * 65}")
        result = trial_factorize(rsa.n)
        if result:
            print(f"  Найдено: {rsa.n} = {result[0]} × {result[1]}")
        print(f"  (Для малых чисел факторизация тривиальна)")
        print(f"  Криптостойкость обеспечивается при n ≥ 2048 бит")

    else:
        # Графический режим (по умолчанию)
        app = QApplication(sys.argv)
        window = RSAMainWindow()
        window.show()
        sys.exit(app.exec())
