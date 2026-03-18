"""
Алгоритм классического аддитивного рюкзака (АВКР) — криптосистема Меркла-Хеллмана.

Оформлено в соответствии с моделью алфавитной криптосистемы
В.О. Осипяна: Σ₀ = (M*, Q, C*, E(m), D(c) | V(E(m), D(c))).

NP-сложная задача в основе АВКР — задача о рюкзаке (Subset Sum Problem):
дан набор положительных целых чисел {a₁, a₂, ..., aₙ} и целое число S,
требуется определить, существует ли подмножество, сумма которого равна S.

Литература: Осипян В.О. Разработка методов построения систем передачи
            и защиты информации. Монография. КубГУ, 2004.
"""

from __future__ import annotations

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
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont


# ---------------------------------------------------------------------------
#  Вспомогательные функции теории чисел
# ---------------------------------------------------------------------------

def gcd(a: int, b: int) -> int:
    """Наибольший общий делитель (алгоритм Евклида)."""
    while b:
        a, b = b, a % b
    return a


def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    """Расширенный алгоритм Евклида.

    Возвращает (g, x, y) такие, что a·x + b·y = g = gcd(a, b).
    Необходим для нахождения мультипликативного обратного w⁻¹ mod q.
    """
    if a == 0:
        return b, 0, 1
    g, x, y = extended_gcd(b % a, a)
    return g, y - (b // a) * x, x


def mod_inverse(a: int, m: int) -> int:
    """Вычисляет мультипликативный обратный элемент: a⁻¹ mod m.

    Используется для дешифрования: нужно найти w⁻¹ mod q,
    чтобы вычислить S' = c · w⁻¹ mod q из шифротекста c.
    """
    g, x, _ = extended_gcd(a % m, m)
    if g != 1:
        raise ValueError(
            f"Обратный элемент не существует: gcd({a}, {m}) = {g} ≠ 1"
        )
    return x % m


def is_prime(n: int) -> bool:
    """Проверяет, является ли число простым."""
    if n < 2:
        return False
    if n < 4:
        return True
    if n % 2 == 0 or n % 3 == 0:
        return False
    i = 5
    while i * i <= n:
        if n % i == 0 or n % (i + 2) == 0:
            return False
        i += 6
    return True


def generate_prime_in_range(low: int, high: int) -> int:
    """Генерирует случайное простое число в диапазоне [low, high]."""
    attempts = 0
    while attempts < 10000:
        n = random.randint(low, high)
        if is_prime(n):
            return n
        attempts += 1
    # Перебор, если случайный поиск не дал результата
    for n in range(low, high + 1):
        if is_prime(n):
            return n
    raise ValueError(f"Не найдено простое число в диапазоне [{low}, {high}]")


# ---------------------------------------------------------------------------
#  Генерация сверхвозрастающей последовательности
# ---------------------------------------------------------------------------

def generate_superincreasing_sequence(length: int, start_range: tuple[int, int] = (2, 10)) -> list[int]:
    """Генерирует сверхвозрастающую последовательность длины length.

    Сверхвозрастающая последовательность (b₁, b₂, ..., bₙ) — это
    последовательность, в которой каждый элемент строго больше суммы
    всех предыдущих:
        bᵢ > Σⱼ₌₁ⁱ⁻¹ bⱼ  для всех i = 2, ..., n

    Задача о рюкзаке для сверхвозрастающей последовательности решается
    за линейное время O(n) жадным алгоритмом (это «лёгкий» рюкзак).
    Именно эта последовательность составляет закрытый ключ.

    Параметры
    ---------
    length : int
        Длина последовательности (= длина блока сообщения в битах).
    start_range : tuple[int, int]
        Диапазон для первого элемента последовательности.
    """
    if length < 1:
        raise ValueError("Длина последовательности должна быть >= 1")

    # Первый элемент — случайное число из start_range
    seq = [random.randint(*start_range)]
    total = seq[0]

    for _ in range(1, length):
        # Каждый следующий элемент > суммы всех предыдущих
        # Добавляем случайный отступ для разнообразия
        next_val = total + random.randint(1, max(total, 10))
        seq.append(next_val)
        total += next_val

    return seq


# ---------------------------------------------------------------------------
#  Решение «лёгкого» рюкзака (сверхвозрастающая последовательность)
# ---------------------------------------------------------------------------

def solve_superincreasing_knapsack(target: int, sequence: list[int]) -> list[int] | None:
    """Решает задачу о рюкзаке для сверхвозрастающей последовательности.

    Жадный алгоритм: проходим по последовательности справа налево.
    Если текущий элемент ≤ остатка, включаем его (бит = 1).

    Это ключевая операция дешифрования: после вычисления S' = c · w⁻¹ mod q
    нужно восстановить биты сообщения из S' по закрытой
    сверхвозрастающей последовательности.

    Возвращает список бит [x₁, x₂, ..., xₙ] или None, если решение не найдено.
    """
    n = len(sequence)
    bits = [0] * n
    remainder = target

    # Проходим справа налево (от наибольшего к наименьшему)
    for i in range(n - 1, -1, -1):
        if sequence[i] <= remainder:
            bits[i] = 1
            remainder -= sequence[i]

    # Проверяем, что остаток = 0 (решение корректно)
    if remainder != 0:
        return None

    return bits


# ---------------------------------------------------------------------------
#  Класс-криптосистема АВКР (Меркла-Хеллмана)
# ---------------------------------------------------------------------------

@dataclass
class KnapsackCryptoSystem:
    """Реализация криптосистемы Σ₀ = (M*, Q, C*, E(m), D(c) | V(E(m), D(c)))
    на основе алгоритма аддитивного рюкзака (АВКР, Merkle-Hellman).

    Алгоритм АВКР основан на NP-сложной задаче о сумме подмножеств:
    дана последовательность (a₁, a₂, ..., aₙ) и число S, найти подмножество
    {i₁, i₂, ...}, что Σ aᵢⱼ = S. Для общего случая задача NP-полна.

    Схема Меркла-Хеллмана:
    ─────────────────────
    Закрытый ключ: сверхвозрастающая последовательность B = (b₁, ..., bₙ),
                   модуль q > Σbᵢ, множитель w (gcd(w, q) = 1).
    Открытый ключ: последовательность A = (a₁, ..., aₙ),
                   где aᵢ = w · bᵢ mod q.

    E(m): c = Σᵢ mᵢ · aᵢ  (сумма элементов открытого ключа, где mᵢ = 1).
    D(c): S' = c · w⁻¹ mod q, затем решаем лёгкий рюкзак для B и S'.

    В терминологии Осипяна
    ──────────────────────
    M*   — множество всех двоичных блоков длины n: m = (m₁, m₂, ..., mₙ), mᵢ ∈ {0,1}.
    Q    — алфавит {0, 1} (двоичные значения бит).
    C*   — множество шифротекстов (целых чисел — сумм элементов открытого ключа).
    E(m) — алгоритм шифрования: c = Σᵢ mᵢ · aᵢ.
    D(c) — алгоритм дешифрования: S' = c · w⁻¹ mod q → жадный алгоритм по B.
    V(E(m), D(c)) — верификация: D(E(m)) = m для любого m ∈ M*.

    Атрибуты
    --------
    block_size : int
        Длина блока (количество бит в одном блоке сообщения).
    private_seq : list[int]
        Сверхвозрастающая последовательность B (закрытый ключ).
    q : int
        Модуль (q > sum(B)).
    w : int
        Множитель (gcd(w, q) = 1).
    public_seq : list[int]
        Открытая последовательность A: aᵢ = w · bᵢ mod q.
    w_inv : int
        Обратный элемент: w⁻¹ mod q.
    """

    block_size: int
    private_seq: list[int] = field(default_factory=list)
    q: int = 0
    w: int = 0
    public_seq: list[int] = field(init=False, default_factory=list)
    w_inv: int = field(init=False, default=0)

    def __post_init__(self) -> None:
        """Генерация ключей АВКР."""
        if self.block_size < 1:
            raise ValueError("Размер блока должен быть >= 1")

        # Если закрытая последовательность не задана — генерируем
        if not self.private_seq:
            self.private_seq = generate_superincreasing_sequence(self.block_size)
        else:
            if len(self.private_seq) != self.block_size:
                raise ValueError(
                    f"Длина закрытой последовательности ({len(self.private_seq)}) "
                    f"не совпадает с размером блока ({self.block_size})"
                )
            # Проверяем сверхвозрастаемость
            self._validate_superincreasing(self.private_seq)

        total = sum(self.private_seq)

        # Если модуль q не задан — выбираем случайное простое число > sum(B)
        if self.q == 0:
            # q должно быть > суммы всех элементов закрытой последовательности
            self.q = generate_prime_in_range(total + 1, total * 2 + 100)
        else:
            if self.q <= total:
                raise ValueError(
                    f"Модуль q = {self.q} должен быть > суммы "
                    f"закрытой последовательности = {total}"
                )

        # Если множитель w не задан — выбираем случайный, взаимно простой с q
        if self.w == 0:
            self.w = self._choose_w()
        else:
            if gcd(self.w, self.q) != 1:
                raise ValueError(
                    f"w = {self.w} не взаимно просто с q = {self.q}"
                )

        # Вычисляем w⁻¹ mod q (необходим для дешифрования)
        self.w_inv = mod_inverse(self.w, self.q)

        # Формируем открытый ключ: aᵢ = w · bᵢ mod q
        # Это «трудная» последовательность — не сверхвозрастающая
        self.public_seq = [(self.w * b) % self.q for b in self.private_seq]

    def _choose_w(self) -> int:
        """Выбирает случайный множитель w: 2 ≤ w < q, gcd(w, q) = 1.

        Поскольку q — простое число, любое w ∈ [2, q-1] подходит
        (gcd(w, q) = 1 для любого w, не кратного q).
        """
        while True:
            w = random.randint(2, self.q - 1)
            if gcd(w, self.q) == 1:
                return w

    @staticmethod
    def _validate_superincreasing(seq: list[int]) -> None:
        """Проверяет, что последовательность является сверхвозрастающей."""
        total = 0
        for i, val in enumerate(seq):
            if val <= 0:
                raise ValueError(
                    f"Элемент [{i}] = {val} должен быть положительным"
                )
            if i > 0 and val <= total:
                raise ValueError(
                    f"Последовательность не сверхвозрастающая: "
                    f"b[{i}] = {val} ≤ Σb[0..{i - 1}] = {total}"
                )
            total += val

    # ---- E(m): шифрование ---------------------------------------------------

    def encrypt_block(self, bits: list[int]) -> int:
        """Шифрует один блок (список бит): c = Σᵢ mᵢ · aᵢ.

        Это функция E(m) криптосистемы — прямое преобразование.
        Каждый бит сообщения mᵢ умножается на соответствующий элемент
        открытого ключа aᵢ, результаты суммируются.

        Параметры
        ---------
        bits : list[int]
            Блок сообщения — список из 0 и 1 длины block_size.

        Возвращает
        ----------
        int
            Шифротекст c = Σ mᵢ · aᵢ.
        """
        self._validate_bits(bits)
        # Формула шифрования: c = Σᵢ₌₁ⁿ mᵢ · aᵢ
        return sum(b * a for b, a in zip(bits, self.public_seq))

    # ---- D(c): дешифрование -------------------------------------------------

    def decrypt_block(self, c: int) -> list[int]:
        """Дешифрует шифротекст c обратно в блок бит.

        Это функция D(c) криптосистемы — обратное преобразование.

        Шаг 1: вычисляем S' = c · w⁻¹ mod q.
                Это переводит задачу из «трудного» рюкзака (открытый ключ A)
                в «лёгкий» рюкзак (закрытый ключ B), т.к.:
                S' = c · w⁻¹ = (Σ mᵢ · w · bᵢ) · w⁻¹ = Σ mᵢ · bᵢ (mod q)

        Шаг 2: решаем задачу о рюкзаке для S' и сверхвозрастающей
                последовательности B жадным алгоритмом за O(n).

        Параметры
        ---------
        c : int
            Шифротекст (неотрицательное целое число).

        Возвращает
        ----------
        list[int]
            Расшифрованный блок бит [m₁, m₂, ..., mₙ].
        """
        if not isinstance(c, int) or c < 0:
            raise ValueError(
                f"Шифротекст должен быть неотрицательным целым, получено {c}"
            )

        # Шаг 1: S' = c · w⁻¹ mod q
        s_prime = (c * self.w_inv) % self.q

        # Шаг 2: жадный алгоритм по сверхвозрастающей последовательности
        bits = solve_superincreasing_knapsack(s_prime, self.private_seq)

        if bits is None:
            raise ValueError(
                f"Не удалось расшифровать шифротекст c = {c} "
                f"(S' = {s_prime} не раскладывается по закрытой последовательности)"
            )

        return bits

    # ---- Шифрование/дешифрование текстовых сообщений -------------------------

    def encrypt_text(self, text: str) -> list[int]:
        """Шифрует текстовую строку блоками по block_size бит.

        Каждый символ преобразуется в его двоичное представление,
        символы объединяются в общий поток бит, который разбивается
        на блоки длины block_size. Каждый блок шифруется отдельно.

        Параметры
        ---------
        text : str
            Текст для шифрования.

        Возвращает
        ----------
        list[int]
            Список шифротекстов (по одному на блок).
        """
        if not text:
            raise ValueError("Текст не может быть пустым")

        # Преобразуем текст в поток бит (8 бит на символ для ASCII,
        # 16 бит для Unicode, но мы используем 8 бит для простоты)
        bit_stream: list[int] = []
        for char in text:
            code = ord(char)
            if code > 255:
                raise ValueError(
                    f"Символ '{char}' (код {code}) выходит за пределы ASCII. "
                    f"Используйте латиницу и базовые символы."
                )
            # 8 бит на символ, старший бит первым
            for bit_pos in range(7, -1, -1):
                bit_stream.append((code >> bit_pos) & 1)

        # Дополняем до кратности block_size нулями
        remainder = len(bit_stream) % self.block_size
        if remainder != 0:
            bit_stream.extend([0] * (self.block_size - remainder))

        # Шифруем по блокам
        ciphertext: list[int] = []
        for i in range(0, len(bit_stream), self.block_size):
            block = bit_stream[i:i + self.block_size]
            ciphertext.append(self.encrypt_block(block))

        return ciphertext

    def decrypt_text(self, ciphertext: list[int], text_length: int) -> str:
        """Дешифрует список шифротекстов обратно в строку.

        Параметры
        ---------
        ciphertext : list[int]
            Список зашифрованных блоков.
        text_length : int
            Длина исходного текста (в символах), чтобы отбросить
            дополняющие нули.

        Возвращает
        ----------
        str
            Расшифрованная строка.
        """
        if not ciphertext:
            raise ValueError("Шифротекст не может быть пустым")
        if text_length < 1:
            raise ValueError("Длина текста должна быть >= 1")

        # Расшифровываем каждый блок
        bit_stream: list[int] = []
        for c in ciphertext:
            bits = self.decrypt_block(c)
            bit_stream.extend(bits)

        # Берём только нужное количество бит (8 * text_length)
        total_bits = text_length * 8
        bit_stream = bit_stream[:total_bits]

        # Собираем символы из бит
        chars: list[str] = []
        for i in range(0, len(bit_stream), 8):
            byte_bits = bit_stream[i:i + 8]
            if len(byte_bits) < 8:
                break
            code = 0
            for bit in byte_bits:
                code = (code << 1) | bit
            chars.append(chr(code))

        return "".join(chars)

    # ---- V(E(m), D(c)): верификация ------------------------------------------

    def verify_block(self, bits: list[int]) -> bool:
        """Проверяет свойство криптосистемы: D(E(m)) == m.

        Это функция V(E(m), D(c)) — верификация корректности.
        """
        self._validate_bits(bits)
        c = self.encrypt_block(bits)
        decrypted = self.decrypt_block(c)
        return decrypted == bits

    # ---- Информация о ключах -------------------------------------------------

    def key_info(self) -> dict:
        """Возвращает полную информацию о ключах."""
        return {
            "block_size": self.block_size,
            "private_seq": self.private_seq,
            "q": self.q,
            "w": self.w,
            "w_inv": self.w_inv,
            "public_seq": self.public_seq,
            "sum_private": sum(self.private_seq),
        }

    # ---- Вспомогательные методы ----------------------------------------------

    def _validate_bits(self, bits: list[int]) -> None:
        """Проверяет корректность входного блока бит."""
        if len(bits) != self.block_size:
            raise ValueError(
                f"Длина блока ({len(bits)}) не совпадает "
                f"с размером блока ({self.block_size})"
            )
        for i, b in enumerate(bits):
            if b not in (0, 1):
                raise ValueError(
                    f"Элемент [{i}] = {b} должен быть 0 или 1"
                )

    def __repr__(self) -> str:
        return (
            f"KnapsackCryptoSystem(block_size={self.block_size}, "
            f"q={self.q}, w={self.w})"
        )


# ---------------------------------------------------------------------------
#  Демонстрация NP-сложности: попытка решения общего рюкзака перебором
# ---------------------------------------------------------------------------

def brute_force_knapsack(target: int, sequence: list[int], limit: int = 2**20) -> list[int] | None:
    """Попытка решения задачи о рюкзаке полным перебором.

    Перебирает все 2ⁿ подмножеств (до limit).
    Демонстрирует экспоненциальную сложность задачи.

    Возвращает список бит или None.
    """
    n = len(sequence)
    total_subsets = 2 ** n

    if total_subsets > limit:
        # Ограничиваем перебор
        total_subsets = limit

    for mask in range(total_subsets):
        s = 0
        for i in range(n):
            if mask & (1 << i):
                s += sequence[i]
        if s == target:
            return [(mask >> i) & 1 for i in range(n)]

    return None


# ---------------------------------------------------------------------------
#  GUI на PyQt6
# ---------------------------------------------------------------------------

class KnapsackMainWindow(QMainWindow):
    """Главное окно приложения криптосистемы АВКР."""

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(
            "АВКР — криптосистема Σ₀ = (M*, Q, C*, E(m), D(c) | V(E(m), D(c)))"
        )
        self.setMinimumSize(1000, 750)

        self.crypto: KnapsackCryptoSystem | None = None

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

        tabs.addTab(self._build_keygen_tab(), "Генерация ключей")
        tabs.addTab(self._build_block_tab(), "Блок E(m)/D(c)")
        tabs.addTab(self._build_text_tab(), "Текст E(m)/D(c)")
        tabs.addTab(self._build_np_tab(), "NP-сложность")

        # Лог
        self.log = QTextEdit()
        self.log.setReadOnly(True)
        self.log.setFont(self.mono_font)
        self.log.setMaximumHeight(180)
        layout.addWidget(QLabel("Лог операций:"))
        layout.addWidget(self.log)

    # ---- Вкладка: Генерация ключей -------------------------------------------

    def _build_keygen_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Параметры
        params_group = QGroupBox("Параметры генерации")
        params_layout = QVBoxLayout(params_group)

        # Размер блока
        row1 = QHBoxLayout()
        row1.addWidget(QLabel("Размер блока (бит):"))
        self.spin_block = QSpinBox()
        self.spin_block.setRange(4, 64)
        self.spin_block.setValue(8)
        row1.addWidget(self.spin_block)
        params_layout.addLayout(row1)

        # Ручной ввод закрытой последовательности
        row2 = QHBoxLayout()
        row2.addWidget(QLabel("Закр. послед. B (через запятую):"))
        self.input_private = QLineEdit()
        self.input_private.setPlaceholderText(
            "Оставьте пустым для автогенерации, "
            "например: 2, 5, 11, 23, 47, 95, 191, 383"
        )
        row2.addWidget(self.input_private)
        params_layout.addLayout(row2)

        # Ручной ввод q и w
        row3 = QHBoxLayout()
        row3.addWidget(QLabel("q ="))
        self.input_q = QLineEdit()
        self.input_q.setPlaceholderText("авто")
        row3.addWidget(self.input_q)
        row3.addWidget(QLabel("w ="))
        self.input_w = QLineEdit()
        self.input_w.setPlaceholderText("авто")
        row3.addWidget(self.input_w)
        params_layout.addLayout(row3)

        # Кнопки
        btn_layout = QHBoxLayout()
        btn_auto = QPushButton("Автогенерация ключей")
        btn_auto.clicked.connect(self._on_keygen_auto)
        btn_layout.addWidget(btn_auto)
        btn_manual = QPushButton("Ручная генерация")
        btn_manual.clicked.connect(self._on_keygen_manual)
        btn_layout.addWidget(btn_manual)
        params_layout.addLayout(btn_layout)

        layout.addWidget(params_group)

        # Информация о ключах
        self.key_info_text = QTextEdit()
        self.key_info_text.setReadOnly(True)
        self.key_info_text.setFont(self.mono_font)
        layout.addWidget(QLabel("Параметры криптосистемы:"))
        layout.addWidget(self.key_info_text)

        return tab

    # ---- Вкладка: Блок E(m)/D(c) -------------------------------------------

    def _build_block_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)

        # Шифрование блока
        enc_group = QGroupBox("E(m): Шифрование блока — c = Σ mᵢ · aᵢ")
        enc_layout = QVBoxLayout(enc_group)
        row = QHBoxLayout()
        row.addWidget(QLabel("Биты m ="))
        self.input_bits = QLineEdit("1,0,1,1,0,0,1,0")
        self.input_bits.setToolTip(
            "Введите блок бит через запятую, например: 1,0,1,1,0,0,1,0"
        )
        row.addWidget(self.input_bits)
        btn_enc = QPushButton("Зашифровать E(m)")
        btn_enc.clicked.connect(self._on_encrypt_block)
        row.addWidget(btn_enc)
        enc_layout.addLayout(row)
        self.label_c = QLabel("c = ?")
        self.label_c.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
        )
        enc_layout.addWidget(self.label_c)
        layout.addWidget(enc_group)

        # Дешифрование блока
        dec_group = QGroupBox("D(c): Дешифрование — S' = c·w⁻¹ mod q → жадный алгоритм")
        dec_layout = QVBoxLayout(dec_group)
        row2 = QHBoxLayout()
        row2.addWidget(QLabel("c ="))
        self.input_c = QLineEdit()
        row2.addWidget(self.input_c)
        btn_dec = QPushButton("Расшифровать D(c)")
        btn_dec.clicked.connect(self._on_decrypt_block)
        row2.addWidget(btn_dec)
        dec_layout.addLayout(row2)
        self.label_bits = QLabel("m = ?")
        self.label_bits.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
        )
        dec_layout.addWidget(self.label_bits)
        layout.addWidget(dec_group)

        # Верификация
        ver_group = QGroupBox("V(E(m), D(c)): Верификация D(E(m)) == m")
        ver_layout = QVBoxLayout(ver_group)
        row3 = QHBoxLayout()
        row3.addWidget(QLabel("Биты m ="))
        self.input_v = QLineEdit("1,0,1,1,0,0,1,0")
        row3.addWidget(self.input_v)
        btn_ver = QPushButton("Проверить V")
        btn_ver.clicked.connect(self._on_verify)
        row3.addWidget(btn_ver)
        ver_layout.addLayout(row3)
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
        enc_group = QGroupBox("E(m): Шифрование текста (поблочно)")
        enc_layout = QVBoxLayout(enc_group)
        self.input_text = QLineEdit("Hello")
        enc_layout.addWidget(self.input_text)
        btn_enc = QPushButton("Зашифровать текст")
        btn_enc.clicked.connect(self._on_encrypt_text)
        enc_layout.addWidget(btn_enc)
        self.enc_text_result = QTextEdit()
        self.enc_text_result.setReadOnly(True)
        self.enc_text_result.setFont(self.mono_font)
        self.enc_text_result.setMaximumHeight(100)
        enc_layout.addWidget(self.enc_text_result)
        layout.addWidget(enc_group)

        # Дешифрование текста
        dec_group = QGroupBox("D(c): Дешифрование текста")
        dec_layout = QVBoxLayout(dec_group)
        self.input_cipher_text = QTextEdit()
        self.input_cipher_text.setFont(self.mono_font)
        self.input_cipher_text.setMaximumHeight(100)
        self.input_cipher_text.setPlaceholderText(
            "Шифротекст (числа через запятую)"
        )
        dec_layout.addWidget(self.input_cipher_text)
        row = QHBoxLayout()
        row.addWidget(QLabel("Длина исходного текста:"))
        self.spin_text_len = QSpinBox()
        self.spin_text_len.setRange(1, 10000)
        self.spin_text_len.setValue(5)
        row.addWidget(self.spin_text_len)
        btn_dec = QPushButton("Расшифровать текст")
        btn_dec.clicked.connect(self._on_decrypt_text)
        row.addWidget(btn_dec)
        dec_layout.addLayout(row)
        self.dec_text_result = QLineEdit()
        self.dec_text_result.setReadOnly(True)
        dec_layout.addWidget(self.dec_text_result)
        layout.addWidget(dec_group)

        layout.addStretch()
        return tab

    # ---- Вкладка: NP-сложность -----------------------------------------------

    def _build_np_tab(self) -> QWidget:
        tab = QWidget()
        layout = QVBoxLayout(tab)

        info_label = QLabel(
            "NP-сложная задача о сумме подмножеств (Subset Sum Problem):\n"
            "Дана последовательность (a₁, a₂, ..., aₙ) и число S.\n"
            "Найти подмножество {i₁, i₂, ...}, что Σ aᵢⱼ = S.\n\n"
            "Криптостойкость АВКР:\n"
            "• Задача о рюкзаке для общей последовательности — NP-полна.\n"
            "• Атакующий видит только открытый ключ A (не сверхвозрастающий).\n"
            "• Без знания w и q перебор требует O(2ⁿ) операций.\n\n"
            "Примечание: в 1982 г. Шамир показал, что схему Меркла-Хеллмана\n"
            "можно взломать за полиномиальное время, используя LLL-алгоритм\n"
            "для приведения решёток. Поэтому АВКР не рекомендуется\n"
            "для реального использования."
        )
        info_label.setWordWrap(True)
        layout.addWidget(info_label)

        # Демонстрация перебора
        bf_group = QGroupBox(
            "Перебор: попытка решить рюкзак для открытого ключа"
        )
        bf_layout = QVBoxLayout(bf_group)

        row = QHBoxLayout()
        row.addWidget(QLabel("Целевая сумма S ="))
        self.input_target = QLineEdit()
        self.input_target.setPlaceholderText("Подставить из шифротекста")
        row.addWidget(self.input_target)
        btn_use_c = QPushButton("Взять последний c")
        btn_use_c.clicked.connect(self._on_use_last_c)
        row.addWidget(btn_use_c)
        btn_bf = QPushButton("Перебор (до 2²⁰)")
        btn_bf.clicked.connect(self._on_brute_force)
        row.addWidget(btn_bf)
        bf_layout.addLayout(row)

        self.bf_result = QTextEdit()
        self.bf_result.setReadOnly(True)
        self.bf_result.setFont(self.mono_font)
        bf_layout.addWidget(self.bf_result)
        layout.addWidget(bf_group)

        layout.addStretch()
        return tab

    # ---- Обработчики событий -------------------------------------------------

    def _on_keygen_auto(self) -> None:
        """Автоматическая генерация ключей."""
        try:
            block_size = self.spin_block.value()
            self.crypto = KnapsackCryptoSystem(block_size=block_size)
            self._display_key_info()
            self._log(
                f"Автогенерация: block_size={block_size}, "
                f"q={self.crypto.q}, w={self.crypto.w}"
            )
        except ValueError as ex:
            QMessageBox.warning(self, "Ошибка", str(ex))

    def _on_keygen_manual(self) -> None:
        """Генерация ключей из вручную заданных параметров."""
        try:
            block_size = self.spin_block.value()

            # Закрытая последовательность
            priv_text = self.input_private.text().strip()
            private_seq = []
            if priv_text:
                private_seq = [int(x.strip()) for x in priv_text.split(",")]
                block_size = len(private_seq)
                self.spin_block.setValue(block_size)

            # q и w
            q_text = self.input_q.text().strip()
            q = int(q_text) if q_text else 0
            w_text = self.input_w.text().strip()
            w = int(w_text) if w_text else 0

            self.crypto = KnapsackCryptoSystem(
                block_size=block_size,
                private_seq=private_seq if private_seq else [],
                q=q,
                w=w,
            )
            self._display_key_info()
            self._log(
                f"Ручная генерация: block_size={block_size}, "
                f"q={self.crypto.q}, w={self.crypto.w}"
            )
        except ValueError as ex:
            QMessageBox.warning(self, "Ошибка", str(ex))

    def _display_key_info(self) -> None:
        """Отображает информацию о сгенерированных ключах."""
        if self.crypto is None:
            return
        info = self.crypto.key_info()
        b_str = ", ".join(map(str, info["private_seq"]))
        a_str = ", ".join(map(str, info["public_seq"]))
        text = (
            f"Криптосистема Σ₀ = (M*, Q, C*, E(m), D(c) | V(E(m), D(c)))\n"
            f"Алгоритм: Аддитивный рюкзак (АВКР, Merkle-Hellman)\n"
            f"{'─' * 70}\n"
            f"  Размер блока n = {info['block_size']} бит\n"
            f"{'─' * 70}\n"
            f"  ЗАКРЫТЫЙ КЛЮЧ:\n"
            f"  B = ({b_str})\n"
            f"  Σ B = {info['sum_private']}\n"
            f"  q = {info['q']}  (q > Σ B)\n"
            f"  w = {info['w']}  (gcd(w, q) = 1)\n"
            f"  w⁻¹ mod q = {info['w_inv']}\n"
            f"{'─' * 70}\n"
            f"  ОТКРЫТЫЙ КЛЮЧ:\n"
            f"  A = ({a_str})\n"
            f"  (aᵢ = w · bᵢ mod q)\n"
            f"{'─' * 70}\n"
            f"  M* = {{(m₁,...,m_n) | mᵢ ∈ {{0,1}}}}  "
            f"(все двоичные блоки длины {info['block_size']})\n"
            f"  E(m) = Σ mᵢ · aᵢ\n"
            f"  D(c) = solve_knapsack(c · w⁻¹ mod q, B)\n"
        )
        self.key_info_text.setText(text)

    def _on_encrypt_block(self) -> None:
        """Шифрование блока бит."""
        if not self._check_keys():
            return
        try:
            bits_text = self.input_bits.text().strip()
            bits = [int(x.strip()) for x in bits_text.split(",")]
            c = self.crypto.encrypt_block(bits)
            self.label_c.setText(f"c = {c}")
            self.input_c.setText(str(c))
            self._last_c = c
            terms = " + ".join(
                f"{b}·{a}" for b, a in zip(bits, self.crypto.public_seq) if b
            )
            self._log(f"E({bits}) = {terms} = {c}")
        except ValueError as ex:
            QMessageBox.warning(self, "Ошибка", str(ex))

    def _on_decrypt_block(self) -> None:
        """Дешифрование блока."""
        if not self._check_keys():
            return
        try:
            c = int(self.input_c.text().strip())
            bits = self.crypto.decrypt_block(c)
            self.label_bits.setText(f"m = {bits}")
            s_prime = (c * self.crypto.w_inv) % self.crypto.q
            self._log(
                f"D({c}): S' = {c}·{self.crypto.w_inv} mod {self.crypto.q} "
                f"= {s_prime} → m = {bits}"
            )
        except ValueError as ex:
            QMessageBox.warning(self, "Ошибка", str(ex))

    def _on_verify(self) -> None:
        """Верификация D(E(m)) == m."""
        if not self._check_keys():
            return
        try:
            bits_text = self.input_v.text().strip()
            bits = [int(x.strip()) for x in bits_text.split(",")]
            result = self.crypto.verify_block(bits)
            c = self.crypto.encrypt_block(bits)
            bits2 = self.crypto.decrypt_block(c)
            status = "ВЕРНО" if result else "ОШИБКА"
            self.label_v.setText(f"результат: {status}")
            self._log(
                f"V: m={bits} → E(m)={c} → D(E(m))={bits2} → {status}"
            )
        except ValueError as ex:
            QMessageBox.warning(self, "Ошибка", str(ex))

    def _on_encrypt_text(self) -> None:
        """Шифрование текста."""
        if not self._check_keys():
            return
        try:
            text = self.input_text.text()
            cipher = self.crypto.encrypt_text(text)
            cipher_str = ", ".join(map(str, cipher))
            self.enc_text_result.setText(cipher_str)
            self.input_cipher_text.setText(cipher_str)
            self.spin_text_len.setValue(len(text))
            self._log(
                f"Зашифрован текст '{text}' ({len(text)} символов, "
                f"{len(cipher)} блоков)"
            )
        except ValueError as ex:
            QMessageBox.warning(self, "Ошибка", str(ex))

    def _on_decrypt_text(self) -> None:
        """Дешифрование текста."""
        if not self._check_keys():
            return
        try:
            cipher_str = self.input_cipher_text.toPlainText().strip()
            cipher = [int(x.strip()) for x in cipher_str.split(",") if x.strip()]
            text_len = self.spin_text_len.value()
            text = self.crypto.decrypt_text(cipher, text_len)
            self.dec_text_result.setText(text)
            self._log(f"Расшифрован текст: '{text}'")
        except ValueError as ex:
            QMessageBox.warning(self, "Ошибка", str(ex))

    def _on_use_last_c(self) -> None:
        """Подставляет последний шифротекст в поле целевой суммы."""
        c_text = self.input_c.text().strip()
        if c_text:
            self.input_target.setText(c_text)
        else:
            QMessageBox.warning(
                self, "Ошибка",
                "Сначала зашифруйте блок на вкладке «Блок E(m)/D(c)»"
            )

    def _on_brute_force(self) -> None:
        """Попытка перебора рюкзака для открытого ключа."""
        if not self._check_keys():
            return
        try:
            target = int(self.input_target.text().strip())
            n = self.crypto.block_size

            import time
            start = time.perf_counter()
            result = brute_force_knapsack(target, self.crypto.public_seq)
            elapsed = time.perf_counter() - start

            text = f"Открытый ключ A: {self.crypto.public_seq}\n"
            text += f"Целевая сумма S = {target}\n"
            text += f"Размер задачи: n = {n} (всего 2^{n} = {2**n} подмножеств)\n\n"

            if result:
                text += (
                    f"Решение найдено за {elapsed:.4f} с:\n"
                    f"  m = {result}\n"
                    f"  Проверка: Σ mᵢ·aᵢ = "
                    f"{sum(b*a for b, a in zip(result, self.crypto.public_seq))}\n"
                )
            else:
                text += f"Решение НЕ найдено за {elapsed:.4f} с\n"

            text += (
                f"\n{'─' * 60}\n"
                f"Сложность полного перебора: O(2ⁿ)\n"
                f"При n = {n}: 2^{n} = {2**n} вариантов\n"
                f"При n = 256: 2^256 ≈ 1.16 × 10⁷⁷ вариантов\n"
                f"{'─' * 60}\n"
                f"Задача о сумме подмножеств (Subset Sum) является\n"
                f"NP-полной задачей (доказано Карпом, 1972).\n"
                f"Наилучшие известные алгоритмы:\n"
                f"  • Полный перебор: O(2ⁿ)\n"
                f"  • Meet-in-the-middle: O(2^(n/2))\n"
                f"  • Динамическое программирование: O(n·S)\n"
                f"    (псевдополиномиальный, зависит от величины S)\n"
            )

            self.bf_result.setText(text)
            self._log(
                f"Перебор: S={target}, n={n}: "
                f"{'найдено' if result else 'не найдено'} за {elapsed:.4f} с"
            )
        except ValueError:
            QMessageBox.warning(self, "Ошибка", "Введите корректное целое число")

    # ---- Утилиты -------------------------------------------------------------

    def _check_keys(self) -> bool:
        if self.crypto is None:
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
    if "--cli" in sys.argv:
        print("=" * 65)
        print("  Алгоритм АВКР (Меркла-Хеллмана) — модель Осипяна")
        print("  Σ₀ = (M*, Q, C*, E(m), D(c) | V(E(m), D(c)))")
        print("=" * 65)

        # Генерация ключей с фиксированными параметрами для воспроизводимости
        private_seq = [2, 5, 11, 23, 47, 95, 191, 383]
        q = 881  # простое, > sum(private_seq) = 757
        w = 588  # gcd(588, 881) = 1

        crypto = KnapsackCryptoSystem(
            block_size=8, private_seq=private_seq, q=q, w=w
        )
        info = crypto.key_info()

        print(f"\n  Закрытый ключ:")
        print(f"    B = {info['private_seq']}")
        print(f"    Σ B = {info['sum_private']}")
        print(f"    q = {info['q']}  (q > Σ B = {info['sum_private']})")
        print(f"    w = {info['w']}  (gcd(w, q) = 1)")
        print(f"    w⁻¹ mod q = {info['w_inv']}")
        print(f"\n  Открытый ключ:")
        print(f"    A = {info['public_seq']}")

        # Шифрование блока
        m_bits = [1, 0, 1, 1, 0, 0, 1, 0]
        print(f"\n{'─' * 65}")
        print(f"  E(m): Шифрование блока")
        print(f"{'─' * 65}")
        c = crypto.encrypt_block(m_bits)
        terms = " + ".join(
            f"{b}·{a}" for b, a in zip(m_bits, crypto.public_seq) if b
        )
        print(f"  m = {m_bits}")
        print(f"  c = Σ mᵢ·aᵢ = {terms} = {c}")

        # Дешифрование
        print(f"\n{'─' * 65}")
        print(f"  D(c): Дешифрование")
        print(f"{'─' * 65}")
        s_prime = (c * crypto.w_inv) % crypto.q
        decrypted = crypto.decrypt_block(c)
        print(f"  c = {c}")
        print(f"  S' = c · w⁻¹ mod q = {c} · {crypto.w_inv} mod {crypto.q} = {s_prime}")
        print(f"  Решаем лёгкий рюкзак: S'={s_prime}, B={crypto.private_seq}")
        print(f"  m = {decrypted}")

        # Верификация
        print(f"\n{'─' * 65}")
        print(f"  V(E(m), D(c)): Верификация")
        print(f"{'─' * 65}")
        print(f"  D(E({m_bits})) == {m_bits} ? {crypto.verify_block(m_bits)}")

        # Текстовое сообщение
        print(f"\n{'─' * 65}")
        print(f"  Шифрование текста (поблочно)")
        print(f"{'─' * 65}")
        text = "Hello"
        cipher = crypto.encrypt_text(text)
        print(f"  Текст: '{text}'")
        print(f"  Шифр:  {cipher}")
        decrypted_text = crypto.decrypt_text(cipher, len(text))
        print(f"  Расшифровано: '{decrypted_text}'")

        # NP-сложность
        print(f"\n{'─' * 65}")
        print(f"  NP-сложная задача: рюкзак для открытого ключа")
        print(f"{'─' * 65}")
        import time
        start = time.perf_counter()
        bf_result = brute_force_knapsack(c, crypto.public_seq)
        elapsed = time.perf_counter() - start
        if bf_result:
            print(f"  Перебор: найдено за {elapsed:.4f} с: {bf_result}")
        print(f"  При n=8 перебор тривиален (2⁸ = 256 вариантов)")
        print(f"  Криптостойкость обеспечивается при n ≥ 256")

    else:
        app = QApplication(sys.argv)
        window = KnapsackMainWindow()
        window.show()
        sys.exit(app.exec())
