"""
Алгоритм классического мультипликативного рюкзака (МВКР).

Оформлено в соответствии с моделью алфавитной криптосистемы
В.О. Осипяна: Sigma_D = (M*, Q, C*, E(m), D(c) | V(E(m), D(c))).

NP-сложная задача в основе МВКР — задача о произведении подмножеств
(Subset Product Problem): дан набор положительных целых чисел
{a1, a2, ..., an} и целое число P, требуется определить, существует ли
подмножество, произведение элементов которого равно P.

Отличие от АВКР (аддитивного рюкзака):
  АВКР: E(m) = SUM(mi * ai),  трюк — модулярное умножение на w
  МВКР: E(m) = PROD(ai^mi),   трюк — модулярное возведение в степень w

Литература: Осипян В.О. Разработка методов построения систем передачи
            и защиты информации. Монография. КубГУ, 2004.
"""

from __future__ import annotations

import random
import sys
from dataclasses import dataclass, field
from math import gcd

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

def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    """Расширенный алгоритм Евклида.

    Возвращает (g, x, y) такие, что a*x + b*y = g = gcd(a, b).
    В МВКР используется для нахождения w^{-1} mod (q-1),
    необходимого при дешифровании.
    """
    if a == 0:
        return b, 0, 1
    g, x, y = extended_gcd(b % a, a)
    return g, y - (b // a) * x, x


def mod_inverse(a: int, m: int) -> int:
    """Вычисляет мультипликативный обратный элемент: a^{-1} mod m.

    В МВКР: находим w^{-1} mod (q-1), чтобы при дешифровании
    вычислить P = c^{w^{-1}} mod q, возвращая произведение
    из «лёгкого» рюкзака.
    """
    g, x, _ = extended_gcd(a % m, m)
    if g != 1:
        raise ValueError(
            f"Обратный элемент не существует: gcd({a}, {m}) = {g} != 1"
        )
    return x % m


def is_prime_miller_rabin(n: int, k: int = 20) -> bool:
    """Тест Миллера-Рабина на простоту (вероятностный).

    Для МВКР нужны большие простые числа (q > произведению всех
    элементов закрытого ключа), поэтому простая проверка делителями
    слишком медленна. Миллер-Рабин работает за O(k * log^2(n)).
    """
    if n < 2:
        return False
    if n < 4:
        return True
    if n % 2 == 0:
        return False

    # Представляем n - 1 = 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    # k раундов теста
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime_above(low: int) -> int:
    """Генерирует ближайшее простое число, большее low.

    В МВКР q должно быть > произведения всех элементов B,
    чтобы при дешифровании произведение не редуцировалось по модулю.
    """
    candidate = low + 1 if low % 2 == 0 else low + 2
    if candidate % 2 == 0:
        candidate += 1
    while not is_prime_miller_rabin(candidate):
        candidate += 2
    return candidate


def generate_n_primes(n: int, randomize: bool = False) -> list[int]:
    """Генерирует n различных простых чисел.

    В «лёгком» мультипликативном рюкзаке закрытый ключ — набор
    различных простых чисел. Произведение любого подмножества
    однозначно определяет это подмножество (основная теорема арифметики).

    Если randomize=True, выбираются случайные простые для большей
    криптостойкости; иначе — первые n простых для наглядности.
    """
    if randomize:
        # Случайные простые в диапазоне [2, 10*n + 50]
        primes: list[int] = []
        candidates = list(range(2, max(10 * n + 50, 100)))
        random.shuffle(candidates)
        for c in candidates:
            if is_prime_miller_rabin(c):
                primes.append(c)
                if len(primes) == n:
                    break
        primes.sort()
        return primes

    # Первые n простых чисел (детерминированно)
    primes = []
    candidate = 2
    while len(primes) < n:
        if is_prime_miller_rabin(candidate):
            primes.append(candidate)
        candidate += 1
    return primes


# ---------------------------------------------------------------------------
#  Решение «лёгкого» мультипликативного рюкзака
# ---------------------------------------------------------------------------

def solve_coprime_product_knapsack(
    target: int, primes: list[int]
) -> list[int] | None:
    """Решает задачу о произведении для набора различных простых чисел.

    Для набора различных простых (p1, p2, ..., pn) и целевого P
    задача тривиальна: проверяем делимость P на каждое pᵢ.

    Это аналог жадного алгоритма для сверхвозрастающей
    последовательности в АВКР. Сложность — O(n), в отличие
    от O(2^n) для общего случая.

    Корректность гарантируется основной теоремой арифметики:
    разложение на простые множители единственно.

    Возвращает список бит [m1, m2, ..., mn] или None.
    """
    n = len(primes)
    bits = [0] * n
    remainder = target

    for i in range(n):
        if remainder % primes[i] == 0:
            bits[i] = 1
            remainder //= primes[i]

    # Если remainder == 1, все множители найдены
    return bits if remainder == 1 else None


# ---------------------------------------------------------------------------
#  Класс-криптосистема МВКР (мультипликативный рюкзак)
# ---------------------------------------------------------------------------

@dataclass
class MultiplicativeKnapsackCryptoSystem:
    """Реализация криптосистемы Sigma_D = (M*, Q, C*, E(m), D(c) | V(E(m), D(c)))
    на основе алгоритма мультипликативного рюкзака (МВКР).

    Алгоритм МВКР основан на NP-сложной задаче о произведении подмножеств:
    дана последовательность (a1, a2, ..., an) и число P, найти подмножество
    {i1, i2, ...}, что PROD(a_{ij}) = P.

    Схема МВКР:
    -----------
    Закрытый ключ: различные простые числа B = (p1, ..., pn),
                   модуль q (простое, q > PROD(pi)),
                   показатель w (gcd(w, q-1) = 1).
    Открытый ключ: последовательность A = (a1, ..., an),
                   где ai = pi^w mod q.

    E(m): c = PROD(ai^mi) mod q  (произведение выбранных элементов).
    D(c): P = c^{w^{-1}} mod q, затем факторизация P по B.

    В терминологии Осипяна
    ----------------------
    M*   — множество всех двоичных блоков: m = (m1, ..., mn), mi in {0,1}.
    Q    — алфавит {0, 1}.
    C*   — множество шифротекстов (элементы Z_q*).
    E(m) — алгоритм шифрования: c = PROD(ai^mi) mod q.
    D(c) — алгоритм дешифрования: P = c^{w^{-1}} mod q -> факторизация по B.
    V(E(m), D(c)) — верификация: D(E(m)) = m для любого m in M*.

    Атрибуты
    --------
    block_size : int
        Длина блока (количество бит в одном блоке сообщения).
    private_seq : list[int]
        Различные простые числа B (закрытый ключ).
    q : int
        Модуль (простое, q > PROD(B)).
    w : int
        Секретный показатель (gcd(w, q-1) = 1).
    public_seq : list[int]
        Открытая последовательность A: ai = pi^w mod q.
    w_inv : int
        Обратный показатель: w^{-1} mod (q-1).
    """

    block_size: int
    private_seq: list[int] = field(default_factory=list)
    q: int = 0
    w: int = 0
    public_seq: list[int] = field(init=False, default_factory=list)
    w_inv: int = field(init=False, default=0)

    def __post_init__(self) -> None:
        """Генерация ключей МВКР."""
        if self.block_size < 1:
            raise ValueError("Размер блока должен быть >= 1")

        # Если закрытая последовательность не задана — генерируем
        if not self.private_seq:
            self.private_seq = generate_n_primes(self.block_size)
        else:
            if len(self.private_seq) != self.block_size:
                raise ValueError(
                    f"Длина закрытой последовательности ({len(self.private_seq)}) "
                    f"не совпадает с размером блока ({self.block_size})"
                )
            # Проверяем попарную взаимную простоту
            self._validate_coprime(self.private_seq)

        # Произведение всех элементов закрытого ключа
        product_b = 1
        for b in self.private_seq:
            product_b *= b

        # Модуль q — простое число, q > PROD(B)
        # Это гарантирует, что при дешифровании произведение
        # не будет редуцировано по модулю
        if self.q == 0:
            self.q = generate_prime_above(product_b)
        else:
            if self.q <= product_b:
                raise ValueError(
                    f"Модуль q = {self.q} должен быть > произведения "
                    f"закрытой последовательности = {product_b}"
                )
            if not is_prime_miller_rabin(self.q):
                raise ValueError(f"q = {self.q} не является простым числом")

        # Секретный показатель w: gcd(w, q-1) = 1
        # Это необходимо для существования w^{-1} mod (q-1),
        # который используется в дешифровании
        if self.w == 0:
            self.w = self._choose_w()
        else:
            if gcd(self.w, self.q - 1) != 1:
                raise ValueError(
                    f"gcd(w={self.w}, q-1={self.q - 1}) != 1"
                )

        # w^{-1} mod (q-1) — ключевой элемент дешифрования
        # По малой теореме Ферма: a^{q-1} = 1 (mod q) для a != 0 (mod q)
        # Поэтому a^{w * w^{-1}} = a^{1 + k(q-1)} = a (mod q)
        self.w_inv = mod_inverse(self.w, self.q - 1)

        # Открытый ключ: ai = pi^w mod q
        # Возведение в степень «маскирует» простую структуру B,
        # превращая «лёгкий» мультипликативный рюкзак в «трудный»
        self.public_seq = [pow(b, self.w, self.q) for b in self.private_seq]

    def _choose_w(self) -> int:
        """Выбирает секретный показатель w: 2 <= w < q-1, gcd(w, q-1) = 1.

        w должен быть взаимно прост с q-1 (не с q!), потому что
        обратный вычисляется по модулю q-1 (через малую теорему Ферма).
        """
        while True:
            w = random.randint(2, self.q - 2)
            if gcd(w, self.q - 1) == 1:
                return w

    @staticmethod
    def _validate_coprime(seq: list[int]) -> None:
        """Проверяет, что все элементы попарно взаимно просты."""
        for i in range(len(seq)):
            if seq[i] <= 0:
                raise ValueError(
                    f"Элемент [{i}] = {seq[i]} должен быть положительным"
                )
            for j in range(i + 1, len(seq)):
                if gcd(seq[i], seq[j]) != 1:
                    raise ValueError(
                        f"Элементы b[{i}]={seq[i]} и b[{j}]={seq[j]} "
                        f"не взаимно просты"
                    )

    # ---- E(m): шифрование ---------------------------------------------------

    def encrypt_block(self, bits: list[int]) -> int:
        """Шифрует один блок: c = PROD(ai^mi) mod q.

        Это функция E(m) — прямое преобразование.
        Каждый бит mi выбирает (mi=1) или пропускает (mi=0)
        соответствующий элемент открытого ключа ai.
        Результат — произведение выбранных элементов по модулю q.

        При пустом сообщении (все mi=0) c = 1 (пустое произведение).

        Параметры
        ---------
        bits : list[int]
            Блок сообщения — список из 0 и 1 длины block_size.

        Возвращает
        ----------
        int
            Шифротекст c = PROD(ai^mi) mod q.
        """
        self._validate_bits(bits)
        # Формула: c = PROD_{i=1}^{n} ai^mi mod q
        c = 1
        for b, a in zip(bits, self.public_seq):
            if b:
                c = (c * a) % self.q
        return c

    # ---- D(c): дешифрование -------------------------------------------------

    def decrypt_block(self, c: int) -> list[int]:
        """Дешифрует шифротекст c обратно в блок бит.

        Это функция D(c) — обратное преобразование.

        Шаг 1: вычисляем P = c^{w^{-1}} mod q.
                Это «снимает маскировку»:
                P = (PROD ai^mi)^{w^{-1}}
                  = (PROD pi^{w*mi})^{w^{-1}}
                  = PROD pi^{mi * w * w^{-1}}
                  = PROD pi^mi  (mod q)
                Поскольку q > PROD(pi), результат точен (без редукции).

        Шаг 2: факторизация P по известным простым B.
                Это O(n) — «лёгкий» мультипликативный рюкзак.

        Параметры
        ---------
        c : int
            Шифротекст (неотрицательное целое число).

        Возвращает
        ----------
        list[int]
            Расшифрованный блок бит [m1, m2, ..., mn].
        """
        if not isinstance(c, int) or c < 0:
            raise ValueError(
                f"Шифротекст должен быть неотрицательным целым, получено {c}"
            )

        # Шаг 1: P = c^{w^{-1}} mod q
        p = pow(c, self.w_inv, self.q)

        # Шаг 2: факторизация по закрытому ключу (различные простые)
        bits = solve_coprime_product_knapsack(p, self.private_seq)

        if bits is None:
            raise ValueError(
                f"Не удалось расшифровать шифротекст c = {c} "
                f"(P = {p} не раскладывается по закрытой последовательности)"
            )

        return bits

    # ---- Шифрование/дешифрование текстовых сообщений -------------------------

    def encrypt_text(self, text: str) -> list[int]:
        """Шифрует текстовую строку блоками по block_size бит.

        Каждый символ (8 бит) преобразуется в двоичное представление,
        символы объединяются в поток, который разбивается на блоки.
        Каждый блок шифруется отдельно.

        Параметры
        ---------
        text : str
            Текст для шифрования (ASCII, коды 0-255).

        Возвращает
        ----------
        list[int]
            Список шифротекстов (по одному на блок).
        """
        if not text:
            raise ValueError("Текст не может быть пустым")

        # Преобразуем текст в поток бит (8 бит на символ)
        bit_stream: list[int] = []
        for char in text:
            code = ord(char)
            if code > 255:
                raise ValueError(
                    f"Символ '{char}' (код {code}) выходит за пределы ASCII. "
                    f"Используйте латиницу и базовые символы."
                )
            for bit_pos in range(7, -1, -1):
                bit_stream.append((code >> bit_pos) & 1)

        # Дополняем до кратности block_size нулями
        remainder = len(bit_stream) % self.block_size
        if remainder != 0:
            bit_stream.extend([0] * (self.block_size - remainder))

        # Шифруем по блокам
        ciphertext: list[int] = []
        for i in range(0, len(bit_stream), self.block_size):
            block = bit_stream[i : i + self.block_size]
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
            byte_bits = bit_stream[i : i + 8]
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
        product_b = 1
        for b in self.private_seq:
            product_b *= b
        return {
            "block_size": self.block_size,
            "private_seq": self.private_seq,
            "q": self.q,
            "w": self.w,
            "w_inv": self.w_inv,
            "public_seq": self.public_seq,
            "product_private": product_b,
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
            f"MultiplicativeKnapsackCryptoSystem(block_size={self.block_size}, "
            f"q={self.q}, w={self.w})"
        )


# ---------------------------------------------------------------------------
#  Демонстрация NP-сложности: перебор для мультипликативного рюкзака
# ---------------------------------------------------------------------------

def brute_force_product_knapsack(
    target: int,
    sequence: list[int],
    modulus: int,
    limit: int = 2**20,
) -> list[int] | None:
    """Попытка решения мультипликативного рюкзака полным перебором.

    Перебирает все 2^n подмножеств (до limit), вычисляя произведение
    элементов каждого подмножества по модулю modulus.
    Демонстрирует экспоненциальную сложность задачи.
    """
    n = len(sequence)
    total_subsets = min(2**n, limit)

    for mask in range(total_subsets):
        p = 1
        for i in range(n):
            if mask & (1 << i):
                p = (p * sequence[i]) % modulus
        if p == target:
            return [(mask >> i) & 1 for i in range(n)]

    return None


# ---------------------------------------------------------------------------
#  GUI на PyQt6
# ---------------------------------------------------------------------------

class MKnapsackMainWindow(QMainWindow):
    """Главное окно приложения криптосистемы МВКР."""

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(
            "МВКР -- Sigma_D = (M*, Q, C*, E(m), D(c) | V(E(m), D(c)))"
        )
        self.setMinimumSize(1050, 780)

        self.crypto: MultiplicativeKnapsackCryptoSystem | None = None

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
        self.spin_block.setRange(4, 32)
        self.spin_block.setValue(8)
        row1.addWidget(self.spin_block)
        params_layout.addLayout(row1)

        # Ручной ввод закрытой последовательности
        row2 = QHBoxLayout()
        row2.addWidget(QLabel("Простые B (через запятую):"))
        self.input_private = QLineEdit()
        self.input_private.setPlaceholderText(
            "Оставьте пустым для автогенерации, "
            "например: 2, 3, 5, 7, 11, 13, 17, 19"
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
        enc_group = QGroupBox(
            "E(m): Шифрование блока -- c = PROD(ai^mi) mod q"
        )
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
        dec_group = QGroupBox(
            "D(c): Дешифрование -- P = c^{w^{-1}} mod q -> факторизация по B"
        )
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
            "NP-сложная задача о произведении подмножеств (Subset Product Problem):\n"
            "Дана последовательность (a1, a2, ..., an) и число P.\n"
            "Найти подмножество {i1, i2, ...}, что PROD(a_{ij}) = P.\n\n"
            "Криптостойкость МВКР:\n"
            "  * Задача о произведении для общей последовательности -- NP-полна.\n"
            "  * Атакующий видит открытый ключ A = (pi^w mod q) -- без w\n"
            "    восстановить простые числа невозможно (задача дискретного логарифма).\n"
            "  * Без знания w перебор требует O(2^n) операций.\n\n"
            "Примечание: безопасность МВКР также связана с задачей дискретного\n"
            "логарифма (DLP). Знание w позволяет восстановить B из A.\n"
            "Для реального использования рекомендуются более современные схемы."
        )
        info_label.setWordWrap(True)
        layout.addWidget(info_label)

        # Демонстрация перебора
        bf_group = QGroupBox(
            "Перебор: попытка решить рюкзак для открытого ключа"
        )
        bf_layout = QVBoxLayout(bf_group)

        row = QHBoxLayout()
        row.addWidget(QLabel("Целевое произведение P ="))
        self.input_target = QLineEdit()
        self.input_target.setPlaceholderText("Подставить из шифротекста")
        row.addWidget(self.input_target)
        btn_use_c = QPushButton("Взять последний c")
        btn_use_c.clicked.connect(self._on_use_last_c)
        row.addWidget(btn_use_c)
        btn_bf = QPushButton("Перебор (до 2^20)")
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
            self.crypto = MultiplicativeKnapsackCryptoSystem(
                block_size=block_size
            )
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
            private_seq: list[int] = []
            if priv_text:
                private_seq = [int(x.strip()) for x in priv_text.split(",")]
                block_size = len(private_seq)
                self.spin_block.setValue(block_size)

            # q и w
            q_text = self.input_q.text().strip()
            q = int(q_text) if q_text else 0
            w_text = self.input_w.text().strip()
            w = int(w_text) if w_text else 0

            self.crypto = MultiplicativeKnapsackCryptoSystem(
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
            f"Криптосистема Sigma_D = (M*, Q, C*, E(m), D(c) | V(E(m), D(c)))\n"
            f"Алгоритм: Мультипликативный рюкзак (МВКР)\n"
            f"{'─' * 70}\n"
            f"  Размер блока n = {info['block_size']} бит\n"
            f"{'─' * 70}\n"
            f"  ЗАКРЫТЫЙ КЛЮЧ:\n"
            f"  B = ({b_str})\n"
            f"  PROD(B) = {info['product_private']}\n"
            f"  q = {info['q']}  (простое, q > PROD(B))\n"
            f"  w = {info['w']}  (gcd(w, q-1) = 1)\n"
            f"  w^{{-1}} mod (q-1) = {info['w_inv']}\n"
            f"{'─' * 70}\n"
            f"  ОТКРЫТЫЙ КЛЮЧ:\n"
            f"  A = ({a_str})\n"
            f"  (ai = pi^w mod q)\n"
            f"{'─' * 70}\n"
            f"  M* = {{(m1,...,mn) | mi in {{0,1}}}}  "
            f"(все двоичные блоки длины {info['block_size']})\n"
            f"  E(m) = PROD(ai^mi) mod q\n"
            f"  D(c) = factor(c^{{w^{{-1}}}} mod q, B)\n"
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
            terms = " * ".join(
                f"{a}" for b, a in zip(bits, self.crypto.public_seq) if b
            )
            self._log(f"E({bits}) = {terms} mod {self.crypto.q} = {c}")
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
            p = pow(c, self.crypto.w_inv, self.crypto.q)
            self._log(
                f"D({c}): P = {c}^{{{self.crypto.w_inv}}} mod {self.crypto.q} "
                f"= {p} -> m = {bits}"
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
                f"V: m={bits} -> E(m)={c} -> D(E(m))={bits2} -> {status}"
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
            cipher = [
                int(x.strip()) for x in cipher_str.split(",") if x.strip()
            ]
            text_len = self.spin_text_len.value()
            text = self.crypto.decrypt_text(cipher, text_len)
            self.dec_text_result.setText(text)
            self._log(f"Расшифрован текст: '{text}'")
        except ValueError as ex:
            QMessageBox.warning(self, "Ошибка", str(ex))

    def _on_use_last_c(self) -> None:
        """Подставляет последний шифротекст в поле целевого произведения."""
        c_text = self.input_c.text().strip()
        if c_text:
            self.input_target.setText(c_text)
        else:
            QMessageBox.warning(
                self,
                "Ошибка",
                "Сначала зашифруйте блок на вкладке «Блок E(m)/D(c)»",
            )

    def _on_brute_force(self) -> None:
        """Попытка перебора мультипликативного рюкзака для открытого ключа."""
        if not self._check_keys():
            return
        try:
            target = int(self.input_target.text().strip())
            n = self.crypto.block_size

            import time

            start = time.perf_counter()
            result = brute_force_product_knapsack(
                target, self.crypto.public_seq, self.crypto.q
            )
            elapsed = time.perf_counter() - start

            text = f"Открытый ключ A: {self.crypto.public_seq}\n"
            text += f"Модуль q = {self.crypto.q}\n"
            text += f"Целевое произведение P = {target}\n"
            text += (
                f"Размер задачи: n = {n} "
                f"(всего 2^{n} = {2**n} подмножеств)\n\n"
            )

            if result:
                # Проверка
                check = 1
                for b, a in zip(result, self.crypto.public_seq):
                    if b:
                        check = (check * a) % self.crypto.q
                text += (
                    f"Решение найдено за {elapsed:.4f} с:\n"
                    f"  m = {result}\n"
                    f"  Проверка: PROD(ai^mi) mod q = {check}\n"
                )
            else:
                text += f"Решение НЕ найдено за {elapsed:.4f} с\n"

            text += (
                f"\n{'─' * 60}\n"
                f"Сложность полного перебора: O(2^n)\n"
                f"При n = {n}: 2^{n} = {2**n} вариантов\n"
                f"При n = 256: 2^256 ~ 1.16 x 10^77 вариантов\n"
                f"{'─' * 60}\n"
                f"Задача о произведении подмножеств (Subset Product)\n"
                f"является NP-полной задачей.\n"
                f"Безопасность МВКР также связана с задачей\n"
                f"дискретного логарифма (DLP).\n"
            )

            self.bf_result.setText(text)
            self._log(
                f"Перебор: P={target}, n={n}: "
                f"{'найдено' if result else 'не найдено'} за {elapsed:.4f} с"
            )
        except ValueError:
            QMessageBox.warning(
                self, "Ошибка", "Введите корректное целое число"
            )

    # ---- Утилиты -------------------------------------------------------------

    def _check_keys(self) -> bool:
        if self.crypto is None:
            QMessageBox.warning(
                self,
                "Ошибка",
                "Сначала сгенерируйте ключи (вкладка «Генерация ключей»)",
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
        print("  Алгоритм МВКР (мультипликативный рюкзак) -- модель Осипяна")
        print("  Sigma_D = (M*, Q, C*, E(m), D(c) | V(E(m), D(c)))")
        print("=" * 65)

        # Генерация ключей с первыми 8 простыми числами
        private_seq = [2, 3, 5, 7, 11, 13, 17, 19]
        product_b = 1
        for p in private_seq:
            product_b *= p
        print(f"\n  Закрытый ключ (различные простые):")
        print(f"    B = {private_seq}")
        print(f"    PROD(B) = {product_b}")

        crypto = MultiplicativeKnapsackCryptoSystem(
            block_size=8, private_seq=private_seq
        )
        info = crypto.key_info()

        print(f"    q = {info['q']}  (простое, q > PROD(B))")
        print(f"    w = {info['w']}  (gcd(w, q-1) = 1)")
        print(f"    w^{{-1}} mod (q-1) = {info['w_inv']}")
        print(f"\n  Открытый ключ (ai = pi^w mod q):")
        print(f"    A = {info['public_seq']}")

        # Шифрование блока
        m_bits = [1, 0, 1, 1, 0, 0, 1, 0]
        print(f"\n{'─' * 65}")
        print(f"  E(m): Шифрование блока")
        print(f"{'─' * 65}")
        c = crypto.encrypt_block(m_bits)
        selected = [
            f"{a}" for b, a in zip(m_bits, crypto.public_seq) if b
        ]
        print(f"  m = {m_bits}")
        print(f"  c = {' * '.join(selected)} mod {crypto.q} = {c}")

        # Дешифрование
        print(f"\n{'─' * 65}")
        print(f"  D(c): Дешифрование")
        print(f"{'─' * 65}")
        p_val = pow(c, crypto.w_inv, crypto.q)
        decrypted = crypto.decrypt_block(c)
        print(f"  c = {c}")
        print(
            f"  P = c^{{w^{{-1}}}} mod q = {c}^{{{crypto.w_inv}}} "
            f"mod {crypto.q} = {p_val}"
        )
        selected_primes = [
            str(pr)
            for b, pr in zip(decrypted, crypto.private_seq) if b
        ]
        print(
            f"  Факторизация P = {p_val}: "
            f"{' * '.join(selected_primes)} = {p_val}"
        )
        print(f"  m = {decrypted}")

        # Верификация
        print(f"\n{'─' * 65}")
        print(f"  V(E(m), D(c)): Верификация")
        print(f"{'─' * 65}")
        print(
            f"  D(E({m_bits})) == {m_bits} ? "
            f"{crypto.verify_block(m_bits)}"
        )

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
        print(f"  NP-сложная задача: мультипликативный рюкзак")
        print(f"{'─' * 65}")
        import time

        start = time.perf_counter()
        bf_result = brute_force_product_knapsack(
            c, crypto.public_seq, crypto.q
        )
        elapsed = time.perf_counter() - start
        if bf_result:
            print(f"  Перебор: найдено за {elapsed:.4f} с: {bf_result}")
        print(f"  При n=8 перебор тривиален (2^8 = 256 вариантов)")
        print(f"  Криптостойкость обеспечивается при n >= 256")

    else:
        app = QApplication(sys.argv)
        window = MKnapsackMainWindow()
        window.show()
        sys.exit(app.exec())
