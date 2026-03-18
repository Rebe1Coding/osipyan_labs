"""
Код Хэмминга C(n, k) — передача данных по каналу связи
с обнаружением и исправлением одной симметричной ошибки.

Оформлено в соответствии с моделью алфавитной криптосистемы
В.О. Осипяна: Σ₀ = (M*, Q, C*, E(m), D(c) | V(E(m), D(c))).

Автор алгоритма: В.О. Осипян
"""

from __future__ import annotations

import math
from dataclasses import dataclass


# ---------------------------------------------------------------------------
#  Вспомогательные функции
# ---------------------------------------------------------------------------

def _calc_parity_bits(k: int) -> int:
    """Вычисляет минимальное число проверочных бит r для k информационных.

    Условие Хэмминга: 2^r >= k + r + 1  (т.е. n = k + r, n+1 <= 2^r).
    """
    r = 0
    while (1 << r) < k + r + 1:
        r += 1
    return r


def _is_power_of_two(x: int) -> bool:
    """Проверяет, является ли x степенью двойки (позиция проверочного бита)."""
    return x > 0 and (x & (x - 1)) == 0


# ---------------------------------------------------------------------------
#  Класс-криптосистема Хэмминга
# ---------------------------------------------------------------------------

@dataclass
class HammingCodeSystem:
    """Реализация криптосистемы Σ₀ = (M*, Q, C*, E(m), D(c) | V(E(m), D(c)))
    на основе кода Хэмминга C(n, k).

    Атрибуты
    ---------
    k : int
        Число информационных бит (размерность кода).
    r : int
        Число проверочных (контрольных) бит.
    n : int
        Длина кодового слова (n = k + r).

    В терминологии Осипяна
    ----------------------
    M*  — множество всех сообщений (двоичных строк длины k).
    Q   — множество числовых эквивалентов элементарных сообщений {0, 1}.
    C*  — множество шифротекстов (кодовых слов длины n).
    E(m) — алгоритм кодирования (шифрования): m -> c.
    D(c) — алгоритм декодирования (дешифрования): c -> m.
    V(E(m), D(c)) — верификация: D(E(m)) == m для любого m ∈ M*.
    """

    k: int  # число информационных бит
    r: int = 0  # число проверочных бит (вычисляется автоматически)
    n: int = 0  # длина кодового слова

    def __post_init__(self) -> None:
        if self.k < 1:
            raise ValueError(f"k должно быть >= 1, получено {self.k}")
        self.r = _calc_parity_bits(self.k)
        self.n = self.k + self.r

    # ---- E(m): кодирование (шифрование) ---------------------------------

    def encode(self, message: list[int]) -> list[int]:
        """Кодирует информационное слово m длины k в кодовое слово c длины n.

        Это функция E(m) криптосистемы — прямое преобразование.

        Параметры
        ---------
        message : list[int]
            Двоичный вектор длины k (элементы 0 или 1).

        Возвращает
        ----------
        list[int]
            Кодовое слово (шифротекст) длины n.
        """
        self._validate_message(message)

        # Создаём массив длины n+1 (индексация с 1, как в теории Хэмминга)
        codeword = [0] * (self.n + 1)  # codeword[0] не используется

        # Шаг 1: расставляем информационные биты на НЕ-степенные позиции
        j = 0  # индекс по message
        for i in range(1, self.n + 1):
            if not _is_power_of_two(i):
                codeword[i] = message[j]
                j += 1

        # Шаг 2: вычисляем каждый проверочный бит (позиции 2^0, 2^1, …, 2^(r-1))
        # Проверочный бит p на позиции 2^j покрывает все позиции i,
        # у которых j-й бит в двоичном представлении i равен 1.
        for j in range(self.r):
            parity_pos = 1 << j  # позиция проверочного бита: 2^j
            parity = 0
            for i in range(1, self.n + 1):
                if i & parity_pos and i != parity_pos:
                    parity ^= codeword[i]
            codeword[parity_pos] = parity

        return codeword[1:]  # возвращаем с индекса 1 (убираем нулевой)

    # ---- D(c): декодирование (дешифрование) ------------------------------

    def decode(self, received: list[int]) -> tuple[list[int], int]:
        """Декодирует принятое слово c длины n, исправляя одиночную ошибку.

        Это функция D(c) криптосистемы — обратное преобразование.

        Параметры
        ---------
        received : list[int]
            Принятый двоичный вектор длины n (возможно, с одной ошибкой).

        Возвращает
        ----------
        tuple[list[int], int]
            (decoded_message, error_position)
            decoded_message — восстановленное сообщение длины k.
            error_position  — позиция исправленной ошибки (0 = ошибок нет).
        """
        self._validate_codeword(received)

        # Индексация с 1
        cw = [0] + list(received)

        # Шаг 1: вычисляем синдром S = (s_{r-1}, …, s_1, s_0)
        # s_j = XOR всех cw[i], где j-й бит позиции i равен 1
        syndrome = 0
        for j in range(self.r):
            parity_pos = 1 << j
            s_j = 0
            for i in range(1, self.n + 1):
                if i & parity_pos:
                    s_j ^= cw[i]
            if s_j:
                syndrome |= parity_pos

        # Шаг 2: если синдром != 0, исправляем бит на позиции syndrome
        error_position = syndrome
        if error_position != 0:
            if error_position > self.n:
                raise ValueError(
                    f"Синдром {error_position} выходит за пределы "
                    f"кодового слова длины {self.n}. "
                    "Возможно, произошло более одной ошибки."
                )
            cw[error_position] ^= 1  # инвертируем ошибочный бит

        # Шаг 3: извлекаем информационные биты (НЕ-степенные позиции)
        decoded = []
        for i in range(1, self.n + 1):
            if not _is_power_of_two(i):
                decoded.append(cw[i])

        return decoded, error_position

    # ---- V(E(m), D(c)): верификация --------------------------------------

    def verify(self, message: list[int]) -> bool:
        """Проверяет свойство криптосистемы: D(E(m)) == m для данного m.

        Это функция V(E(m), D(c)) — верификация корректности.
        """
        self._validate_message(message)
        encoded = self.encode(message)
        decoded, _ = self.decode(encoded)
        return decoded == message

    # ---- Вспомогательные методы ------------------------------------------

    def _validate_message(self, message: list[int]) -> None:
        if len(message) != self.k:
            raise ValueError(
                f"Длина сообщения должна быть {self.k}, получено {len(message)}"
            )
        if not all(b in (0, 1) for b in message):
            raise ValueError("Сообщение должно содержать только 0 и 1")

    def _validate_codeword(self, codeword: list[int]) -> None:
        if len(codeword) != self.n:
            raise ValueError(
                f"Длина кодового слова должна быть {self.n}, "
                f"получено {len(codeword)}"
            )
        if not all(b in (0, 1) for b in codeword):
            raise ValueError("Кодовое слово должно содержать только 0 и 1")

    def __repr__(self) -> str:
        return (
            f"HammingCodeSystem(C({self.n},{self.k}), "
            f"r={self.r}, "
            f"исправляет 1 ошибку)"
        )


# ---------------------------------------------------------------------------
#  Демонстрация
# ---------------------------------------------------------------------------

def _bits_to_str(bits: list[int]) -> str:
    """Превращает список бит в строку для удобного вывода."""
    return "".join(map(str, bits))


if __name__ == "__main__":
    # --- Пример 1: Хэмминг C(7, 4) ---
    print("=" * 60)
    print("  Код Хэмминга — модель криптосистемы Осипяна")
    print("  Σ₀ = (M*, Q, C*, E(m), D(c) | V(E(m), D(c)))")
    print("=" * 60)

    k = 4
    hamming = HammingCodeSystem(k=k)
    print(f"\nСистема: {hamming}")
    print(f"  M* — двоичные строки длины {hamming.k}")
    print(f"  Q  = {{0, 1}}")
    print(f"  C* — кодовые слова длины {hamming.n}")

    # Исходное сообщение
    m = [1, 0, 1, 1]
    print(f"\n--- Кодирование E(m) ---")
    print(f"  Сообщение m  = {_bits_to_str(m)}")

    c = hamming.encode(m)
    print(f"  Кодовое слово c = E(m) = {_bits_to_str(c)}")

    # Декодирование без ошибок
    print(f"\n--- Декодирование D(c) без ошибок ---")
    decoded, err_pos = hamming.decode(c)
    print(f"  Декодировано D(c) = {_bits_to_str(decoded)}")
    print(f"  Позиция ошибки   = {err_pos} (0 = нет ошибки)")

    # Вносим одиночную ошибку (инвертируем бит на позиции 5)
    print(f"\n--- Декодирование D(c') с одиночной ошибкой ---")
    c_err = list(c)
    err_bit = 4  # индекс (0-based), т.е. позиция 5 в кодовом слове
    c_err[err_bit] ^= 1
    print(f"  Принятое слово c' = {_bits_to_str(c_err)}  "
          f"(ошибка на позиции {err_bit + 1})")

    decoded_err, err_pos = hamming.decode(c_err)
    print(f"  Декодировано D(c') = {_bits_to_str(decoded_err)}")
    print(f"  Обнаружена и исправлена ошибка на позиции: {err_pos}")
    print(f"  Совпадает с исходным m: {decoded_err == m}")

    # Верификация V(E(m), D(c))
    print(f"\n--- Верификация V(E(m), D(c)) ---")
    is_valid = hamming.verify(m)
    print(f"  D(E(m)) == m ? {is_valid}")

    # --- Пример 2: Хэмминг C(15, 11) ---
    print(f"\n{'=' * 60}")
    k2 = 11
    hamming2 = HammingCodeSystem(k=k2)
    print(f"Система: {hamming2}")

    m2 = [1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0]
    c2 = hamming2.encode(m2)
    print(f"  m  = {_bits_to_str(m2)}")
    print(f"  c  = {_bits_to_str(c2)}")

    # Ошибка на позиции 10
    c2_err = list(c2)
    c2_err[9] ^= 1
    decoded2, err_pos2 = hamming2.decode(c2_err)
    print(f"  c' = {_bits_to_str(c2_err)}  (ошибка на позиции 10)")
    print(f"  D(c') = {_bits_to_str(decoded2)},  исправлена позиция: {err_pos2}")
    print(f"  Верификация V: {hamming2.verify(m2)}")
