"""
Расширенный код Хэмминга C[n+1, k] — передача данных по каналу связи
с обнаружением и исправлением одной симметричной ошибки,
а также обнаружением двойной ошибки.

Отличие от стандартного кода Хэмминга C(n, k):
к кодовому слову длины n добавляется один общий бит чётности (позиция 0),
равный XOR всех остальных бит. Итоговая длина — n+1.

Оформлено в соответствии с моделью алфавитной криптосистемы
В.О. Осипяна: Σ₀ = (M*, Q, C*, E(m), D(c) | V(E(m), D(c))).

Автор алгоритма: В.О. Осипян
"""

from __future__ import annotations

from dataclasses import dataclass


# ---------------------------------------------------------------------------
#  Вспомогательные функции
# ---------------------------------------------------------------------------

def _calc_parity_bits(k: int) -> int:
    """Вычисляет минимальное число проверочных бит r для k информационных.

    Условие Хэмминга: 2^r >= k + r + 1.
    Перебираем r, пока неравенство не выполнится.
    """
    r = 0
    while (1 << r) < k + r + 1:
        r += 1
    return r


def _is_power_of_two(x: int) -> bool:
    """Проверяет, является ли x степенью двойки.

    У степеней двойки ровно один установленный бит,
    поэтому x & (x - 1) == 0.
    """
    return x > 0 and (x & (x - 1)) == 0


# ---------------------------------------------------------------------------
#  Класс-криптосистема расширенного Хэмминга
# ---------------------------------------------------------------------------

@dataclass
class ExtendedHammingCodeSystem:
    """Реализация криптосистемы Σ₀ = (M*, Q, C*, E(m), D(c) | V(E(m), D(c)))
    на основе расширенного кода Хэмминга C[n+1, k].

    Атрибуты
    ---------
    k : int
        Число информационных бит (размерность кода).
    r : int
        Число проверочных бит стандартного кода Хэмминга.
    n : int
        Длина стандартного кодового слова (n = k + r).
    n_ext : int
        Длина расширенного кодового слова (n_ext = n + 1 = k + r + 1).

    Расширение
    ----------
    К стандартному коду Хэмминга C(n, k) добавляется один бит общей
    чётности p_overall на позиции 0. Этот бит равен XOR всех остальных
    n бит кодового слова. Это позволяет:
    - исправить 1 ошибку (как и стандартный код);
    - обнаружить 2 ошибки (стандартный код этого не может).

    В терминологии Осипяна
    ----------------------
    M*  — множество всех сообщений (двоичных строк длины k).
    Q   — алфавит {0, 1}.
    C*  — множество кодовых слов (шифротекстов) длины n+1.
    E(m) — алгоритм кодирования (шифрования): m -> c.
    D(c) — алгоритм декодирования (дешифрования): c -> m.
    V(E(m), D(c)) — верификация: D(E(m)) == m для любого m ∈ M*.
    """

    k: int  # число информационных бит
    r: int = 0  # число проверочных бит (вычисляется автоматически)
    n: int = 0  # длина стандартного кодового слова
    n_ext: int = 0  # длина расширенного кодового слова (n + 1)

    def __post_init__(self) -> None:
        if self.k < 1:
            raise ValueError(f"k должно быть >= 1, получено {self.k}")
        self.r = _calc_parity_bits(self.k)
        self.n = self.k + self.r
        self.n_ext = self.n + 1  # +1 за счёт общего бита чётности

    # ---- E(m): кодирование (шифрование) ---------------------------------

    def encode(self, message: list[int]) -> list[int]:
        """Кодирует информационное слово m длины k в расширенное кодовое
        слово c длины n+1.

        Это функция E(m) криптосистемы — прямое преобразование.

        Параметры
        ---------
        message : list[int]
            Двоичный вектор длины k (элементы 0 или 1).

        Возвращает
        ----------
        list[int]
            Расширенное кодовое слово длины n+1.
            Формат: [p_overall, c_1, c_2, ..., c_n],
            где p_overall — общий бит чётности.
        """
        self._validate_message(message)

        # Создаём массив длины n+1 (индексация с 1 для стандартной части).
        # codeword[0] не используется на этом этапе — позже станет p_overall.
        codeword = [0] * (self.n + 1)

        # Шаг 1: расставляем информационные биты на позиции,
        # не являющиеся степенями двойки.
        # Степени двойки (1, 2, 4, 8, ...) зарезервированы под проверочные биты.
        j = 0
        for i in range(1, self.n + 1):
            if not _is_power_of_two(i):
                codeword[i] = message[j]
                j += 1

        # Шаг 2: вычисляем проверочные биты p_j на позициях 2^j.
        # p_j = XOR всех codeword[i], где j-й бит числа i равен 1
        # (кроме самой позиции 2^j).
        for j in range(self.r):
            parity_pos = 1 << j
            parity = 0
            for i in range(1, self.n + 1):
                if i & parity_pos and i != parity_pos:
                    parity ^= codeword[i]
            codeword[parity_pos] = parity

        # Шаг 3 (расширение): вычисляем общий бит чётности p_overall.
        # p_overall = XOR всех бит c_1, c_2, ..., c_n.
        # Этот бит обеспечивает чётность всего расширенного слова,
        # что позволяет различать одиночные и двойные ошибки.
        p_overall = 0
        for i in range(1, self.n + 1):
            p_overall ^= codeword[i]

        # Возвращаем расширенное слово: [p_overall, c_1, c_2, ..., c_n]
        return [p_overall] + codeword[1:]

    # ---- D(c): декодирование (дешифрование) ------------------------------

    def decode(self, received: list[int]) -> tuple[list[int], int, str]:
        """Декодирует принятое расширенное слово длины n+1, исправляя
        одиночную ошибку или обнаруживая двойную.

        Это функция D(c) криптосистемы — обратное преобразование.

        Параметры
        ---------
        received : list[int]
            Принятый двоичный вектор длины n+1 (возможно, с ошибками).

        Возвращает
        ----------
        tuple[list[int], int, str]
            (decoded_message, error_position, status)
            decoded_message — восстановленное сообщение длины k.
            error_position  — позиция исправленной ошибки (0 = нет ошибки,
                              -1 = двойная ошибка).
            status — текстовое описание результата:
                     "no_error", "corrected", "double_error".
        """
        self._validate_extended_codeword(received)

        # Разделяем общий бит чётности и основное кодовое слово.
        p_overall_received = received[0]
        # Индексация с 1 для основной части
        cw = [0] + list(received[1:])

        # Шаг 1: вычисляем синдром S стандартного кода Хэмминга.
        # s_j = XOR всех cw[i], где j-й бит позиции i равен 1.
        # При декодировании суммируем все позиции (включая проверочные).
        syndrome = 0
        for j in range(self.r):
            parity_pos = 1 << j
            s_j = 0
            for i in range(1, self.n + 1):
                if i & parity_pos:
                    s_j ^= cw[i]
            if s_j:
                syndrome |= parity_pos

        # Шаг 2: проверяем общую чётность.
        # p_check = XOR(p_overall_received, c_1, c_2, ..., c_n).
        # Если передача без ошибок, p_check = 0.
        p_check = p_overall_received
        for i in range(1, self.n + 1):
            p_check ^= cw[i]

        # Шаг 3: интерпретация синдрома и общей чётности.
        #
        # | Синдром S | Общая чётность p_check | Интерпретация           |
        # |-----------|------------------------|-------------------------|
        # | S = 0     | p_check = 0            | Ошибок нет              |
        # | S = 0     | p_check = 1            | Ошибка в бите p_overall |
        # | S ≠ 0     | p_check = 1            | Одиночная ошибка        |
        # |           |                        | на позиции S —          |
        # |           |                        | исправляем              |
        # | S ≠ 0     | p_check = 0            | Двойная ошибка —        |
        # |           |                        | обнаружена, но          |
        # |           |                        | НЕ исправляема          |

        if syndrome == 0 and p_check == 0:
            # Ошибок нет
            error_position = 0
            status = "no_error"
        elif syndrome == 0 and p_check == 1:
            # Ошибка только в бите общей чётности (позиция 0).
            # Информационные и проверочные биты не затронуты.
            error_position = 0
            status = "corrected"
            # Бит p_overall испорчен, но он не влияет на данные —
            # информационные биты корректны.
        elif syndrome != 0 and p_check == 1:
            # Одиночная ошибка на позиции syndrome в основном слове.
            if syndrome > self.n:
                raise ValueError(
                    f"Синдром {syndrome} выходит за пределы "
                    f"кодового слова длины {self.n}. "
                    "Возможно, произошло более двух ошибок."
                )
            cw[syndrome] ^= 1  # исправляем ошибочный бит
            error_position = syndrome
            status = "corrected"
        else:
            # syndrome != 0 и p_check == 0 → двойная ошибка.
            # Расширенный код Хэмминга обнаруживает, но НЕ может
            # исправить двойную ошибку.
            error_position = -1
            status = "double_error"

        # Шаг 4: извлекаем информационные биты (позиции, не являющиеся
        # степенями двойки) из (возможно исправленного) слова.
        decoded = []
        for i in range(1, self.n + 1):
            if not _is_power_of_two(i):
                decoded.append(cw[i])

        return decoded, error_position, status

    # ---- V(E(m), D(c)): верификация --------------------------------------

    def verify(self, message: list[int]) -> bool:
        """Проверяет свойство криптосистемы: D(E(m)) == m для данного m."""
        self._validate_message(message)
        encoded = self.encode(message)
        decoded, _, status = self.decode(encoded)
        return decoded == message and status == "no_error"

    # ---- Валидация -------------------------------------------------------

    def _validate_message(self, message: list[int]) -> None:
        if len(message) != self.k:
            raise ValueError(
                f"Длина сообщения должна быть {self.k}, получено {len(message)}"
            )
        if not all(b in (0, 1) for b in message):
            raise ValueError("Сообщение должно содержать только 0 и 1")

    def _validate_extended_codeword(self, codeword: list[int]) -> None:
        if len(codeword) != self.n_ext:
            raise ValueError(
                f"Длина расширенного кодового слова должна быть {self.n_ext}, "
                f"получено {len(codeword)}"
            )
        if not all(b in (0, 1) for b in codeword):
            raise ValueError("Кодовое слово должно содержать только 0 и 1")

    def __repr__(self) -> str:
        return (
            f"ExtendedHammingCodeSystem(C[{self.n_ext},{self.k}], "
            f"n={self.n}, r={self.r}, "
            f"исправляет 1, обнаруживает 2 ошибки)"
        )


# ---------------------------------------------------------------------------
#  Демонстрация
# ---------------------------------------------------------------------------

def _bits_to_str(bits: list[int]) -> str:
    """Превращает список бит в строку для удобного вывода."""
    return "".join(map(str, bits))


if __name__ == "__main__":
    # --- Пример 1: Расширенный Хэмминг C[8, 4] ---
    print("=" * 65)
    print("  Расширенный код Хэмминга — модель криптосистемы Осипяна")
    print("  Σ₀ = (M*, Q, C*, E(m), D(c) | V(E(m), D(c)))")
    print("=" * 65)

    k = 4
    hamming = ExtendedHammingCodeSystem(k=k)
    print(f"\nСистема: {hamming}")
    print(f"  M* — двоичные строки длины {hamming.k}")
    print(f"  Q  = {{0, 1}}")
    print(f"  C* — расширенные кодовые слова длины {hamming.n_ext}")

    # Исходное сообщение
    m = [1, 0, 1, 1]
    print(f"\n--- E(m): Кодирование ---")
    print(f"  Сообщение m = {_bits_to_str(m)}")

    c = hamming.encode(m)
    print(f"  Расширенное кодовое слово c = E(m) = {_bits_to_str(c)}")
    print(f"  [p_overall | c_1 ... c_n] = [{c[0]} | {_bits_to_str(c[1:])}]")

    # Декодирование без ошибок
    print(f"\n--- D(c): Декодирование без ошибок ---")
    decoded, err_pos, status = hamming.decode(c)
    print(f"  D(c) = {_bits_to_str(decoded)}")
    print(f"  Статус: {status}, позиция ошибки: {err_pos}")

    # Одиночная ошибка (инвертируем бит на позиции 5 основного слова)
    print(f"\n--- D(c'): Одиночная ошибка ---")
    c_err1 = list(c)
    err_idx = 5  # позиция в расширенном слове (= позиция 5 в основном)
    c_err1[err_idx] ^= 1
    print(f"  Принятое c' = {_bits_to_str(c_err1)}  "
          f"(ошибка на позиции {err_idx} расш. слова)")

    decoded1, err_pos1, status1 = hamming.decode(c_err1)
    print(f"  D(c') = {_bits_to_str(decoded1)}")
    print(f"  Статус: {status1}, исправлена позиция: {err_pos1}")
    print(f"  Совпадает с m: {decoded1 == m}")

    # Одиночная ошибка в бите общей чётности (позиция 0)
    print(f"\n--- D(c'): Ошибка в бите общей чётности ---")
    c_err_p = list(c)
    c_err_p[0] ^= 1
    print(f"  Принятое c' = {_bits_to_str(c_err_p)}  "
          f"(ошибка в p_overall)")

    decoded_p, err_pos_p, status_p = hamming.decode(c_err_p)
    print(f"  D(c') = {_bits_to_str(decoded_p)}")
    print(f"  Статус: {status_p}")
    print(f"  Совпадает с m: {decoded_p == m}")

    # Двойная ошибка (инвертируем 2 бита)
    print(f"\n--- D(c'): Двойная ошибка (обнаружение) ---")
    c_err2 = list(c)
    c_err2[2] ^= 1  # ошибка в позиции 2
    c_err2[5] ^= 1  # ошибка в позиции 5
    print(f"  Принятое c' = {_bits_to_str(c_err2)}  "
          f"(ошибки на позициях 2 и 5)")

    decoded2, err_pos2, status2 = hamming.decode(c_err2)
    print(f"  D(c') = {_bits_to_str(decoded2)}")
    print(f"  Статус: {status2}")
    print(f"  ДВОЙНАЯ ОШИБКА ОБНАРУЖЕНА (не исправляема)")

    # Верификация V(E(m), D(c))
    print(f"\n--- V(E(m), D(c)): Верификация ---")
    is_valid = hamming.verify(m)
    print(f"  D(E(m)) == m ? {is_valid}")

    # --- Пример 2: Расширенный Хэмминг C[16, 11] ---
    print(f"\n{'=' * 65}")
    k2 = 11
    hamming2 = ExtendedHammingCodeSystem(k=k2)
    print(f"Система: {hamming2}")

    m2 = [1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0]
    c2 = hamming2.encode(m2)
    print(f"  m  = {_bits_to_str(m2)}")
    print(f"  c  = {_bits_to_str(c2)}  (длина {len(c2)})")

    # Одиночная ошибка на позиции 10
    c2_err = list(c2)
    c2_err[10] ^= 1
    decoded2_1, err_pos2_1, status2_1 = hamming2.decode(c2_err)
    print(f"  c' = {_bits_to_str(c2_err)}  (ошибка на позиции 10)")
    print(f"  D(c') = {_bits_to_str(decoded2_1)}, "
          f"статус: {status2_1}, позиция: {err_pos2_1}")

    # Двойная ошибка
    c2_err2 = list(c2)
    c2_err2[3] ^= 1
    c2_err2[7] ^= 1
    decoded2_2, err_pos2_2, status2_2 = hamming2.decode(c2_err2)
    print(f"  c' = {_bits_to_str(c2_err2)}  (ошибки на позициях 3 и 7)")
    print(f"  Статус: {status2_2} — двойная ошибка обнаружена")

    print(f"\n  Верификация V: {hamming2.verify(m2)}")
