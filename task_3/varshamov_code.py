"""
Код Варшамова-Тененгольца (VT-код) — передача данных по каналу связи
с обнаружением и исправлением одной асимметричной ошибки.

Оформлено в соответствии с моделью алфавитной криптосистемы
В.О. Осипяна: Σ₀ = (M*, Q, C*, E(m), D(c) | V(E(m), D(c))).

Автор алгоритма: В.О. Осипян
Литература: Осипян В.О. Элементы теории передачи информации.
            Краснодар, 1998.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass, field
from itertools import product


# ---------------------------------------------------------------------------
#  Вспомогательные функции
# ---------------------------------------------------------------------------

def _varshamov_syndrome(word: list[int], n: int) -> int:
    """Вычисляет синдром Варшамова-Тененгольца для двоичного слова.

    Формула: S(x) = Σ_{i=1}^{n} i·x_i  (mod n+1)

    Позиции нумеруются с 1: x_1, x_2, ..., x_n.
    В массиве Python индексация с 0, поэтому i-я позиция → word[i-1].
    """
    return sum((i + 1) * word[i] for i in range(n)) % (n + 1)


def _generate_vt_codebook(n: int, a: int) -> list[list[int]]:
    """Генерирует все кодовые слова VT_a(n).

    VT_a(n) = { x ∈ {0,1}^n : Σ_{i=1}^{n} i·x_i ≡ a (mod n+1) }

    Возвращает отсортированный список кодовых слов.
    """
    codebook: list[list[int]] = []
    for bits in product((0, 1), repeat=n):
        word = list(bits)
        if _varshamov_syndrome(word, n) == a:
            codebook.append(word)
    return codebook


def _bits_to_str(bits: list[int]) -> str:
    """Превращает список бит в строку для удобного вывода."""
    return "".join(map(str, bits))


def _bits_to_int(bits: list[int]) -> int:
    """Преобразует двоичный вектор в целое число."""
    result = 0
    for b in bits:
        result = result * 2 + b
    return result


# ---------------------------------------------------------------------------
#  Класс-криптосистема кода Варшамова-Тененгольца
# ---------------------------------------------------------------------------

@dataclass
class VarshamovCodeSystem:
    """Реализация криптосистемы Σ₀ = (M*, Q, C*, E(m), D(c) | V(E(m), D(c)))
    на основе кода Варшамова-Тененгольца VT_a(n).

    Код VT_a(n) предназначен для исправления **одной асимметричной** ошибки
    в двоичном канале связи (Z-канал). В отличие от кода Хэмминга,
    который исправляет симметричные ошибки (0↔1 с равной вероятностью),
    VT-код ориентирован на каналы, где ошибки однонаправлены:
    преимущественно 1→0 или преимущественно 0→1.

    Атрибуты
    ---------
    n : int
        Длина кодового слова.
    a : int
        Параметр кода (0 ≤ a ≤ n). Определяет конкретный подкод.
    k : int
        Число информационных бит (вычисляется из размера кодовой книги).

    В терминологии Осипяна
    ----------------------
    M*  — множество всех сообщений (двоичных строк длины k).
    Q   — множество числовых эквивалентов элементарных сообщений {0, 1}.
    C*  — множество кодовых слов (шифротекстов) длины n, принадлежащих VT_a(n).
    E(m) — алгоритм кодирования (шифрования): m → c ∈ VT_a(n).
    D(c) — алгоритм декодирования (дешифрования): c → m.
    V(E(m), D(c)) — верификация: D(E(m)) == m для любого m ∈ M*.
    """

    n: int  # длина кодового слова
    a: int = 0  # параметр кода
    k: int = 0  # число информационных бит (вычисляется)
    _codebook: list[list[int]] = field(
        default_factory=list, repr=False, init=False
    )

    def __post_init__(self) -> None:
        if self.n < 2:
            raise ValueError(f"n должно быть >= 2, получено {self.n}")
        if not (0 <= self.a <= self.n):
            raise ValueError(
                f"Параметр a должен быть в диапазоне [0, {self.n}], "
                f"получено {self.a}"
            )
        # Генерируем кодовую книгу — множество C*
        self._codebook = _generate_vt_codebook(self.n, self.a)
        # Число информационных бит = ⌊log₂|C*|⌋
        # (используем степень двойки, чтобы обеспечить биективное отображение)
        self.k = int(math.log2(len(self._codebook)))

    # ---- E(m): кодирование (шифрование) ------------------------------------

    def encode(self, message: list[int]) -> list[int]:
        """Кодирует информационное слово m длины k в кодовое слово c ∈ VT_a(n).

        Это функция E(m) криптосистемы — прямое преобразование.

        Используется табличное кодирование: сообщение m интерпретируется
        как двоичное число — индекс в кодовой книге VT_a(n).

        Параметры
        ---------
        message : list[int]
            Двоичный вектор длины k (элементы 0 или 1).

        Возвращает
        ----------
        list[int]
            Кодовое слово (шифротекст) длины n из множества VT_a(n).
        """
        self._validate_message(message)

        # Интерпретируем сообщение как номер кодового слова в кодовой книге
        index = _bits_to_int(message)

        if index >= len(self._codebook):
            raise ValueError(
                f"Индекс сообщения {index} выходит за пределы "
                f"кодовой книги (размер {len(self._codebook)})"
            )

        return list(self._codebook[index])

    # ---- D(c): декодирование (дешифрование) --------------------------------

    def decode(
        self, received: list[int], channel_type: str = "1->0"
    ) -> tuple[list[int], int | None, str]:
        """Декодирует принятое слово, исправляя одну асимметричную ошибку.

        Это функция D(c) криптосистемы — обратное преобразование.

        В асимметричном канале (Z-канале) ошибки происходят только
        в одном направлении, которое является свойством канала:
        - Z-канал "1->0": бит может измениться только из 1 в 0;
        - Z-канал "0->1": бит может измениться только из 0 в 1.

        Алгоритм:
        1. Вычисляем синдром S = Σ i·y_i mod (n+1).
        2. Если S == a, ошибок нет.
        3. Если S ≠ a, определяем позицию ошибки:
           - Канал 1→0: j = (a − S) mod (n+1).
           - Канал 0→1: j = (S − a) mod (n+1).

        Параметры
        ---------
        received : list[int]
            Принятый двоичный вектор длины n (возможно, с одной ошибкой).
        channel_type : str
            Тип асимметричного канала: "1->0" или "0->1".

        Возвращает
        ----------
        tuple[list[int], int | None, str]
            (decoded_message, error_position, error_type)
            decoded_message — восстановленное сообщение длины k.
            error_position  — позиция ошибки (0-based), None если ошибок нет.
            error_type      — описание типа обнаруженной ошибки.
        """
        if channel_type not in ("1->0", "0->1"):
            raise ValueError(
                "Тип канала должен быть '1->0' или '0->1'"
            )
        self._validate_codeword(received)

        corrected = list(received)
        syndrome = _varshamov_syndrome(received, self.n)

        error_pos: int | None = None
        error_type = "нет ошибки"

        if syndrome != self.a:
            if channel_type == "1->0":
                # Ошибка 1→0 на позиции j уменьшает синдром на j
                # j = (a − S) mod (n+1)
                j = (self.a - syndrome) % (self.n + 1)
                expected_bit = 0  # после ошибки 1→0 бит стал 0
                fix_value = 1     # восстанавливаем в 1
                error_type = "1→0"
            else:
                # Ошибка 0→1 на позиции j увеличивает синдром на j
                # j = (S − a) mod (n+1)
                j = (syndrome - self.a) % (self.n + 1)
                expected_bit = 1  # после ошибки 0→1 бит стал 1
                fix_value = 0     # восстанавливаем в 0
                error_type = "0→1"

            if 1 <= j <= self.n and received[j - 1] == expected_bit:
                corrected[j - 1] = fix_value
                error_pos = j - 1  # переводим в 0-based
            else:
                raise ValueError(
                    f"Не удалось исправить ошибку. "
                    f"Синдром={syndrome}, ожидаемый={self.a}, "
                    f"позиция j={j}. "
                    f"Возможно, произошло более одной ошибки."
                )

        # Находим исправленное кодовое слово в кодовой книге
        # и извлекаем соответствующее сообщение
        try:
            index = self._codebook.index(corrected)
        except ValueError:
            raise ValueError(
                "Исправленное слово не найдено в кодовой книге. "
                "Возможно, произошло более одной ошибки."
            )

        # Преобразуем индекс обратно в двоичное сообщение длины k
        decoded = []
        for i in range(self.k - 1, -1, -1):
            decoded.append((index >> i) & 1)

        return decoded, error_pos, error_type

    # ---- V(E(m), D(c)): верификация ----------------------------------------

    def verify(self, message: list[int], channel_type: str = "1->0") -> bool:
        """Проверяет свойство криптосистемы: D(E(m)) == m для данного m.

        Это функция V(E(m), D(c)) — верификация корректности.
        """
        self._validate_message(message)
        encoded = self.encode(message)
        decoded, _, _ = self.decode(encoded, channel_type)
        return decoded == message

    # ---- Имитация канала с асимметричной ошибкой ---------------------------

    def introduce_error(
        self, codeword: list[int], error_type: str = "1->0"
    ) -> tuple[list[int], int | None]:
        """Вносит одну асимметричную ошибку в кодовое слово.

        Параметры
        ---------
        codeword : list[int]
            Исходное кодовое слово длины n.
        error_type : str
            Тип ошибки: "1->0" или "0->1".

        Возвращает
        ----------
        tuple[list[int], int | None]
            (received, error_position) — слово с ошибкой и позиция ошибки.
            Если ошибку внести невозможно (нет подходящих бит), позиция = None.
        """
        received = list(codeword)

        if error_type == "1->0":
            candidates = [i for i, b in enumerate(received) if b == 1]
        elif error_type == "0->1":
            candidates = [i for i, b in enumerate(received) if b == 0]
        else:
            raise ValueError("Тип ошибки должен быть '1->0' или '0->1'")

        if not candidates:
            return received, None

        pos = random.choice(candidates)
        received[pos] ^= 1  # инвертируем бит
        return received, pos

    # ---- Информация о коде -------------------------------------------------

    def code_info(self) -> dict[str, int | float]:
        """Возвращает характеристики кода."""
        total_codewords = len(self._codebook)
        usable_codewords = 2 ** self.k
        code_rate = self.k / self.n if self.n > 0 else 0.0
        return {
            "n": self.n,
            "a": self.a,
            "k": self.k,
            "total_codewords": total_codewords,
            "usable_codewords": usable_codewords,
            "code_rate": round(code_rate, 4),
        }

    # ---- Вспомогательные методы --------------------------------------------

    def _validate_message(self, message: list[int]) -> None:
        if len(message) != self.k:
            raise ValueError(
                f"Длина сообщения должна быть {self.k}, "
                f"получено {len(message)}"
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
            f"VarshamovCodeSystem(VT_{self.a}({self.n}), "
            f"k={self.k}, "
            f"исправляет 1 асимметричную ошибку)"
        )


# ---------------------------------------------------------------------------
#  Демонстрация
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # --- Пример: VT-код длины 7 ---
    print("=" * 65)
    print("  Код Варшамова-Тененгольца — модель криптосистемы Осипяна")
    print("  Σ₀ = (M*, Q, C*, E(m), D(c) | V(E(m), D(c)))")
    print("=" * 65)

    n = 7
    a = 0
    vt = VarshamovCodeSystem(n=n, a=a)
    info = vt.code_info()

    print(f"\nСистема: {vt}")
    print(f"  M* — двоичные строки длины {vt.k}")
    print(f"  Q  = {{0, 1}}")
    print(f"  C* — кодовые слова длины {vt.n} из VT_{a}({n})")
    print(f"  Всего кодовых слов |C*| = {info['total_codewords']}")
    print(f"  Используемых (2^k)      = {info['usable_codewords']}")
    print(f"  Скорость кода R = k/n   = {info['code_rate']}")

    # Первые кодовые слова
    print(f"\nПервые 10 кодовых слов VT_{a}({n}):")
    for i, cw in enumerate(vt._codebook[:10]):
        s = _varshamov_syndrome(cw, n)
        print(f"  {i:3d}: {_bits_to_str(cw)}  (синдром={s})")

    # --- Кодирование ---
    m = [1, 0, 1, 1]
    print(f"\n{'─' * 65}")
    print(f"  Кодирование E(m)")
    print(f"{'─' * 65}")
    print(f"  Сообщение m = {_bits_to_str(m)}  (десятичное: {_bits_to_int(m)})")

    c = vt.encode(m)
    print(f"  Кодовое слово c = E(m) = {_bits_to_str(c)}")
    print(f"  Синдром S(c) = {_varshamov_syndrome(c, n)}  (ожидается {a})")

    # --- Декодирование без ошибок ---
    print(f"\n{'─' * 65}")
    print(f"  Декодирование D(c) без ошибок")
    print(f"{'─' * 65}")
    decoded, err_pos, err_type = vt.decode(c, "1->0")
    print(f"  Декодировано D(c) = {_bits_to_str(decoded)}")
    print(f"  Ошибка: {err_type}")

    # --- Асимметричная ошибка 1→0 (Z-канал) ---
    print(f"\n{'─' * 65}")
    print(f"  Z-канал: асимметричная ошибка 1→0")
    print(f"{'─' * 65}")

    random.seed(42)  # для воспроизводимости
    c_err, pos = vt.introduce_error(c, "1->0")
    print(f"  Отправлено c  = {_bits_to_str(c)}")
    print(f"  Принято    c' = {_bits_to_str(c_err)}  "
          f"(ошибка на позиции {pos})")
    print(f"  Синдром S(c') = {_varshamov_syndrome(c_err, n)}")

    decoded_err, det_pos, det_type = vt.decode(c_err, "1->0")
    print(f"  Обнаружена ошибка: тип {det_type}, позиция {det_pos}")
    print(f"  Декодировано D(c') = {_bits_to_str(decoded_err)}")
    print(f"  Совпадает с m: {decoded_err == m}")

    # --- Асимметричная ошибка 0→1 (обратный Z-канал) ---
    print(f"\n{'─' * 65}")
    print(f"  Обратный Z-канал: асимметричная ошибка 0→1")
    print(f"{'─' * 65}")

    c_err2, pos2 = vt.introduce_error(c, "0->1")
    print(f"  Отправлено c  = {_bits_to_str(c)}")
    print(f"  Принято    c' = {_bits_to_str(c_err2)}  "
          f"(ошибка на позиции {pos2})")
    print(f"  Синдром S(c') = {_varshamov_syndrome(c_err2, n)}")

    decoded_err2, det_pos2, det_type2 = vt.decode(c_err2, "0->1")
    print(f"  Обнаружена ошибка: тип {det_type2}, позиция {det_pos2}")
    print(f"  Декодировано D(c') = {_bits_to_str(decoded_err2)}")
    print(f"  Совпадает с m: {decoded_err2 == m}")

    # --- Верификация V(E(m), D(c)) ---
    print(f"\n{'─' * 65}")
    print(f"  Верификация V(E(m), D(c))")
    print(f"{'─' * 65}")
    print(f"  D(E(m)) == m ? {vt.verify(m)}")

    # Полная верификация для всех возможных сообщений
    all_ok = True
    for idx in range(2 ** vt.k):
        msg = []
        for i in range(vt.k - 1, -1, -1):
            msg.append((idx >> i) & 1)
        if not vt.verify(msg):
            all_ok = False
            print(f"  ОШИБКА верификации для m = {_bits_to_str(msg)}")
    print(f"  Все 2^{vt.k} = {2**vt.k} сообщений: "
          f"{'OK' if all_ok else 'ОШИБКА'}")

    # --- Пример 2: VT-код длины 10 ---
    print(f"\n{'=' * 65}")
    n2 = 10
    a2 = 0
    vt2 = VarshamovCodeSystem(n=n2, a=a2)
    print(f"Система: {vt2}")
    info2 = vt2.code_info()
    print(f"  |C*| = {info2['total_codewords']}, "
          f"k = {info2['k']}, R = {info2['code_rate']}")

    m2 = [1, 1, 0, 0, 1, 0]
    c2 = vt2.encode(m2)
    print(f"  m  = {_bits_to_str(m2)}")
    print(f"  c  = {_bits_to_str(c2)}")

    c2_err, pos_err = vt2.introduce_error(c2, "1->0")
    decoded2, det_pos_2, det_type_2 = vt2.decode(c2_err, "1->0")
    print(f"  c' = {_bits_to_str(c2_err)}  "
          f"(ошибка {det_type_2} на позиции {pos_err})")
    print(f"  D(c') = {_bits_to_str(decoded2)},  "
          f"исправлена позиция: {det_pos_2}")
    print(f"  Верификация V: {vt2.verify(m2)}")
