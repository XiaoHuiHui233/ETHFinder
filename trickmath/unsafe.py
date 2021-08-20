def div_rounding_up(x: int, y: int) -> int:
    return x // y + (1 if x % y > 0 else 0)