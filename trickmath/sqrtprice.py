from trickmath.base import mul_div, mul_div_rounding_up, div_rounding_up


def get_amount0_delta(sqrt_ratio_A_X96: int, sqrt_ratio_B_X96: int,
        liquidity: int, round_up: bool) -> int:
    if (sqrt_ratio_A_X96 > sqrt_ratio_B_X96):
        sqrt_ratio_A_X96 ^= sqrt_ratio_B_X96
        sqrt_ratio_B_X96 ^= sqrt_ratio_A_X96
        sqrt_ratio_A_X96 ^= sqrt_ratio_B_X96
    numerator1 = liquidity << 96
    numerator2 = sqrt_ratio_B_X96 - sqrt_ratio_A_X96
    if sqrt_ratio_A_X96 <= 0:
        raise ValueError()
    if round_up:
        return div_rounding_up(
            mul_div_rounding_up(numerator1, numerator2, sqrt_ratio_B_X96),
            sqrt_ratio_A_X96
        )
    else:
        return mul_div(numerator1, numerator2, sqrt_ratio_B_X96) // sqrt_ratio_A_X96


def get_amount1_delta(sqrt_ratio_A_X96: int, sqrt_ratio_B_X96: int,
            liquidity: int, round_up: bool) -> int:
    if (sqrt_ratio_A_X96 > sqrt_ratio_B_X96):
        sqrt_ratio_A_X96 ^= sqrt_ratio_B_X96
        sqrt_ratio_B_X96 ^= sqrt_ratio_A_X96
        sqrt_ratio_A_X96 ^= sqrt_ratio_B_X96

    if round_up:
        return mul_div_rounding_up(liquidity, sqrt_ratio_B_X96 - sqrt_ratio_A_X96, 0x1000000000000000000000000)
    else:
        return mul_div(liquidity, sqrt_ratio_B_X96 - sqrt_ratio_A_X96, 0x1000000000000000000000000)


def get_amount0_delta_with_signed(sqrt_ratio_A_X96: int, sqrt_ratio_B_X96: int,
        liquidity: int) -> int:
    if liquidity < 0:
        return -get_amount0_delta(sqrt_ratio_A_X96, sqrt_ratio_B_X96, -liquidity, False)
    else:
        return get_amount0_delta(sqrt_ratio_A_X96, sqrt_ratio_B_X96, liquidity, True)


def get_amount1_delta_with_signed(sqrt_ratio_A_X96: int, sqrt_ratio_B_X96: int,
        liquidity: int) -> int:
    if liquidity < 0:
        return -get_amount1_delta(sqrt_ratio_A_X96, sqrt_ratio_B_X96, -liquidity, False)
    else:
        return get_amount1_delta(sqrt_ratio_A_X96, sqrt_ratio_B_X96, liquidity, True)