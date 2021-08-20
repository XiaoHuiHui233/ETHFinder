from .base import mul_div, mul_div_rounding_up
from .unsafe import div_rounding_up


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


def get_next_sqrt_price_from_amount0_rounding_up(sqrt_P_X96: int, liquidity: int, amount: int, add: bool) -> int:
        # we short circuit amount == 0 because the result is otherwise not guaranteed to equal the input price
        if amount == 0:
            return sqrt_P_X96
        numerator1 = liquidity << 96

        if add:
            product = amount * sqrt_P_X96
            product %= 2 ** 256
            if product // amount == sqrt_P_X96:
                denominator = numerator1 + product
                if (denominator >= numerator1):
                    # always fits in 160 bits
                    return mul_div_rounding_up(numerator1, sqrt_P_X96, denominator)
            return div_rounding_up(numerator1, (numerator1 // sqrt_P_X96) + amount)
        else:
            product = amount * sqrt_P_X96
            product %= 2 ** 256
            # if the product overflows, we know the denominator underflows
            # in addition, we must check that the denominator does not underflow
            if product / amount != sqrt_P_X96 or numerator1 <= product:
                raise ValueError()
            denominator = numerator1 - product
            return mul_div_rounding_up(numerator1, sqrt_P_X96, denominator)


def get_next_sqrt_price_from_amount1_rounding_down(sqrt_P_X96: int, liquidity: int, amount: int, add: bool) -> int:
        # if we're adding (subtracting), rounding down requires rounding the quotient down (up)
        # in both cases, avoid a mulDiv for most inputs
        if add:
            if amount <= 2 ** 161 - 1:
                quotient = (amount << 96) / liquidity
            else:
                quotient = mul_div(amount, 0x1000000000000000000000000, liquidity)
            return sqrt_P_X96 + quotient
        else:
            if amount <= 2 ** 160 - 1:
                quotient = div_rounding_up(amount << 96, liquidity)
            else:
                quotient = mul_div_rounding_up(amount, 0x1000000000000000000000000, liquidity)

            if sqrt_P_X96 <= quotient:
                raise ValueError()
            # always fits 160 bits
            return sqrt_P_X96 - quotient


def get_next_sqrt_price_from_input(sqrt_P_X96: int, liquidity: int, amount_in: int, zero_for_one: bool) -> int:
        if sqrt_P_X96 <= 0:
            raise ValueError()
        if liquidity <= 0:
            raise ValueError()

        # round to make sure that we don't pass the target price
        if zero_for_one:
            return get_next_sqrt_price_from_amount0_rounding_up(sqrt_P_X96, liquidity, amount_in, True)
        else:
            return get_next_sqrt_price_from_amount1_rounding_down(sqrt_P_X96, liquidity, amount_in, True)


def get_next_sqrt_price_from_output(sqrt_P_X96: int, liquidity: int, amount_out: int, zero_for_one: bool) -> int:
        if sqrt_P_X96 <= 0:
            raise ValueError()
        if liquidity <= 0:
            raise ValueError()

        # round to make sure that we pass the target price
        if zero_for_one:
            return get_next_sqrt_price_from_amount1_rounding_down(sqrt_P_X96, liquidity, amount_out, False)
        else:
            return get_next_sqrt_price_from_amount0_rounding_up(sqrt_P_X96, liquidity, amount_out, False)
