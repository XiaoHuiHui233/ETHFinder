from .base import mul_div, mul_div_rounding_up
from .sqrtprice import get_amount0_delta, get_amount1_delta
from .sqrtprice import get_next_sqrt_price_from_input
from .sqrtprice import get_next_sqrt_price_from_output


def compute_swap_step(
    sqrt_ratio_current_X96: int,
    sqrt_ratio_target_X96: int,
    liquidity: int,
    amount_remaining: int,
    fee_pips: int
) -> tuple[int, int, int, int]:
    zero_for_one = sqrt_ratio_current_X96 >= sqrt_ratio_target_X96
    exact_in = amount_remaining >= 0
    if exact_in:
        amount_remaining_less_fee = mul_div(
            amount_remaining, 1e6 - fee_pips, 1e6
        )
        if zero_for_one:
            amount_in = get_amount0_delta(
                sqrt_ratio_target_X96, sqrt_ratio_current_X96, liquidity, True
            )
        else:
            amount_in = get_amount1_delta(
                sqrt_ratio_current_X96, sqrt_ratio_target_X96, liquidity, True
            )
        if amount_remaining_less_fee >= amount_in:
            sqrt_ratio_next_X96 = sqrt_ratio_target_X96
        else:
            sqrt_ratio_next_X96 = get_next_sqrt_price_from_input(
                sqrt_ratio_current_X96,
                liquidity,
                amount_remaining_less_fee,
                zero_for_one
            )
    else:
        if zero_for_one:
            amount_out = get_amount1_delta(
                sqrt_ratio_target_X96,
                sqrt_ratio_current_X96,
                liquidity,
                False
            )
        else:
            amount_out = get_amount0_delta(
                sqrt_ratio_current_X96,
                sqrt_ratio_target_X96,
                liquidity,
                False
            )
        if -amount_remaining >= amount_out:
            sqrt_ratio_next_X96 = sqrt_ratio_target_X96
        else:
            sqrt_ratio_next_X96 = get_next_sqrt_price_from_output(
                sqrt_ratio_current_X96,
                liquidity,
                -amount_remaining,
                zero_for_one
            )
    max = sqrt_ratio_target_X96 == sqrt_ratio_next_X96

    # get the input/output amounts
    if zero_for_one:
        if not max or not exact_in:
            amount_in = get_amount0_delta(
                sqrt_ratio_next_X96, sqrt_ratio_current_X96, liquidity, True
            )
        if not max or exact_in:
            amount_out = get_amount1_delta(
                sqrt_ratio_next_X96, sqrt_ratio_current_X96, liquidity, False
            )
    else:
        if not max or not exact_in:
            amount_in = get_amount1_delta(
                sqrt_ratio_current_X96, sqrt_ratio_next_X96, liquidity, True
            )
        if not max or exact_in:
            amount_out = get_amount0_delta(
                sqrt_ratio_current_X96, sqrt_ratio_next_X96, liquidity, False
            )

        # cap the output amount to not exceed the remaining output amount
        if not exact_in and amount_out > -amount_remaining:
            amount_out = -amount_remaining

        if exact_in and sqrt_ratio_next_X96 != sqrt_ratio_target_X96:
            # we didn't reach the target, so take the remainder of the maximum
            # input as fee
            fee_amount = amount_remaining - amount_in
        else:
            fee_amount = mul_div_rounding_up(
                amount_in, fee_pips, 1e6 - fee_pips
            )
    return sqrt_ratio_next_X96, amount_in, amount_out, fee_amount
