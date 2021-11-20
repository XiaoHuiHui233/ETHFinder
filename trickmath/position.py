from typing import Tuple

from .tick import get_sqrt_ratio_at_tick
from .sqrtprice import get_amount0_delta_with_signed
from .sqrtprice import get_amount1_delta_with_signed


def modify_position(
    tick_lower: int,
    tick_upper: int,
    liquidity_delta: int,
    sqrt_price_X96: int,
    tick: int
) -> Tuple[int, int]:
    if liquidity_delta != 0:
        if tick < tick_lower:
            # current tick is below the passed range; liquidity can only become
            # in range by crossing from left to
            # right, when we'll need _more_ token0 (it's becoming more
            # valuable) so user must provide it
            amount0 = get_amount0_delta_with_signed(
                get_sqrt_ratio_at_tick(tick_lower),
                get_sqrt_ratio_at_tick(tick_upper),
                liquidity_delta
            )
            amount1 = 0
        elif tick < tick_upper:
            # current tick is inside the passed range
            amount0 = get_amount0_delta_with_signed(
                sqrt_price_X96,
                get_sqrt_ratio_at_tick(tick_upper),
                liquidity_delta
            )
            amount1 = get_amount1_delta_with_signed(
                get_sqrt_ratio_at_tick(tick_lower),
                sqrt_price_X96,
                liquidity_delta
            )
        else:
            # current tick is above the passed range; liquidity can only become
            # in range by crossing from right to
            # left, when we'll need _more_ token1 (it's becoming more
            # valuable) so user must provide it
            amount0 = 0
            amount1 = get_amount1_delta_with_signed(
                get_sqrt_ratio_at_tick(tick_lower),
                get_sqrt_ratio_at_tick(tick_upper),
                liquidity_delta
            )
        return amount0, amount1


def burn(
    tick_lower: int,
    tick_upper: int,
    amount: int,
    sqrt_price_X96: int,
    tick: int
) -> Tuple[int, int]:
    amount0_int, amount1_int = modify_position(
        tick_lower, tick_upper, -amount, sqrt_price_X96, tick
    )
    amount0 = -amount0_int
    amount1 = -amount1_int
    return (amount0, amount1)
