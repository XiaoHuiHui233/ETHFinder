MIN_TICK = -887272
MAX_TICK = -MIN_TICK
MIN_SQRT_RATIO = 4295128739
MAX_SQRT_RATIO = 1461446703485210103287273052203988822378723970342


def get_sqrt_ratio_at_tick(tick: int) -> int:
    abs_tick = -tick if tick < 0 else tick

    if abs_tick > MAX_TICK:
        raise ValueError()

    ratio = 0xfffcb933bd6fad37aa2d162d1a594001 if abs_tick & 1 != 0 \
        else 0x100000000000000000000000000000000
    if abs_tick & 0x2 != 0:
        ratio = (ratio * 0xfff97272373d413259a46990580e213a) >> 128
    if abs_tick & 0x4 != 0:
        ratio = (ratio * 0xfff2e50f5f656932ef12357cf3c7fdcc) >> 128
    if abs_tick & 0x8 != 0:
        ratio = (ratio * 0xffe5caca7e10e4e61c3624eaa0941cd0) >> 128
    if abs_tick & 0x10 != 0:
        ratio = (ratio * 0xffcb9843d60f6159c9db58835c926644) >> 128
    if abs_tick & 0x20 != 0:
        ratio = (ratio * 0xff973b41fa98c081472e6896dfb254c0) >> 128
    if abs_tick & 0x40 != 0:
        ratio = (ratio * 0xff2ea16466c96a3843ec78b326b52861) >> 128
    if abs_tick & 0x80 != 0:
        ratio = (ratio * 0xfe5dee046a99a2a811c461f1969c3053) >> 128
    if abs_tick & 0x100 != 0:
        ratio = (ratio * 0xfcbe86c7900a88aedcffc83b479aa3a4) >> 128
    if abs_tick & 0x200 != 0:
        ratio = (ratio * 0xf987a7253ac413176f2b074cf7815e54) >> 128
    if abs_tick & 0x400 != 0:
        ratio = (ratio * 0xf3392b0822b70005940c7a398e4b70f3) >> 128
    if abs_tick & 0x800 != 0:
        ratio = (ratio * 0xe7159475a2c29b7443b29c7fa6e889d9) >> 128
    if abs_tick & 0x1000 != 0:
        ratio = (ratio * 0xd097f3bdfd2022b8845ad8f792aa5825) >> 128
    if abs_tick & 0x2000 != 0:
        ratio = (ratio * 0xa9f746462d870fdf8a65dc1f90e061e5) >> 128
    if abs_tick & 0x4000 != 0:
        ratio = (ratio * 0x70d869a156d2a1b890bb3df62baf32f7) >> 128
    if abs_tick & 0x8000 != 0:
        ratio = (ratio * 0x31be135f97d08fd981231505542fcfa6) >> 128
    if abs_tick & 0x10000 != 0:
        ratio = (ratio * 0x9aa508b5b7a84e1c677de54f3e99bc9) >> 128
    if abs_tick & 0x20000 != 0:
        ratio = (ratio * 0x5d6af8dedb81196699c329225ee604) >> 128
    if abs_tick & 0x40000 != 0:
        ratio = (ratio * 0x2216e584f5fa1ea926041bedfe98) >> 128
    if abs_tick & 0x80000 != 0:
        ratio = (ratio * 0x48a170391f7dc42444e8fa2) >> 128
    if tick > 0:
        ratio = (2**256 - 1) // ratio

    # this divides by 1<<32 rounding up to go from a Q128.128 to a Q128.96.
    # we then downcast because we know the result always fits within 160 bits
    # due to our tick input constraint
    # we round up in the division so getTickAtSqrtRatio of the output price is
    # always consistent
    sqrt_price_X96 = (ratio >> 32) + (0 if ratio % (1 << 32) == 0 else 1)
    return sqrt_price_X96


def get_tick_at_sqrt_ratio(sqrt_price_X96: int) -> int:
    # second inequality must be < because the price can never reach the price
    # at the max tick
    if sqrt_price_X96 < MIN_SQRT_RATIO or sqrt_price_X96 > MAX_SQRT_RATIO:
        raise ValueError()
    ratio = sqrt_price_X96 << 32

    r = ratio
    msb = 0
    f = 1 if r > 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF else 0
    f = f << 7
    msb = msb | f
    r = r >> f

    f = 1 if r > 0xFFFFFFFFFFFFFFFF else 0
    f = f << 6
    msb = msb | f
    r = r >> f

    f = 1 if r > 0xFFFFFFFF else 0
    f = f << 5
    msb = msb | f
    r = r >> f

    f = 1 if r > 0xFFFF else 0
    f = f << 4
    msb = msb | f
    r = r >> f

    f = 1 if r > 0xFF else 0
    f = f << 3
    msb = msb | f
    r = r >> f

    f = 1 if r > 0xF else 0
    f = f << 2
    msb = msb | f
    r = r >> f

    f = 1 if r > 0x3 else 0
    f = f << 1
    msb = msb | f
    r = r >> f

    f = 1 if r > 0x1 else 0
    msb = msb | f

    if (msb >= 128):
        r = ratio >> (msb - 127)
    else:
        r = ratio << (127 - msb)

    log_2 = (msb - 128) << 64

    for temp in range(63, 49, -1):
        r = r * r >> 127
        f = r >> 128
        log_2 = log_2 | (f << temp)
        r = r >> f

    # 128.128 number
    log_sqrt10001 = log_2 * 255738958999603826347141

    tick_low = (log_sqrt10001 - 3402992956809132418596140100660247210) >> 128
    tick_hi = (log_sqrt10001 + 291339464771989622907027621153398088495) >> 128

    tick = tick_low if tick_low == tick_hi else \
        tick_hi if get_sqrt_ratio_at_tick(tick_hi) <= sqrt_price_X96 else \
        tick_low
    return tick
