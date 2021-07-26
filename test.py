import random

from trickmath.tick import get_sqrt_ratio_at_tick, get_tick_at_sqrt_ratio, MIN_TICK, MAX_TICK
from trickmath.position import burn
from trickmath.base import mul_div


a = get_sqrt_ratio_at_tick(184200)
print(a)
b = a / (2**96)
print(b)
print(b * b)


c = get_tick_at_sqrt_ratio(a)
print(c)
print('----------------------------------')

# # test
# cnt = 0
# for i in range(MIN_TICK, MAX_TICK + 1):
#     cnt += 1
#     if cnt % 10000 == 0:
#         print(cnt / 2 / MAX_TICK * 100, '%')
#     sr = get_sqrt_ratio_at_tick(i)
#     if i != get_tick_at_sqrt_ratio(sr):
#         raise ValueError(i)

print(get_tick_at_sqrt_ratio(1637261839662082274827076810251933))

print(
    burn(
        184200,
        207240,
        309819542158801 + 107844134963126,
        1637261839662082274827076810251933,
        198734
    )
)