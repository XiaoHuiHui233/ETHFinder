import sys

sys.path.append("../")

from pyuniswap import tick


# magic_number = (10 ** 12) * (2 ** 192)

# def conv(price: float) -> int:
#     t100 = int(price * 100)
#     return int(math.sqrt(t100 * (2**192))) // (10**7)

# a = get_sqrt_ratio_at_tick(184200)
# print(a)
# print(magic_number / (a * a))

# a = get_sqrt_ratio_at_tick(207240)
# print(a)
# print(magic_number / (a * a))

# c = get_tick_at_sqrt_ratio(a)
# print(c)
# print('----------------------------------')

a = tick.get_sqrt_ratio_at_tick(-193590)
# print(a)
b = a / (2**96)
c = b * b
# print(c)
# d = c * (10**12)
# print(d)
# print(a)
# magic_number = (10 ** 12) * (2 ** 192)
# print((a * a) // magic_number)
# sp = conv(3807.38)
# print(sp)
# tk = get_tick_at_sqrt_ratio(sp)
# print(tk)
# print(
#     burn(
#         -193590,
#         -191150,
#         18979928417637,
#         sp,
#         tk
#     )
# )

# # test
# cnt = 0
# for i in range(MIN_TICK, MAX_TICK + 1):
#     cnt += 1
#     if cnt % 10000 == 0:
#         print(cnt / 2 / MAX_TICK * 100, '%')
#     sr = get_sqrt_ratio_at_tick(i)
#     if i != get_tick_at_sqrt_ratio(sr):
#         raise ValueError(i)

# print(get_tick_at_sqrt_ratio(1637261839662082274827076810251933))

# print('----------------------------------')
# print(
#     burn(
#         184200,
#         207240,
#         309819542158801 + 107844134963126,
#         1637261839662082274827076810251933,
#         198734
#     )
# )
# t = 1637261839662082274827076810251933 / (2 ** 96)
# print(t)
# print(t * t)
# print('----------------------------------')
# print(int.from_bytes(bytes.fromhex(
#         "fffffffffffffffffffffffffffffffffffffffffffffffffffffee2f236561a"
#     ), byteorder='big', signed=True))
# print(int.from_bytes(bytes.fromhex(
#         "00000000000000000000000000000000000000000000001d471aa54807170000"
#     ), byteorder='big', signed=True))
# print(int.from_bytes(bytes.fromhex(
#         "00000000000000000000000000000000000051fa4af40d67c620c13caa45f01d"
#     ), byteorder='big', signed=True))
# print(int.from_bytes(bytes.fromhex(
#         "000000000000000000000000000000000000000000000000ff91fc0652a963da"
#     ), byteorder='big', signed=True))
# print(int.from_bytes(bytes.fromhex(
#         "0000000000000000000000000000000000000000000000000000000000030982"
#     ), byteorder='big', signed=True))

# for i in range(184200, 207200):
#     a = get_sqrt_ratio_at_tick(i) >> 96
#     b = get_sqrt_ratio_at_tick(i-1) >> 96
#     print((a * a) / (b * b))

# new = 0x44d29ce622b40de52cd4800f45f2
# old = 0x44d1bb65cb6097bb37985f30c037
# liquid = 0x1336bff4e5b71542a
# magic_number = (10**12) * (2**192)
# new_price = magic_number / (new*new)
# old_price = magic_number / (old*old)
# delta_price = new_price - old_price
# print(new_price, old_price, delta_price)

# print(get_amount1_delta(new, old, liquid, True))

pa = 4410891813269210046787536
pb = 5104229933688966249757389
pc = 4551360343611603677725893

x = 125167156
y = 124892799737916377
l = 67203530580679

print(l * (pb - pc) >> 96)
print(l * (pc - pa) >> 96)
