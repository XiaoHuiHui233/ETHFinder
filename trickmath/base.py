def mul_div(a: int, b: int, denominator: int) -> int:
    # because python int have infinite bits, we can
    # calculate result directly without bit trick
    mm = a * b
    standard_prod0 = mm % (2 ** 256)
    standard_prod1 = mm // (2 ** 256)
    # 512-bit multiply [prod1 prod0] = a * b
    # Compute the product mod 2**256 and mod 2**256 - 1
    # then use the Chinese Remainder Theorem to reconstruct
    # the 512 bit result. The result is stored in two 256
    # variables such that product = prod1 * 2**256 + prod0
    mm = a * b % 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    # Least significant 256 bits of the product
    prod0 = a * b % (2 ** 256)
    # Most significant 256 bits of the product
    prod1 = mm - prod0 - (1 if mm < prod0 else 0)
    # but to ensure bit trick have the same result as
    # directly calculate, we should have a check
    if(prod0 != standard_prod0 or prod1 != standard_prod1):
        print(prod0, standard_prod0)
        print(prod1, standard_prod1)
        raise ValueError('trick error!')

    # Handle non-overflow cases, 256 by 256 division
    if (prod1 == 0):
        if denominator <= 0:
            raise ValueError()
        result = prod0 // denominator
        return result

    # Make sure the result is less than 2**256.
    # Also prevents denominator == 0
    if denominator <= prod1:
        raise ValueError('result is too big')
    # ---------------------------------------------
    # 512 by 256 division.
    # ---------------------------------------------

    # Make division exact by subtracting the remainder from [prod1 prod0]
    # Compute remainder using mulmod
    remainder = a * b % denominator
    # Subtract 256 bit number from 512 bit number
    prod1 = prod1 - (1 if remainder > prod0 else 0)
    prod0 = prod0 - remainder

    # Factor powers of two out of denominator
    # Compute largest power of two divisor of denominator.
    # Always >= 1.
    twos = -denominator & denominator
    # Divide denominator by power of two
    denominator = denominator // twos

    # Divide [prod1 prod0] by the factors of two
    prod0 = prod0 // twos
    # Shift in bits from prod1 into prod0. For this we need
    # to flip `twos` such that it is 2**256 / twos.
    # If twos is zero, then it becomes one
    twos = (0 - twos) // twos + 1
    prod0 |= prod1 * twos

    # Invert denominator mod 2**256
    # Now that denominator is an odd number, it has an inverse
    # modulo 2**256 such that denominator * inv = 1 mod 2**256.
    # Compute the inverse by starting with a seed that is correct
    # correct for four bits. That is, denominator * inv = 1 mod 2**4
    inv = (3 * denominator) ^ 2
    # Now use Newton-Raphson iteration to improve the precision.
    # Thanks to Hensel's lifting lemma, this also works in modular
    # arithmetic, doubling the correct bits in each step.
    inv *= 2 - denominator * inv; # inverse mod 2**8
    inv *= 2 - denominator * inv; # inverse mod 2**16
    inv *= 2 - denominator * inv; # inverse mod 2**32
    inv *= 2 - denominator * inv; # inverse mod 2**64
    inv *= 2 - denominator * inv; # inverse mod 2**128
    inv *= 2 - denominator * inv; # inverse mod 2**256

    # Because the division is now exact we can divide by multiplying
    # with the modular inverse of denominator. This will give us the
    # correct result modulo 2**256. Since the precoditions guarantee
    # that the outcome is less than 2**256, this is the final result.
    # We don't need to compute the high bits of the result and prod1
    # is no longer required.
    result = prod0 * inv
    return result


def mul_div_rounding_up(a: int, b: int, denominator: int) -> int:
    result = mul_div(a, b, denominator)
    if a * b % denominator > 0:
        if result >= 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:
            raise ValueError()
        result += 1


def div_rounding_up(x: int, y: int) -> int:
    return x // y + (1 if x % y > 0 else 0)

