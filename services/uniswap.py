

UNISWAP_V3_ADDRESS = bytes.fromhex("8ad599c3a0ff1de082011efddc58f1908eb6e6d8")
UNISWAP_V3_TOPIC = bytes.fromhex(
    "c42079f94a6350d7e6235f29174924f928cc2ac818eb64fed8004e115fbcca67"
)

  async def waiting_for_receipts(
        self,
        rckey: str,
        block_ts: int,
        receive_ts: int,
        height: int,
        hash: bytes
    ) -> None:
        if height <= self.last_receipt_block:
            return
        if rckey not in self.handlers:
            return
        promise = await self.handlers[rckey].send_get_default(
            MESSAGE_CODES.RECEIPTS, [hash]
        )
        if promise is None:
            return
        with trio.move_on_after(opts.MSG_TIMEOUT) as cancel_scope:
            await promise.wait()
        if height <= self.last_receipt_block:
            return
        if cancel_scope.cancelled_caught and not promise.is_set():
            logger.warn(f"Waiting for receipts timeout from {rckey}.")
            return
        result = promise.get_result()
        if not result:
            logger.warn(f"received empty receipts from {rckey}.")
            return
        if len(result) > 1:
            logger.warn(f"received too many receipts from {rckey}.")
            return
        receipts = result[0]
        total_amount0 = 0
        total_amount1 = 0
        flag = False
        for receipt in receipts:
            if isinstance(receipt, bytes):
                if receipt[0] >= 0x80:
                    logger.warn(
                        f"Error on the format of received receipt"
                        f" from {rckey}."
                    )
                    continue
                typed_receipt = rlp.decode(receipt[1:])
                if receipt[0] == 0x01:  # eip-2930
                    logs = typed_receipt[3]
                elif receipt[0] == 0x02:  # eip-1559
                    logs = typed_receipt[3]
                else:
                    logger.warn(
                        f"Error on the type of received typed-receipt"
                        f" from {rckey}."
                    )
                    continue
            else:
                logs = receipt[3]
            for log in logs:
                if log[0] != UNISWAP_V3_ADDRESS:
                    continue
                if log[1][0] != UNISWAP_V3_TOPIC:
                    continue
                amount0 = int.from_bytes(log[2][:32], "big", signed=True)
                amount1 = int.from_bytes(log[2][32:64], "big", signed=True)
                sqrt_price = int.from_bytes(log[2][64:96], "big", signed=True)
                liquidity = int.from_bytes(log[2][96:128], "big", signed=True)
                tick = int.from_bytes(log[2][128:160], "big", signed=True)
                logger.info("Found uniswap log.")
                logger.info(f"Amount0: {amount0}, Amount1: {amount1}")
                logger.info(f"Sqrt price: {sqrt_price}, tick: {tick}")
                total_amount0 += amount0
                total_amount1 += amount1
                flag = True
        if flag:
            balance0, balance1 = calc_burn(sqrt_price, tick)
            logger.info(
                f"Total amount({height}): {total_amount0}, {total_amount1}"
            )
            logger.info(f"Balance({height}): {balance0}, {balance1}")
            try:
                self.channel.put_nowait({
                    "type": "uniswap",
                    "block_ts": block_ts,
                    "receive_ts": receive_ts,
                    "hash": hash,
                    "height": height,
                    "balance0": balance0,
                    "balance1": balance1,
                    "amount0": total_amount0,
                    "amount1": total_amount1,
                    "sqrt_price": sqrt_price,
                    "liquidity": liquidity,
                    "tick": tick
                })
            except Exception:
                logger.warn("Failed to put uniswap signal to channel.")
            self.last_receipt_block = height
            self.last_receipt_block_hash = hash