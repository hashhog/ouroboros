"""Bitcoin Core assumevalid: which blocks may connect without script checks.

Core's rule (validation.cpp, ``Chainstate::ConnectBlock``): script checks are
skipped for a block only when ALL of these hold, otherwise they run.

1. assumevalid is not disabled (``-assumevalid=0``) and the network has a
   default assumevalid block (``consensus.defaultAssumeValid``).
2. The assumevalid block is in the header index.
3. The block is an ancestor of the assumevalid block.
4. The block is an ancestor of the best header.
5. The best header has at least ``nMinimumChainWork``.
6. The best header is more than two weeks of equivalent proof-of-work past
   the block (``GetBlockProofEquivalentTime`` > ``TWO_WEEKS_IN_SECONDS``).

Height alone is not one of them.  A block at a low height on a branch that
does not lead to the assumevalid block is fully script-checked by Core.

ouroboros keeps a bounded window of headers ahead of its tip (the validated
header queue), not every header back to genesis, so it cannot always look the
assumevalid block up the way Core does.  It proves rule 3 with
``MAINNET_ANCESTOR_PINS`` instead: hashes of the assumevalid block's own
ancestors, one every 10,000 blocks.  A block whose header chain reaches a pin
at or above its height is an ancestor of that pin, and so of the assumevalid
block.  Pins are not checkpoints: no header or block is ever rejected for not
matching one.  A block that does not reach a pin only loses the script skip.

Every pin was read from Bitcoin Core v31 (``getblockhash <height>``) on a
chain whose active tip descends from the assumevalid block below, so each is
that block's ancestor at its height.  Only mainnet has an assumevalid block
here.  Other networks always check scripts, which is stricter than Core (Core
also ships defaults for testnet3, testnet4 and signet).
"""

from __future__ import annotations

import bisect
from dataclasses import dataclass

TWO_WEEKS_IN_SECONDS = 60 * 60 * 24 * 7 * 2
POW_TARGET_SPACING = 10 * 60

# Bitcoin Core v31 kernel/chainparams.cpp, CMainParams:
#   consensus.defaultAssumeValid = 00000000000000000000ccebd6d74d9194d8dcdc1d177c478e094bfad51ba5ac; // 938343
MAINNET_ASSUMEVALID_HEIGHT = 938_343
MAINNET_ASSUMEVALID_HASH = "00000000000000000000ccebd6d74d9194d8dcdc1d177c478e094bfad51ba5ac"

# Ancestors of MAINNET_ASSUMEVALID_HASH, in RPC (display) byte order.
MAINNET_ANCESTOR_PINS: dict[int, str] = {
    10000: "0000000099c744455f58e6c6e98b671e1bf7f37346bfd4cf5d0274ad8ee660cb",
    20000: "00000000770ebe897270ca5f6d539d8afb4ea4f4e757761a34ca82e17207d886",
    30000: "00000000de1250dc2df5cf4d877e055f338d6ed1ab504d5b71c097cdccd00e13",
    40000: "00000000504d5fa0ad2cb90af16052a4eb2aea70fa1cba653b90a4583c5193e4",
    50000: "000000001aeae195809d120b5d66a39c83eb48792e068f8ea1fea19d84a4278a",
    60000: "000000000b554c46f8eb7264d7d5e334382c6fc3098dabf734de37962ccd7495",
    70000: "00000000002b8cd0faa58444df3ba2a22af2b5838c7e4a5b687444f913a575c2",
    80000: "000000000043a8c0fd1d6f726790caa2a406010d19efd2780db27bdbbd93baf6",
    90000: "0000000000071694daf735a6b5da101d77a04c7e6008c680e461f0025ba7b7af",
    100000: "000000000003ba27aa200b1cecaad478d2b00432346c3f1f3986da1afd33e506",
    110000: "000000000001bbda3f22ef8e476b470a2d3ae16821c23a6d22db77318d0799a9",
    120000: "0000000000000e07595fca57b37fea8522e95e0f6891779cfd34d7e537524471",
    130000: "00000000000011906b491883ab0f16f0e690b133ca860b199b775c3cf6581c21",
    140000: "000000000000086e28cf4717a80066def0ec26c53d660582bd997221fef297db",
    150000: "0000000000000a3290f20e75860d505ce0e948a1d1d846bec7e39015d242884b",
    160000: "000000000000066c6e629b2fb49c7fcc52b82fe9833f328e0c3943856facf231",
    170000: "000000000000051f68f43e9d455e72d9c4e4ce52e8a00c5e24c07340632405cb",
    180000: "00000000000004ff83b6c10460b239ef4a6aa320e5fffd6c7bcedefa8c78593c",
    190000: "0000000000000708bf3b261ffc963b6a768d915f9cfc9ec0a6c2a09969efad1a",
    200000: "000000000000034a7dedef4a161fa058a2d67a173a90155f3a2fe6fc132e0ebf",
    210000: "000000000000048b95347e83192f69cf0366076336c639f9b7228e9ba171342e",
    220000: "000000000000002fdd2c741ed50bc3975a640ca419081711f30f553939641303",
    230000: "000000000000012cfb19f5662707816e122ad60dd9b1cd646c6c9899be2c9667",
    240000: "000000000000000e7ad69c72afc00dc4e05fc15ae3061c47d3591d07c09f2928",
    250000: "000000000000003887df1f29024b06fc2200b55f8af8f35453d7be294df2d214",
    260000: "000000000000001fb91fbcebaaba0e2d926f04908d798a8b598c3bd962951080",
    270000: "0000000000000002a775aec59dc6a9e4bb1c025cf1b8c2195dd9dc3998c827c5",
    280000: "0000000000000001c091ada69f444dc0282ecaabe4808ddbb2532e5555db0c03",
    290000: "0000000000000000fa0b2badd05db0178623ebf8dd081fe7eb874c26e27d0b3b",
    300000: "000000000000000082ccf8f1557c5d40b21edabb18d2d691cfbf87118bac7254",
    310000: "0000000000000000125a28cc9e9209ddb75718f599a8039f6c9e7d9f1fb021e0",
    320000: "000000000000000015aab005b28a326ade60f07515c33517ea5cb598f28fb7ea",
    330000: "00000000000000000faabab19f17c0178c754dbed023e6c871dcaf74159c5f02",
    340000: "00000000000000000d9b2508615d569e18f00c034d71474fc44a43af8d4a5003",
    350000: "0000000000000000053cf64f0400bb38e0c4b3872c38795ddde27acb40a112bb",
    360000: "00000000000000000ca6e07cf681390ff888b7f96790286a440da0f2b87c8ea6",
    370000: "000000000000000002cad3026f68357229dd6eaa6bcef6fe5166e1e53b039b8c",
    380000: "00000000000000000b06cee3cee10d2617e2024a996f5c613f7d786b15a571ff",
    390000: "00000000000000000520000e60b56818523479ada2614806ba17ce0bbe6eaded",
    400000: "000000000000000004ec466ce4732fe6f1ed1cddc2ed4b328fff5224276e3f6f",
    410000: "0000000000000000060d7ea100ecb75c0a4dc482d05ff19ddaa8046b4b80a458",
    420000: "000000000000000002cce816c0ab2c5c269cb081896b7dcb34b8422d6b74ffa1",
    430000: "000000000000000001868b2bb3a285f3cc6b33ea234eb70facf4dcdf22186b87",
    440000: "0000000000000000038cc0f7bcdbb451ad34a458e2d535764f835fdeb896f29b",
    450000: "0000000000000000014083723ed311a461c648068af8cef8a19dcd620c07a20b",
    460000: "000000000000000000ef751bbce8e744ad303c47ece06c8d863e4d417efc258c",
    470000: "0000000000000000006c539c722e280a0769abd510af0073430159d71e6d7589",
    480000: "000000000000000001024c5d7a766b173fc9dbb1be1a4dc7e039e631fd96a8b1",
    490000: "000000000000000000de069137b17b8d5a3dfbd5b145b2dcfb203f15d0c4de90",
    500000: "00000000000000000024fb37364cbf81fd49cc2d51c09c75c35433c3a1945d04",
    510000: "000000000000000000152678f83ec36b6951ed3f7e1cc3b04c5828cab8017329",
    520000: "0000000000000000000d26984c0229c9f6962dc74db0a6d525f2f1640396f69c",
    530000: "000000000000000000024e9be1c7b56cab6428f07920f21ad8457221a91371ae",
    540000: "00000000000000000011b3e92e82e0f9939093dccc3614647686c20e5ebe3aa6",
    550000: "000000000000000000223b7a2298fb1c6c75fb0efc28a4c56853ff4112ec6bc9",
    560000: "0000000000000000002c7b276daf6efb2b6aa68e2ce3be67ef925b3264ae7122",
    570000: "0000000000000000000822cf76247f1ecec0a82dbecb3b482ec4d2d154e0cd1d",
    580000: "00000000000000000003a93e72663961c2449dd1c92a004d39a6ff0df4ac72a3",
    590000: "000000000000000000061610767eaa0394cab83c70ff1c09dd6b2a2bdad5d1d1",
    600000: "00000000000000000007316856900e76b4f7a9139cfbfba89842c8d196cd5f91",
    610000: "0000000000000000000a6f607f74db48dae0a94022c10354536394c17672b7f7",
    620000: "0000000000000000000a9fae27289c097e69ca79f54183cae5b52a5e5a3c4cfa",
    630000: "000000000000000000024bead8df69990852c202db0e0097c1a12ea637d7e96d",
    640000: "0000000000000000000b3021a283b981dd08f4ccf318b684b214f995d102af43",
    650000: "0000000000000000000060e32d547b6ae2ded52aadbc6310808e4ae42b08cc6a",
    660000: "00000000000000000008eddcaf078f12c69a439dde30dbb5aac3d9d94e9c18f6",
    670000: "0000000000000000000411ab5253403532ca82aa6cfe164b4261829155a919f4",
    680000: "000000000000000000076c036ff5119e5a5a74df77abf64203473364509f7732",
    690000: "00000000000000000002a23d6df20eecec15b21d32c75833cce28f113de888b7",
    700000: "0000000000000000000590fc0f3eba193a278534220b2b37e9849e1a770ca959",
    710000: "00000000000000000007822e1ddba0bed6a55f0072aa1584c70a2f81c275f587",
    720000: "00000000000000000000664d48a530c8a9047ae31f6ba81ff5c49c22072d4536",
    730000: "0000000000000000000384f28cb3b9cf4377a39cfd6c29ae9466951de38c0529",
    740000: "00000000000000000005f28764680afdbd8375216ff8f30b17eeb26bd98aac63",
    750000: "0000000000000000000592a974b1b9f087cb77628bb4a097d5c2c11b3476a58e",
    760000: "00000000000000000003e1d91b245eb32787afb10afe49b61621375361221c38",
    770000: "00000000000000000004ea65f5ffe55bfc0adbc001d3a8e154cc9f19da959ba8",
    780000: "00000000000000000000b0e5e00e6cd256aa03b58f01454ebe2f2c63c750a421",
    790000: "00000000000000000001ba9dc00c25c451516958a640a0c4c556a291bbf9d63e",
    800000: "00000000000000000002a7c4c1e48d76c5a37902165a270156b7a8d72728a054",
    810000: "000000000000000000028028ca82b6aa81ce789e4eb9e0321b74c3cbaf405dd1",
    820000: "00000000000000000000ba232574c32b4f0cd023e133c05125310625626d6571",
    830000: "000000000000000000011d55599ed27d7efca05f5849b755319c89eb2cffbc1f",
    840000: "0000000000000000000320283a032748cef8227873ff4872689bf23f1cda83a5",
    850000: "00000000000000000002a0b5db2a7f8d9087464c2586b546be7bce8eb53b8187",
    860000: "0000000000000000000095dd5c0c8e176a6498eb335c491b96df1a1ae178bfbd",
    870000: "0000000000000000000152dd9d6059126e4e4dbc2732246bef2b8496ef1d971d",
    880000: "000000000000000000010b17283c3c400507969a9c2afd1dcf2082ec5cca2880",
    890000: "00000000000000000001f49fb5fb37753c06d78f1a811d707aebf6194bb147e5",
    900000: "000000000000000000010538edbfd2d5b809a33dd83f284aeea41c6d0d96968a",
    910000: "0000000000000000000108970acb9522ffd516eae17acddcb1bd16469194a821",
    920000: "000000000000000000005e9de5d9e008d923ced659896d9ad012e347882bdc87",
    930000: "00000000000000000000df0f80044130bb616de91fb0a1d61f27cdcf20458233",
}


def _internal(display_hex: str) -> bytes:
    """RPC display order -> the internal byte order block hashes use here."""
    return bytes.fromhex(display_hex)[::-1]


@dataclass(frozen=True)
class AssumeValidParams:
    height: int
    block_hash: bytes  # internal byte order
    pin_heights: tuple[int, ...]  # sorted, includes ``height``
    pins: dict[int, bytes]  # height -> internal-order hash, includes the block


def _build_mainnet() -> AssumeValidParams:
    pins = {h: _internal(x) for h, x in MAINNET_ANCESTOR_PINS.items()}
    pins[MAINNET_ASSUMEVALID_HEIGHT] = _internal(MAINNET_ASSUMEVALID_HASH)
    return AssumeValidParams(
        height=MAINNET_ASSUMEVALID_HEIGHT,
        block_hash=pins[MAINNET_ASSUMEVALID_HEIGHT],
        pin_heights=tuple(sorted(pins)),
        pins=pins,
    )


_MAINNET = _build_mainnet()


def params_for(network: str) -> AssumeValidParams | None:
    """The default assumevalid block for *network*, or None (always verify)."""
    if str(network).lower() in ("mainnet", "main", "bitcoin"):
        return _MAINNET
    return None


def pin_at_or_above(params: AssumeValidParams, height: int) -> tuple[int, bytes] | None:
    """Lowest pin at or above *height*, or None when *height* is above the
    assumevalid block."""
    i = bisect.bisect_left(params.pin_heights, height)
    if i >= len(params.pin_heights):
        return None
    h = params.pin_heights[i]
    return h, params.pins[h]


def proof_equivalent_time(best_work: int, block_work: int, best_block_proof: int) -> int:
    """Core ``GetBlockProofEquivalentTime(best, block, best)`` for best >= block:
    seconds the work between them would take at the best header's difficulty."""
    if best_block_proof <= 0:
        return 0
    r = (best_work - block_work) * POW_TARGET_SPACING // best_block_proof
    return min(r, (1 << 63) - 1)
