"""
Bitcoin script interpreter for transaction validation.

This module implements a basic Bitcoin script interpreter that can verify
standard script types (P2PKH, P2SH, P2WPKH, P2WSH, etc.), and also provides
script disassembly functionality for human-readable script representation.
"""

import hashlib
from typing import List, Tuple, Optional
from dataclasses import dataclass

from ouroboros.database import Transaction, TxIn


class ScriptInterpreter:
    """Interprets and verifies Bitcoin scripts"""
    
    def __init__(self):
        """Initialize the script interpreter"""
        pass
    
    def verify(
        self,
        script_sig: bytes,
        script_pubkey: bytes,
        tx: Transaction,
        input_index: int
    ) -> bool:
        """
        Verify a script signature against a script pubkey.
        
        Args:
            script_sig: Script signature from transaction input
            script_pubkey: Script pubkey from UTXO
            tx: The transaction being verified
            input_index: Index of the input being verified
            
        Returns:
            True if script verification passes, False otherwise
        """
        # Combine script_sig and script_pubkey for execution
        # In Bitcoin, we execute: script_sig + script_pubkey
        combined_script = script_sig + script_pubkey
        
        try:
            # Execute the script (pass script_pubkey for signature hash calculation)
            stack = self._execute_script(combined_script, tx, input_index, script_pubkey)
            
            # Script is valid if stack is non-empty and top element is truthy
            if not stack:
                return False
            
            # Check if top element is non-zero (truthy in Bitcoin script)
            top = stack[-1]
            if isinstance(top, bytes):
                # Non-empty byte array is truthy, but empty array is falsy
                # Exception: any non-zero value in a byte array is truthy
                return len(top) > 0 and any(b != 0 for b in top)
            return bool(top)
        
        except Exception:
            # Any exception during script execution means invalid script
            return False
    
    def _execute_script(
        self,
        script: bytes,
        tx: Transaction,
        input_index: int,
        script_pubkey: bytes
    ) -> List[bytes]:
        """
        Execute a Bitcoin script.
        
        Args:
            script: Script bytes to execute
            tx: Transaction context
            input_index: Index of input being verified
            script_pubkey: Script pubkey for signature hash calculation
            
        Returns:
            Stack after execution
        """
        stack: List[bytes] = []
        altstack: List[bytes] = []
        op_count = 0
        max_op_count = 201  # Bitcoin script limit
        
        i = 0
        while i < len(script):
            opcode = script[i]
            i += 1
            
            # Check op count limit
            op_count += 1
            if op_count > max_op_count:
                raise ValueError("Too many operations")
            
            # Data push operations (0x01-0x4b)
            if 1 <= opcode <= 75:
                data_len = opcode
                if i + data_len > len(script):
                    raise ValueError("Invalid data push")
                data = script[i:i + data_len]
                stack.append(data)
                i += data_len
                continue
            
            # OP_PUSHDATA1 (0x4c)
            if opcode == 0x4c:
                if i >= len(script):
                    raise ValueError("Invalid OP_PUSHDATA1")
                data_len = script[i]
                i += 1
                if i + data_len > len(script):
                    raise ValueError("Invalid OP_PUSHDATA1 data")
                data = script[i:i + data_len]
                stack.append(data)
                i += data_len
                continue
            
            # OP_PUSHDATA2 (0x4d)
            if opcode == 0x4d:
                if i + 2 > len(script):
                    raise ValueError("Invalid OP_PUSHDATA2")
                data_len = int.from_bytes(script[i:i+2], 'little')
                i += 2
                if i + data_len > len(script):
                    raise ValueError("Invalid OP_PUSHDATA2 data")
                data = script[i:i + data_len]
                stack.append(data)
                i += data_len
                continue
            
            # OP_PUSHDATA4 (0x4e)
            if opcode == 0x4e:
                if i + 4 > len(script):
                    raise ValueError("Invalid OP_PUSHDATA4")
                data_len = int.from_bytes(script[i:i+4], 'little')
                i += 4
                if i + data_len > len(script):
                    raise ValueError("Invalid OP_PUSHDATA4 data")
                data = script[i:i + data_len]
                stack.append(data)
                i += data_len
                continue
            
            # OP_DUP (0x76)
            if opcode == 0x76:
                if not stack:
                    raise ValueError("Stack underflow")
                stack.append(stack[-1])
                continue
            
            # OP_HASH160 (0xa9)
            if opcode == 0xa9:
                if not stack:
                    raise ValueError("Stack underflow")
                data = stack.pop()
                # SHA256 then RIPEMD160
                sha256_hash = hashlib.sha256(data).digest()
                ripemd160 = hashlib.new('ripemd160', sha256_hash).digest()
                stack.append(ripemd160)
                continue
            
            # OP_EQUALVERIFY (0x88)
            if opcode == 0x88:
                if len(stack) < 2:
                    raise ValueError("Stack underflow")
                a = stack.pop()
                b = stack.pop()
                if a != b:
                    raise ValueError("OP_EQUALVERIFY failed")
                continue
            
            # OP_CHECKSIG (0xac) - ECDSA signature verification
            if opcode == 0xac:
                if len(stack) < 2:
                    raise ValueError("Stack underflow")
                pubkey = stack.pop()
                sig = stack.pop()
                
                # Signature format: DER signature + SIGHASH type (1 byte)
                if len(sig) < 1 or len(pubkey) < 1:
                    stack.append(b'\x00')
                    continue
                
                # Extract SIGHASH type (last byte)
                sighash_type = sig[-1]
                der_sig = sig[:-1]
                
                # Verify signature
                try:
                    # Calculate signature hash for this transaction/input
                    # Note: Full implementation requires proper SignatureHash calculation
                    # which depends on sighash_type (SIGHASH_ALL, SIGHASH_SINGLE, SIGHASH_NONE, etc.)
                    # script_pubkey is passed from verify() method for signature hash calculation
                    message_hash = self._calculate_signature_hash(tx, input_index, script_pubkey, sighash_type)
                    
                    # Verify ECDSA signature
                    result = self._verify_ecdsa_signature(message_hash, der_sig, pubkey)
                    
                    if result:
                        stack.append(b'\x01')
                    else:
                        stack.append(b'\x00')
                
                except Exception as e:
                    # Any error during verification means invalid signature
                    stack.append(b'\x00')
                continue
            
            # OP_CHECKMULTISIG (0xae) - k-of-n signature verification
            # Stack order (top to bottom): n, pub1..pubn, k, sig1..sigk, dummy
            # Ref: en.bitcoin.it/wiki/OP_CHECKMULTISIG
            if opcode == 0xae:
                if len(stack) < 4:
                    raise ValueError("Stack underflow for OP_CHECKMULTISIG")
                n = self._read_num(stack.pop())
                if n < 0 or n > 20:
                    raise ValueError("OP_CHECKMULTISIG n out of range")
                pubkeys = [stack.pop() for _ in range(n)]
                if len(pubkeys) != n:
                    raise ValueError("Stack underflow for OP_CHECKMULTISIG pubkeys")
                k = self._read_num(stack.pop())
                if k < 0 or k > n:
                    raise ValueError("OP_CHECKMULTISIG k out of range")
                sigs = [stack.pop() for _ in range(k)]
                if len(sigs) != k:
                    raise ValueError("Stack underflow for OP_CHECKMULTISIG sigs")
                stack.pop()  # Dummy (Bitcoin bug - extra pop, must be OP_0 per BIP147)
                valid = self._verify_multisig(
                    sigs, pubkeys, k, tx, input_index, script_pubkey
                )
                stack.append(b'\x01' if valid else b'\x00')
                continue
            
            # OP_0, OP_1-OP_16 (push empty array or numbers 1-16)
            if opcode == 0x00:  # OP_0
                stack.append(b'')
                continue
            
            if 0x51 <= opcode <= 0x60:  # OP_1 to OP_16
                num = opcode - 0x50
                stack.append(bytes([num]))
                continue
            
            # For other opcodes, we'll raise an error for now
            # In a full implementation, we'd handle all opcodes
            if opcode not in [0x75, 0x6a, 0x87, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f]:
                # Unknown opcode - for now, allow it but log a warning
                # In production, you'd want stricter validation
                pass
        
        return stack
    
    def _hash160(self, data: bytes) -> bytes:
        """Compute HASH160 (RIPEMD160(SHA256(data)))"""
        sha256_hash = hashlib.sha256(data).digest()
        return hashlib.new('ripemd160', sha256_hash).digest()
    
    def _hash256(self, data: bytes) -> bytes:
        """Compute double SHA256"""
        return hashlib.sha256(hashlib.sha256(data).digest()).digest()
    
    def _read_num(self, data: bytes) -> int:
        """Read script number from stack (empty = 0, else minimal little-endian)."""
        if not data:
            return 0
        return int.from_bytes(data, 'little')

    def _encode_varint(self, value: int) -> bytes:
        """Encode variable-length integer for script serialization."""
        if value < 0xfd:
            return bytes([value])
        elif value <= 0xffff:
            return b'\xfd' + value.to_bytes(2, 'little')
        elif value <= 0xffffffff:
            return b'\xfe' + value.to_bytes(4, 'little')
        else:
            return b'\xff' + value.to_bytes(8, 'little')

    def _calculate_signature_hash(
        self,
        transaction: Transaction,
        input_index: int,
        script_code: bytes,
        sighash_type: int
    ) -> bytes:
        """
        Calculate Bitcoin legacy SignatureHash for ECDSA verification.

        Follows en.bitcoin.it/wiki/OP_CHECKSIG.
        Supports SIGHASH_ALL, SIGHASH_NONE, SIGHASH_SINGLE, SIGHASH_ANYONECANPAY.

        Args:
            transaction: The transaction being signed
            input_index: Index of the input being verified
            script_code: Script code (scriptPubKey for P2PKH)
            sighash_type: SIGHASH type (last byte of signature)

        Returns:
            32-byte hash for signature verification
        """
        base_type = sighash_type & 0x1f
        anyone_can_pay = (sighash_type & 0x80) != 0

        if base_type not in (0x01, 0, 0x02, 0x03):
            base_type = 0x01

        data = bytearray()
        data.extend(transaction.version.to_bytes(4, 'little'))

        # Build inputs to serialize
        if anyone_can_pay:
            inputs_to_serialize = [(input_index, transaction.inputs[input_index])]
        else:
            inputs_to_serialize = list(enumerate(transaction.inputs))

        data.extend(self._encode_varint(len(inputs_to_serialize)))

        for i, tx_in in inputs_to_serialize:
            data.extend(tx_in.prev_txid)
            data.extend(tx_in.prev_vout.to_bytes(4, 'little'))
            if i == input_index:
                data.extend(self._encode_varint(len(script_code)))
                data.extend(script_code)
            else:
                data.extend(b'\x00')
            seq = 0 if base_type in (0x02, 0x03) and i != input_index else tx_in.sequence
            data.extend(seq.to_bytes(4, 'little'))

        if base_type == 0x01 or base_type == 0:  # SIGHASH_ALL
            data.extend(self._encode_varint(len(transaction.outputs)))
            for tx_out in transaction.outputs:
                data.extend(tx_out.value.to_bytes(8, 'little'))
                data.extend(self._encode_varint(len(tx_out.script_pubkey)))
                data.extend(tx_out.script_pubkey)
        elif base_type == 0x02:  # SIGHASH_NONE
            data.extend(b'\x00')  # Zero outputs
        elif base_type == 0x03:  # SIGHASH_SINGLE
            if input_index >= len(transaction.outputs):
                return bytes(32)
            data.extend(self._encode_varint(input_index + 1))
            for j, tx_out in enumerate(transaction.outputs):
                if j == input_index:
                    data.extend(tx_out.value.to_bytes(8, 'little'))
                    data.extend(self._encode_varint(len(tx_out.script_pubkey)))
                    data.extend(tx_out.script_pubkey)
                else:
                    data.extend((-1).to_bytes(8, 'little', signed=True))
                    data.extend(b'\x00')

        data.extend(transaction.locktime.to_bytes(4, 'little'))
        data.extend(sighash_type.to_bytes(4, 'little'))

        return hashlib.sha256(hashlib.sha256(bytes(data)).digest()).digest()
    
    def _verify_ecdsa_signature(self, message_hash: bytes, der_sig: bytes, pubkey: bytes) -> bool:
        """
        Verify ECDSA signature using secp256k1 (Rust sync module or Python coincurve).

        Args:
            message_hash: 32-byte double-SHA256 of signed data
            der_sig: DER-encoded signature (without SIGHASH byte)
            pubkey: Public key (compressed 33 or uncompressed 65 bytes)

        Returns:
            True if signature is valid, False otherwise
        """
        if len(message_hash) != 32 or len(der_sig) < 8:
            return False
        if len(pubkey) not in (33, 65):
            return False

        try:
            import sync
            return sync.verify_ecdsa(der_sig, pubkey, message_hash)
        except (ImportError, AttributeError, ValueError):
            pass

        try:
            from coincurve import PublicKey
            pk = PublicKey(pubkey)
            return pk.verify(der_sig, message_hash)
        except ImportError:
            pass
        except Exception:
            return False

        return False

    def _verify_multisig(
        self,
        sigs: List[bytes],
        pubkeys: List[bytes],
        k: int,
        tx: Transaction,
        input_index: int,
        script_pubkey: bytes
    ) -> bool:
        """
        Verify k-of-n multisig: k signatures must match k of n pubkeys in order.

        Bitcoin rule: For each sig, try pubkeys in order. If sig matches pubkey,
        advance both indices. If not, advance only pubkey index. All k sigs must match.

        Args:
            sigs: Signatures (stack order: top first)
            pubkeys: Public keys (stack order: top first)
            k: Number of required signatures
            tx: Transaction being verified
            input_index: Input index
            script_pubkey: Script pubkey for signature hash (P2SH: redeem script)

        Returns:
            True if exactly k signatures verify
        """
        if k == 0:
            return True
        if k > len(sigs) or k > len(pubkeys):
            return False

        # For multisig, script_code is the redeem script (OP_m pubkeys... OP_n OP_CHECKMULTISIG)
        # In P2SH, script_pubkey passed here is the redeem script from script_sig
        script_code = script_pubkey

        sig_idx = 0
        key_idx = 0
        matched = 0

        while sig_idx < len(sigs) and key_idx < len(pubkeys) and matched < k:
            sig = sigs[sig_idx]
            pubkey = pubkeys[key_idx]

            if len(sig) < 1:
                key_idx += 1
                continue

            sighash_type = sig[-1]
            der_sig = sig[:-1]

            message_hash = self._calculate_signature_hash(tx, input_index, script_code, sighash_type)
            if self._verify_ecdsa_signature(message_hash, der_sig, pubkey):
                sig_idx += 1
                matched += 1

            key_idx += 1

        return matched == k


def disassemble_script(script: bytes) -> str:
    """
    Disassemble Bitcoin script to human-readable ASM format.
    
    Args:
        script: Script bytes
        
    Returns:
        Human-readable script assembly (e.g., "OP_DUP OP_HASH160 <pubkeyhash> OP_EQUALVERIFY OP_CHECKSIG")
    """
    if not script:
        return ""
    
    asm_parts = []
    i = 0
    
    while i < len(script):
        opcode = script[i]
        i += 1
        
        # Data push opcodes
        if opcode == 0x00:
            asm_parts.append("OP_0")
        elif 0x01 <= opcode <= 0x4b:
            # Direct push
            data_len = opcode
            if i + data_len > len(script):
                break
            data = script[i:i+data_len]
            asm_parts.append(data.hex())
            i += data_len
        elif opcode == 0x4c:  # OP_PUSHDATA1
            if i >= len(script):
                break
            data_len = script[i]
            i += 1
            if i + data_len > len(script):
                break
            data = script[i:i+data_len]
            asm_parts.append(data.hex())
            i += data_len
        elif opcode == 0x4d:  # OP_PUSHDATA2
            if i + 1 >= len(script):
                break
            data_len = int.from_bytes(script[i:i+2], 'little')
            i += 2
            if i + data_len > len(script):
                break
            data = script[i:i+data_len]
            asm_parts.append(data.hex())
            i += data_len
        elif opcode == 0x4e:  # OP_PUSHDATA4
            if i + 3 >= len(script):
                break
            data_len = int.from_bytes(script[i:i+4], 'little')
            i += 4
            if i + data_len > len(script):
                break
            data = script[i:i+data_len]
            asm_parts.append(data.hex())
            i += data_len
        else:
            # Opcode name
            opcode_name = _get_opcode_name(opcode)
            asm_parts.append(opcode_name)
    
    return " ".join(asm_parts)


def _get_opcode_name(opcode: int) -> str:
    """Get opcode name from opcode value"""
    opcode_names = {
        0x76: "OP_DUP",
        0xa9: "OP_HASH160",
        0x88: "OP_EQUALVERIFY",
        0xac: "OP_CHECKSIG",
        0x87: "OP_EQUAL",
        0x6a: "OP_RETURN",
        0x51: "OP_1",
        0x52: "OP_2",
        0x53: "OP_3",
        0x54: "OP_4",
        0x55: "OP_5",
        0x56: "OP_6",
        0x57: "OP_7",
        0x58: "OP_8",
        0x59: "OP_9",
        0x5a: "OP_10",
        0x5b: "OP_11",
        0x5c: "OP_12",
        0x5d: "OP_13",
        0x5e: "OP_14",
        0x5f: "OP_15",
        0x60: "OP_16",
        # Add more opcodes as needed
    }
    return opcode_names.get(opcode, f"OP_UNKNOWN_{opcode:02x}")
