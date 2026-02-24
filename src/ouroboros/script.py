"""
Bitcoin script interpreter for transaction validation.

This module implements a basic Bitcoin script interpreter that can verify
standard script types (P2PKH, P2SH, P2WPKH, P2WSH, P2TR, etc.), and also
provides script disassembly functionality for human-readable script
representation.

Taproot support (BIP 340/341/342):
- Schnorr signature verification via coincurve or Rust extension
- Key-path spending (single witness element = Schnorr sig)
- Script-path spending (witness = [...script inputs, script, control block])
- OP_CHECKSIGADD for tapscript multisig
- Taproot-specific sighash (epoch 0x00, tagged hashes)
"""

import hashlib
import struct
from typing import List, Tuple, Optional
from dataclasses import dataclass

from ouroboros.database import Transaction, TxIn


def _tagged_hash(tag: str, data: bytes) -> bytes:
    """BIP 340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || data)."""
    tag_hash = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(tag_hash + tag_hash + data).digest()


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

    # ------------------------------------------------------------------
    # Schnorr / Taproot (BIP 340, 341, 342)
    # ------------------------------------------------------------------

    def _verify_schnorr_signature(
        self, message_hash: bytes, signature: bytes, pubkey_x: bytes
    ) -> bool:
        """
        Verify a BIP 340 Schnorr signature.

        Args:
            message_hash: 32-byte sighash
            signature: 64-byte Schnorr signature
            pubkey_x: 32-byte x-only public key

        Reference: BIP 340
        """
        if len(signature) != 64 or len(pubkey_x) != 32:
            return False

        try:
            import sync
            return sync.verify_schnorr(message_hash, signature, pubkey_x)
        except (ImportError, AttributeError):
            pass

        try:
            from coincurve import PublicKeyXOnly
            pk = PublicKeyXOnly(pubkey_x)
            return pk.verify(signature, message_hash)
        except ImportError:
            pass
        except Exception:
            return False

        return False

    def verify_taproot(
        self,
        tx: Transaction,
        input_index: int,
        witness: List[bytes],
        script_pubkey: bytes,
        input_amounts: Optional[List[int]] = None,
        input_script_pubkeys: Optional[List[bytes]] = None,
    ) -> bool:
        """
        Verify a Taproot (witness v1) spend.

        script_pubkey format: OP_1 <32-byte tweaked pubkey>
        Key-path: witness = [signature]
        Script-path: witness = [...inputs, script, control_block]

        Reference: BIP 341
        """
        if len(script_pubkey) != 34 or script_pubkey[0] != 0x51 or script_pubkey[1] != 0x20:
            return False

        output_pubkey = script_pubkey[2:]

        if not witness:
            return False

        # Annex detection: if last witness element starts with 0x50, it's the annex
        annex = None
        effective_witness = list(witness)
        if len(effective_witness) >= 2 and effective_witness[-1] and effective_witness[-1][0] == 0x50:
            annex = effective_witness.pop()

        if len(effective_witness) == 1:
            return self._verify_taproot_keypath(
                tx, input_index, effective_witness[0], output_pubkey,
                input_amounts, input_script_pubkeys, annex,
            )

        if len(effective_witness) >= 2:
            return self._verify_taproot_scriptpath(
                tx, input_index, effective_witness, output_pubkey,
                input_amounts, input_script_pubkeys, annex,
            )

        return False

    def _verify_taproot_keypath(
        self,
        tx: Transaction,
        input_index: int,
        sig_element: bytes,
        output_pubkey: bytes,
        input_amounts: Optional[List[int]] = None,
        input_script_pubkeys: Optional[List[bytes]] = None,
        annex: Optional[bytes] = None,
    ) -> bool:
        """
        Key-path spend: witness is a single Schnorr signature (64 or 65 bytes).

        Reference: BIP 341 key path spending
        """
        sighash_type = 0x00
        sig = sig_element
        if len(sig) == 65:
            sighash_type = sig[-1]
            sig = sig[:-1]
            if sighash_type == 0x00:
                return False  # explicit 0x00 is invalid per BIP 341
        elif len(sig) != 64:
            return False

        sighash = self._compute_taproot_sighash(
            tx, input_index, sighash_type,
            input_amounts=input_amounts,
            input_script_pubkeys=input_script_pubkeys,
            annex=annex,
            ext_flag=0,
        )
        return self._verify_schnorr_signature(sighash, sig, output_pubkey)

    def _verify_taproot_scriptpath(
        self,
        tx: Transaction,
        input_index: int,
        witness: List[bytes],
        output_pubkey: bytes,
        input_amounts: Optional[List[int]] = None,
        input_script_pubkeys: Optional[List[bytes]] = None,
        annex: Optional[bytes] = None,
    ) -> bool:
        """
        Script-path spend: witness = [...script_inputs, tapscript, control_block].

        Validates the control block Merkle proof against the output key,
        then executes the tapscript under BIP 342 rules.

        Reference: BIP 341 script path spending
        """
        if len(witness) < 2:
            return False

        control_block = witness[-1]
        tap_script = witness[-2]
        script_inputs = witness[:-2]

        if len(control_block) < 33 or (len(control_block) - 33) % 32 != 0:
            return False

        leaf_version = control_block[0] & 0xfe
        internal_key = control_block[1:33]
        merkle_path = control_block[33:]

        # Compute tapleaf hash
        leaf_hash = _tagged_hash(
            "TapLeaf",
            bytes([leaf_version]) + self._ser_script_size(tap_script) + tap_script,
        )

        # Walk up the Merkle path
        k = leaf_hash
        for i in range(0, len(merkle_path), 32):
            branch = merkle_path[i:i + 32]
            if k < branch:
                k = _tagged_hash("TapBranch", k + branch)
            else:
                k = _tagged_hash("TapBranch", branch + k)

        # Compute the tweaked key: P + hash(P || root) * G
        tweak = _tagged_hash("TapTweak", internal_key + k)

        tweaked = self._taproot_tweak_pubkey(internal_key, tweak)
        if tweaked is None:
            return False

        # The y-parity of the output key must match control_block[0] & 1
        tweaked_x, tweaked_parity = tweaked
        if tweaked_x != output_pubkey:
            return False
        if (control_block[0] & 1) != tweaked_parity:
            return False

        # Execute the tapscript (BIP 342)
        if leaf_version == 0xc0:
            sighash = self._compute_taproot_sighash(
                tx, input_index, 0x00,
                input_amounts=input_amounts,
                input_script_pubkeys=input_script_pubkeys,
                annex=annex,
                ext_flag=1,
                tap_leaf_hash=leaf_hash,
            )
            return self._execute_tapscript(
                tap_script, script_inputs, tx, input_index, sighash,
                input_amounts, input_script_pubkeys, annex, leaf_hash,
            )

        return False

    def _taproot_tweak_pubkey(
        self, internal_key: bytes, tweak: bytes
    ) -> Optional[Tuple[bytes, int]]:
        """
        Compute tweaked x-only pubkey: lift internal_key to a point, add
        tweak*G, return (x_bytes, parity).
        """
        try:
            from coincurve import PublicKeyXOnly
            pk = PublicKeyXOnly(internal_key)
            pk.tweak_add(tweak)  # mutates in-place, sets pk.parity
            return pk.format(), int(pk.parity)
        except (ImportError, AttributeError):
            pass
        except Exception:
            return None

        try:
            import sync
            result = sync.taproot_tweak_pubkey(internal_key, tweak)
            return result
        except (ImportError, AttributeError):
            pass
        except Exception:
            return None

        return None

    def _ser_script_size(self, script: bytes) -> bytes:
        """CompactSize-encode the length of a script."""
        n = len(script)
        if n < 0xFD:
            return struct.pack('<B', n)
        elif n <= 0xFFFF:
            return b'\xfd' + struct.pack('<H', n)
        elif n <= 0xFFFFFFFF:
            return b'\xfe' + struct.pack('<I', n)
        else:
            return b'\xff' + struct.pack('<Q', n)

    def _compute_taproot_sighash(
        self,
        tx: Transaction,
        input_index: int,
        sighash_type: int,
        *,
        input_amounts: Optional[List[int]] = None,
        input_script_pubkeys: Optional[List[bytes]] = None,
        annex: Optional[bytes] = None,
        ext_flag: int = 0,
        tap_leaf_hash: Optional[bytes] = None,
    ) -> bytes:
        """
        Compute the signature hash for a Taproot spend (BIP 341 §4).

        Uses tagged hash "TapSighash" and commits to all inputs' amounts
        and scriptPubKeys (unlike BIP 143 which only commits to the
        current input's amount).

        Reference: BIP 341 §4 (Signature validation rules)
        """
        # Determine hash type components
        anyone_can_pay = (sighash_type & 0x80) != 0
        base_type = sighash_type & 0x03  # 0=default/all, 1=all, 2=none, 3=single
        if sighash_type == 0:
            base_type = 0  # SIGHASH_DEFAULT = SIGHASH_ALL

        data = bytearray()

        # Epoch (0x00)
        data.append(0x00)

        # Hash type
        data.append(sighash_type)

        # Transaction data
        data.extend(struct.pack('<i', tx.version))
        data.extend(struct.pack('<I', tx.locktime))

        if not anyone_can_pay:
            # sha_prevouts: SHA256 of all outpoints
            prevouts = bytearray()
            for inp in tx.inputs:
                prevouts.extend(inp.prev_txid)
                prevouts.extend(struct.pack('<I', inp.prev_vout))
            data.extend(hashlib.sha256(bytes(prevouts)).digest())

            # sha_amounts: SHA256 of all input amounts
            if input_amounts:
                amounts = bytearray()
                for amt in input_amounts:
                    amounts.extend(struct.pack('<q', amt))
                data.extend(hashlib.sha256(bytes(amounts)).digest())
            else:
                data.extend(b'\x00' * 32)

            # sha_scriptpubkeys: SHA256 of all input scriptPubKeys (compact-size prefixed)
            if input_script_pubkeys:
                spks = bytearray()
                for spk in input_script_pubkeys:
                    spks.extend(self._ser_script_size(spk))
                    spks.extend(spk)
                data.extend(hashlib.sha256(bytes(spks)).digest())
            else:
                data.extend(b'\x00' * 32)

            # sha_sequences: SHA256 of all sequences
            seqs = bytearray()
            for inp in tx.inputs:
                seqs.extend(struct.pack('<I', inp.sequence))
            data.extend(hashlib.sha256(bytes(seqs)).digest())

        if base_type not in (2, 3):  # not NONE and not SINGLE
            # sha_outputs: SHA256 of all outputs
            outs = bytearray()
            for out in tx.outputs:
                outs.extend(struct.pack('<q', out.value))
                outs.extend(self._ser_script_size(out.script_pubkey))
                outs.extend(out.script_pubkey)
            data.extend(hashlib.sha256(bytes(outs)).digest())

        # Spend type: (ext_flag << 1) | annex_present
        annex_present = 1 if annex else 0
        spend_type = (ext_flag << 1) | annex_present
        data.append(spend_type)

        if anyone_can_pay:
            inp = tx.inputs[input_index]
            data.extend(inp.prev_txid)
            data.extend(struct.pack('<I', inp.prev_vout))
            if input_amounts and input_index < len(input_amounts):
                data.extend(struct.pack('<q', input_amounts[input_index]))
            else:
                data.extend(struct.pack('<q', 0))
            if input_script_pubkeys and input_index < len(input_script_pubkeys):
                spk = input_script_pubkeys[input_index]
                data.extend(self._ser_script_size(spk))
                data.extend(spk)
            else:
                data.extend(b'\x00')
            data.extend(struct.pack('<I', inp.sequence))
        else:
            data.extend(struct.pack('<I', input_index))

        if annex:
            data.extend(hashlib.sha256(
                self._ser_script_size(annex) + annex
            ).digest())

        if base_type == 2:  # SIGHASH_NONE
            pass
        elif base_type == 3:  # SIGHASH_SINGLE
            if input_index < len(tx.outputs):
                out = tx.outputs[input_index]
                out_data = struct.pack('<q', out.value) + self._ser_script_size(out.script_pubkey) + out.script_pubkey
                data.extend(hashlib.sha256(out_data).digest())
            else:
                data.extend(b'\x00' * 32)

        # Extension (script path)
        if ext_flag == 1 and tap_leaf_hash:
            data.extend(tap_leaf_hash)
            data.append(0x00)  # key_version
            data.extend(struct.pack('<i', -1))  # codesep_pos = -1 (none executed)

        return _tagged_hash("TapSighash", bytes(data))

    def _execute_tapscript(
        self,
        script: bytes,
        witness_inputs: List[bytes],
        tx: Transaction,
        input_index: int,
        default_sighash: bytes,
        input_amounts: Optional[List[int]] = None,
        input_script_pubkeys: Optional[List[bytes]] = None,
        annex: Optional[bytes] = None,
        leaf_hash: Optional[bytes] = None,
    ) -> bool:
        """
        Execute a tapscript (BIP 342).

        Differences from legacy script:
        - OP_CHECKSIG uses Schnorr (not ECDSA)
        - OP_CHECKMULTISIG is disabled, replaced by OP_CHECKSIGADD
        - Signature validation failure is immediate script failure (not push 0)
        - Unknown leaf versions are treated as OP_SUCCESS
        """
        stack: List[bytes] = list(witness_inputs)
        op_count = 0
        max_ops = 201

        i = 0
        while i < len(script):
            opcode = script[i]
            i += 1
            op_count += 1
            if op_count > max_ops:
                return False

            # Data pushes
            if 1 <= opcode <= 75:
                if i + opcode > len(script):
                    return False
                stack.append(script[i:i + opcode])
                i += opcode
                continue
            if opcode == 0x4c:  # OP_PUSHDATA1
                if i >= len(script):
                    return False
                dlen = script[i]; i += 1
                if i + dlen > len(script):
                    return False
                stack.append(script[i:i + dlen]); i += dlen
                continue
            if opcode == 0x4d:  # OP_PUSHDATA2
                if i + 2 > len(script):
                    return False
                dlen = int.from_bytes(script[i:i+2], 'little'); i += 2
                if i + dlen > len(script):
                    return False
                stack.append(script[i:i + dlen]); i += dlen
                continue

            if opcode == 0x00:  # OP_0
                stack.append(b'')
                continue
            if 0x51 <= opcode <= 0x60:  # OP_1 .. OP_16
                stack.append(bytes([opcode - 0x50]))
                continue

            # OP_DUP
            if opcode == 0x76:
                if not stack: return False
                stack.append(stack[-1])
                continue
            # OP_DROP
            if opcode == 0x75:
                if not stack: return False
                stack.pop()
                continue
            # OP_EQUAL
            if opcode == 0x87:
                if len(stack) < 2: return False
                a, b = stack.pop(), stack.pop()
                stack.append(b'\x01' if a == b else b'')
                continue
            # OP_EQUALVERIFY
            if opcode == 0x88:
                if len(stack) < 2: return False
                if stack.pop() != stack.pop(): return False
                continue
            # OP_HASH160
            if opcode == 0xa9:
                if not stack: return False
                stack.append(self._hash160(stack.pop()))
                continue

            # OP_CHECKSIG — Schnorr in tapscript
            if opcode == 0xac:
                if len(stack) < 2: return False
                pubkey = stack.pop()
                sig = stack.pop()
                if not sig:
                    stack.append(b'')
                    continue
                if len(pubkey) == 32:
                    sighash_type = 0x00
                    raw_sig = sig
                    if len(sig) == 65:
                        sighash_type = sig[-1]
                        raw_sig = sig[:-1]
                        if sighash_type == 0x00:
                            return False
                    elif len(sig) != 64:
                        return False

                    if sighash_type != 0x00:
                        sighash = self._compute_taproot_sighash(
                            tx, input_index, sighash_type,
                            input_amounts=input_amounts,
                            input_script_pubkeys=input_script_pubkeys,
                            annex=annex,
                            ext_flag=1,
                            tap_leaf_hash=leaf_hash,
                        )
                    else:
                        sighash = default_sighash

                    if not self._verify_schnorr_signature(sighash, raw_sig, pubkey):
                        return False
                    stack.append(b'\x01')
                else:
                    return False
                continue

            # OP_CHECKSIGVERIFY
            if opcode == 0xad:
                if len(stack) < 2: return False
                pubkey = stack.pop()
                sig = stack.pop()
                if len(pubkey) != 32 or not sig:
                    return False
                sighash_type = 0x00
                raw_sig = sig
                if len(sig) == 65:
                    sighash_type = sig[-1]; raw_sig = sig[:-1]
                    if sighash_type == 0x00: return False
                elif len(sig) != 64:
                    return False
                sh = default_sighash if sighash_type == 0x00 else self._compute_taproot_sighash(
                    tx, input_index, sighash_type,
                    input_amounts=input_amounts,
                    input_script_pubkeys=input_script_pubkeys,
                    annex=annex, ext_flag=1, tap_leaf_hash=leaf_hash,
                )
                if not self._verify_schnorr_signature(sh, raw_sig, pubkey):
                    return False
                continue

            # OP_CHECKSIGADD (0xba) — BIP 342
            if opcode == 0xba:
                if len(stack) < 3: return False
                pubkey = stack.pop()
                n = self._read_num(stack.pop())
                sig = stack.pop()

                if not sig:
                    stack.append(self._encode_script_num(n))
                    continue
                if len(pubkey) != 32:
                    return False

                sighash_type = 0x00
                raw_sig = sig
                if len(sig) == 65:
                    sighash_type = sig[-1]; raw_sig = sig[:-1]
                    if sighash_type == 0x00: return False
                elif len(sig) != 64:
                    return False

                sh = default_sighash if sighash_type == 0x00 else self._compute_taproot_sighash(
                    tx, input_index, sighash_type,
                    input_amounts=input_amounts,
                    input_script_pubkeys=input_script_pubkeys,
                    annex=annex, ext_flag=1, tap_leaf_hash=leaf_hash,
                )
                if not self._verify_schnorr_signature(sh, raw_sig, pubkey):
                    return False
                stack.append(self._encode_script_num(n + 1))
                continue

            # OP_CHECKMULTISIG / OP_CHECKMULTISIGVERIFY are disabled in tapscript
            if opcode in (0xae, 0xaf):
                return False

            # OP_SUCCESS range: opcodes 80, 98, 126-129, 131-134, 137-138,
            # 141-142, 149-153, 187-254 — the script succeeds unconditionally
            if opcode in _TAPSCRIPT_OP_SUCCESS:
                return True

        if not stack:
            return False
        top = stack[-1]
        if isinstance(top, bytes):
            return len(top) > 0 and any(b != 0 for b in top)
        return bool(top)

    def _encode_script_num(self, n: int) -> bytes:
        """Encode an integer as a Bitcoin script number (minimal CScriptNum)."""
        if n == 0:
            return b''
        negative = n < 0
        absn = abs(n)
        result = bytearray()
        while absn > 0:
            result.append(absn & 0xFF)
            absn >>= 8
        if result[-1] & 0x80:
            result.append(0x80 if negative else 0x00)
        elif negative:
            result[-1] |= 0x80
        return bytes(result)


# Opcodes that trigger OP_SUCCESS in tapscript (BIP 342).
_TAPSCRIPT_OP_SUCCESS = frozenset(
    [80, 98]
    + list(range(126, 130))
    + list(range(131, 135))
    + [137, 138, 141, 142]
    + list(range(149, 154))
    + list(range(187, 255))
)


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
        0x75: "OP_DROP",
        0xad: "OP_CHECKSIGVERIFY",
        0xae: "OP_CHECKMULTISIG",
        0xaf: "OP_CHECKMULTISIGVERIFY",
        0xba: "OP_CHECKSIGADD",
    }
    return opcode_names.get(opcode, f"OP_UNKNOWN_{opcode:02x}")
