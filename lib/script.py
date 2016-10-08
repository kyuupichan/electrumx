# See the file "COPYING" for information about the copyright
# and warranty status of this software.

from binascii import hexlify
import struct

from lib.enum import Enumeration
from lib.hash import hash160
from lib.util import cachedproperty


class ScriptError(Exception):
    pass


OpCodes = Enumeration("Opcodes", [
    ("OP_0", 0), ("OP_PUSHDATA1", 76),
    "OP_PUSHDATA2", "OP_PUSHDATA4", "OP_1NEGATE",
    "OP_RESERVED",
    "OP_1", "OP_2", "OP_3", "OP_4", "OP_5", "OP_6", "OP_7", "OP_8",
    "OP_9", "OP_10", "OP_11", "OP_12", "OP_13", "OP_14", "OP_15", "OP_16",
    "OP_NOP", "OP_VER", "OP_IF", "OP_NOTIF", "OP_VERIF", "OP_VERNOTIF",
    "OP_ELSE", "OP_ENDIF", "OP_VERIFY", "OP_RETURN",
    "OP_TOALTSTACK", "OP_FROMALTSTACK", "OP_2DROP", "OP_2DUP", "OP_3DUP",
    "OP_2OVER", "OP_2ROT", "OP_2SWAP", "OP_IFDUP", "OP_DEPTH", "OP_DROP",
    "OP_DUP", "OP_NIP", "OP_OVER", "OP_PICK", "OP_ROLL", "OP_ROT",
    "OP_SWAP", "OP_TUCK",
    "OP_CAT", "OP_SUBSTR", "OP_LEFT", "OP_RIGHT", "OP_SIZE",
    "OP_INVERT", "OP_AND", "OP_OR", "OP_XOR", "OP_EQUAL", "OP_EQUALVERIFY",
    "OP_RESERVED1", "OP_RESERVED2",
    "OP_1ADD", "OP_1SUB", "OP_2MUL", "OP_2DIV", "OP_NEGATE", "OP_ABS",
    "OP_NOT", "OP_0NOTEQUAL", "OP_ADD", "OP_SUB", "OP_MUL", "OP_DIV", "OP_MOD",
    "OP_LSHIFT", "OP_RSHIFT", "OP_BOOLAND", "OP_BOOLOR", "OP_NUMEQUAL",
    "OP_NUMEQUALVERIFY", "OP_NUMNOTEQUAL", "OP_LESSTHAN", "OP_GREATERTHAN",
    "OP_LESSTHANOREQUAL", "OP_GREATERTHANOREQUAL", "OP_MIN", "OP_MAX",
    "OP_WITHIN",
    "OP_RIPEMD160", "OP_SHA1", "OP_SHA256", "OP_HASH160", "OP_HASH256",
    "OP_CODESEPARATOR", "OP_CHECKSIG", "OP_CHECKSIGVERIFY", "OP_CHECKMULTISIG",
    "OP_CHECKMULTISIGVERIFY",
    "OP_NOP1",
    "OP_CHECKLOCKTIMEVERIFY", "OP_CHECKSEQUENCEVERIFY"
])


# Paranoia to make it hard to create bad scripts
assert OpCodes.OP_DUP == 0x76
assert OpCodes.OP_HASH160 == 0xa9
assert OpCodes.OP_EQUAL == 0x87
assert OpCodes.OP_EQUALVERIFY == 0x88
assert OpCodes.OP_CHECKSIG == 0xac
assert OpCodes.OP_CHECKMULTISIG == 0xae


class ScriptSig(object):
    '''A script from a tx input, typically provides one or more signatures.'''

    SIG_ADDRESS, SIG_MULTI, SIG_PUBKEY, SIG_UNKNOWN = range(4)

    def __init__(self, script, coin, kind, sigs, pubkeys):
        self.script = script
        self.coin = coin
        self.kind = kind
        self.sigs = sigs
        self.pubkeys = pubkeys

    @cachedproperty
    def address(self):
        if self.kind == SIG_ADDRESS:
            return self.coin.address_from_pubkey(self.pubkeys[0])
        if self.kind == SIG_MULTI:
            return self.coin.multsig_address(self.pubkeys)
        return 'Unknown'

    @classmethod
    def from_script(cls, script, coin):
        '''Returns an instance of this class.  Uncrecognised scripts return
        an object of kind SIG_UNKNOWN.'''
        try:
            return cls.parse_script(script, coin)
        except ScriptError:
            return cls(script, coin, SIG_UNKNOWN, [], [])

    @classmethod
    def parse_script(cls, script, coin):
        '''Returns an instance of this class.  Raises on unrecognised
        scripts.'''
        ops, datas = Script.get_ops(script)

        # Address, PubKey and P2SH redeems only push data
        if not ops or not Script.match_ops(ops, [-1] * len(ops)):
            raise ScriptError('unknown scriptsig pattern')

        # Assume double data pushes are address redeems, single data
        # pushes are pubkey redeems
        if len(ops) == 2:     # Signature, pubkey
            return cls(script, coin, SIG_ADDRESS, [datas[0]], [datas[1]])

        if len(ops) == 1:     # Pubkey
            return cls(script, coin, SIG_PUBKEY, [datas[0]], [])

        # Presumably it is P2SH (though conceivably the above could be
        # too; cannot be sure without the send-to script).  We only
        # handle CHECKMULTISIG P2SH, which because of a bitcoin core
        # bug always start with an unused OP_0.
        if ops[0] != OpCodes.OP_0:
            raise ScriptError('unknown scriptsig pattern; expected OP_0')

        # OP_0, Sig1, ..., SigM, pk_script
        m = len(ops) - 2
        pk_script = datas[-1]
        pk_ops, pk_datas = Script.get_ops(script)

        # OP_2 pubkey1 pubkey2 pubkey3 OP_3 OP_CHECKMULTISIG
        n = len(pk_ops) - 3
        pattern = ([OpCodes.OP_1 + m - 1] + [-1] * n
                   + [OpCodes.OP_1 + n - 1, OpCodes.OP_CHECKMULTISIG])

        if m <= n and Script.match_ops(pk_ops, pattern):
            return cls(script, coin, SIG_MULTI, datas[1:-1], pk_datas[1:-2])

        raise ScriptError('unknown multisig P2SH pattern')


class ScriptPubKey(object):
    '''A script from a tx output that gives conditions necessary for
    spending.'''

    TO_ADDRESS, TO_P2SH, TO_PUBKEY, TO_UNKNOWN = range(4)
    TO_ADDRESS_OPS = [OpCodes.OP_DUP, OpCodes.OP_HASH160, -1,
                      OpCodes.OP_EQUALVERIFY, OpCodes.OP_CHECKSIG]
    TO_P2SH_OPS = [OpCodes.OP_HASH160, -1, OpCodes.OP_EQUAL]
    TO_PUBKEY_OPS = [-1, OpCodes.OP_CHECKSIG]

    def __init__(self, script, coin, kind, hash160, pubkey=None):
        self.script = script
        self.coin = coin
        self.kind = kind
        self.hash160 = hash160
        if pubkey:
            self.pubkey = pubkey

    @cachedproperty
    def address(self):
        if self.kind == ScriptPubKey.TO_P2SH:
            return self.coin.P2SH_address_from_hash160(self.hash160)
        if self.hash160:
            return self.coin.P2PKH_address_from_hash160(self.hash160)
        return ''

    @classmethod
    def from_script(cls, script, coin):
        '''Returns an instance of this class.  Uncrecognised scripts return
        an object of kind TO_UNKNOWN.'''
        try:
            return cls.parse_script(script, coin)
        except ScriptError:
            return cls(script, coin, cls.TO_UNKNOWN, None)

    @classmethod
    def parse_script(cls, script, coin):
        '''Returns an instance of this class.  Raises on unrecognised
        scripts.'''
        ops, datas = Script.get_ops(script)

        if Script.match_ops(ops, cls.TO_ADDRESS_OPS):
            return cls(script, coin, cls.TO_ADDRESS, datas[2])

        if Script.match_ops(ops, cls.TO_P2SH_OPS):
            return cls(script, coin, cls.TO_P2SH, datas[1])

        if Script.match_ops(ops, cls.TO_PUBKEY_OPS):
            pubkey = datas[0]
            return cls(script, coin, cls.TO_PUBKEY, hash160(pubkey), pubkey)

        raise ScriptError('unknown script pubkey pattern')

    @classmethod
    def P2SH_script(cls, hash160):
        return (bytes([OpCodes.OP_HASH160])
                + Script.push_data(hash160)
                + bytes([OpCodes.OP_EQUAL]))

    @classmethod
    def P2PKH_script(cls, hash160):
        return (bytes([OpCodes.OP_DUP, OpCodes.OP_HASH160])
                + Script.push_data(hash160)
                + bytes([OpCodes.OP_EQUALVERIFY, OpCodes.OP_CHECKSIG]))

    @classmethod
    def validate_pubkey(cls, pubkey, req_compressed=False):
        if isinstance(pubkey, (bytes, bytearray)):
            if len(pubkey) == 33 and pubkey[0] in (2, 3):
                return  # Compressed
            if len(pubkey) == 65 and pubkey[0] == 4:
                if not req_compressed:
                    return
                raise PubKeyError('uncompressed pubkeys are invalid')
        raise PubKeyError('invalid pubkey {}'.format(pubkey))

    @classmethod
    def pubkey_script(cls, pubkey):
        cls.validate_pubkey(pubkey)
        return Script.push_data(pubkey) + bytes([OpCodes.OP_CHECKSIG])

    @classmethod
    def multisig_script(cls, m, pubkeys):
        '''Returns the script for a pay-to-multisig transaction.'''
        n = len(pubkeys)
        if not 1 <= m <= n <= 15:
            raise ScriptError('{:d} of {:d} multisig script not possible'
                              .format(m, n))
        for pubkey in pubkeys:
            cls.validate_pubkey(pubkey, req_compressed=True)
        # See https://bitcoin.org/en/developer-guide
        # 2 of 3 is: OP_2 pubkey1 pubkey2 pubkey3 OP_3 OP_CHECKMULTISIG
        return (bytes([OP_1 + m - 1])
                + b''.join(cls.push_data(pubkey) for pubkey in pubkeys)
                + bytes([OP_1 + n - 1, OP_CHECK_MULTISIG]))


class Script(object):

    @classmethod
    def get_ops(cls, script):
        opcodes, datas = [], []

        # The unpacks or script[n] below throw on truncated scripts
        try:
            n = 0
            while n < len(script):
                opcode, data = script[n], None
                n += 1

                if opcode <= OpCodes.OP_PUSHDATA4:
                    # Raw bytes follow
                    if opcode < OpCodes.OP_PUSHDATA1:
                        dlen = opcode
                    elif opcode == OpCodes.OP_PUSHDATA1:
                        dlen = script[n]
                        n += 1
                    elif opcode == OpCodes.OP_PUSHDATA2:
                        (dlen,) = struct.unpack('<H', script[n: n + 2])
                        n += 2
                    else:
                        (dlen,) = struct.unpack('<I', script[n: n + 4])
                        n += 4
                    data = script[n:n + dlen]
                    if len(data) != dlen:
                        raise ScriptError('truncated script')
                    n += dlen

                opcodes.append(opcode)
                datas.append(data)
        except:
            # Truncated script; e.g. tx_hash
            # ebc9fa1196a59e192352d76c0f6e73167046b9d37b8302b6bb6968dfd279b767
            raise ScriptError('truncated script')

        return opcodes, datas

    @classmethod
    def match_ops(cls, ops, pattern):
        if len(ops) != len(pattern):
            return False
        for op, pop in zip(ops, pattern):
            if pop != op:
                # -1 Indicates data push expected
                if pop == -1 and OpCodes.OP_0 <= op <= OpCodes.OP_PUSHDATA4:
                    continue
                return False

        return True

    @classmethod
    def push_data(cls, data):
        '''Returns the opcodes to push the data on the stack.'''
        assert isinstance(data, (bytes, bytearray))

        n = len(data)
        if n < OpCodes.OP_PUSHDATA1:
            return bytes([n]) + data
        if n < 256:
            return bytes([OpCodes.OP_PUSHDATA1, n]) + data
        if n < 65536:
            return bytes([OpCodes.OP_PUSHDATA2]) + struct.pack('<H', n) + data
        return bytes([OpCodes.OP_PUSHDATA4]) + struct.pack('<I', n) + data

    @classmethod
    def opcode_name(cls, opcode):
        if OpCodes.OP_0 < opcode < OpCodes.OP_PUSHDATA1:
            return 'OP_{:d}'.format(opcode)
        try:
            return OpCodes.whatis(opcode)
        except KeyError:
            return 'OP_UNKNOWN:{:d}'.format(opcode)

    @classmethod
    def dump(cls, script):
        opcodes, datas = cls.get_ops(script)
        for opcode, data in zip(opcodes, datas):
            name = cls.opcode_name(opcode)
            if data is None:
                print(name)
            else:
                print('{} {} ({:d} bytes)'
                      .format(name, hexlify(data).decode('ascii'), len(data)))
