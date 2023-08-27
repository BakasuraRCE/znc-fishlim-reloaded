import base64
import binascii
import hashlib
import random
import string
import struct
import traceback
from enum import Enum
from typing import Tuple

try:
    import znc
except ImportError:
    into_znc = False
    print('Running outside of ZNC; use it only for running tests.')
else:
    into_znc = True

from Crypto.Cipher import Blowfish
from Crypto.Random import get_random_bytes


#
# NOTE ABOUT DH1080:
# =================
#
# Diffie-Hellman key exchange assumes that you already have
# authenticated channels between Alice and Bob.  Which means that Alice
# has to be sure that she is really talking to Bob and not to any man in
# the middle.  But since the whole idea of FiSH is that you want to
# encrypt your communication on the IRC server whose operators you do
# not trust, there is no reliable way for Alice to tell if she really is
# talking to Bob.  It could also be some rogue IRC admin impersonating
# Bob with a fake hostname and ident or even doing a MITM attack on
# DH1080.  This means you can consider using DH1080 key exchange over
# IRC utterly broken in terms of security.
#

class DH1080:
    g_dh1080 = 2
    p_dh1080 = int('FBE1022E23D213E8ACFA9AE8B9DFAD'
                   'A3EA6B7AC7A7B7E95AB5EB2DF85892'
                   '1FEADE95E6AC7BE7DE6ADBAB8A783E'
                   '7AF7A7FA6A2B7BEB1E72EAE2B72F9F'
                   'A2BFB2A2EFBEFAC868BADB3E828FA8'
                   'BADFADA3E4CC1BE7E8AFE85E9698A7'
                   '83EB68FA07A77AB6AD7BEB618ACF9C'
                   'A2897EB28A6189EFA07AB99A8A7FA9'
                   'AE299EFA7BA66DEAFEFBEFBF0B7D8B', 16)
    q_dh1080 = (p_dh1080 - 1) // 2

    def __init__(self):
        self._public = 0
        self._private = 0
        self._secret = 0
        self._state = 0

        bits = 1080
        while True:
            self._private = self.bytes2int(get_random_bytes(bits // 8))
            self._public = pow(self.g_dh1080, self._private, self.p_dh1080)
            if 2 <= self._public <= self.p_dh1080 - 1 and \
                    self.dh_validate_public(self._public, self.q_dh1080, self.p_dh1080) == 1:
                break

    def finish(self, public_key):
        # validate state
        if self._state != 0:
            return False

        # change state
        self._state = 1

        public = self.bytes2int(self.b64decode(public_key))

        if not 1 < public < self.p_dh1080:
            return False

        if not self.dh_validate_public(public, self.q_dh1080, self.p_dh1080):
            return False

        self._secret = pow(public, self._private, self.p_dh1080)

        return True

    def public_key(self):
        return self.b64encode(self.int2bytes(self._public))

    def secret(self):
        if self._secret == 0:
            return None

        return self.b64encode(self.sha256(self.int2bytes(self._secret)))

    @staticmethod
    def b64encode(s):
        """A non-standard base64-encode."""
        b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        d = [0] * len(s) * 2

        L = len(s) * 8
        m = 0x80
        i, j, k, t = 0, 0, 0, 0
        while i < L:
            if s[i >> 3] & m:
                t |= 1
            j += 1
            m >>= 1
            if not m:
                m = 0x80
            if not j % 6:
                d[k] = b64[t]
                t &= 0
                k += 1
            t <<= 1
            t %= 0x100
            #
            i += 1
        m = 5 - j % 6
        t <<= m
        t %= 0x100
        if m:
            d[k] = b64[t]
            k += 1
        d[k] = 0
        res = ''
        for q in d:
            if q == 0:
                break
            res += q
        return res

    @staticmethod
    def b64decode(s):
        """A non-standard base64-encode."""
        b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        buf = [0] * 256
        for i in range(64):
            buf[ord(b64[i])] = i

        L = len(s)
        if L < 2:
            raise ValueError
        for i in reversed(list(range(L - 1))):
            if buf[ord(s[i])] == 0:
                L -= 1
            else:
                break
        if L < 2:
            raise ValueError

        d = [0] * L
        i, k = 0, 0
        while True:
            i += 1
            if k + 1 < L:
                d[i - 1] = buf[ord(s[k])] << 2
                d[i - 1] %= 0x100
            else:
                break
            k += 1
            if k < L:
                d[i - 1] |= buf[ord(s[k])] >> 4
            else:
                break
            i += 1
            if k + 1 < L:
                d[i - 1] = buf[ord(s[k])] << 4
                d[i - 1] %= 0x100
            else:
                break
            k += 1
            if k < L:
                d[i - 1] |= buf[ord(s[k])] >> 2
            else:
                break
            i += 1
            if k + 1 < L:
                d[i - 1] = buf[ord(s[k])] << 6
                d[i - 1] %= 0x100
            else:
                break
            k += 1
            if k < L:
                d[i - 1] |= buf[ord(s[k])] % 0x100
            else:
                break
            k += 1
        return bytes(d[0:i - 1])

    @staticmethod
    def dh_validate_public(public, q, p):
        """See RFC 2631 section 2.1.5."""
        return 1 == pow(public, q, p)

    @staticmethod
    def bytes2int(b):
        """Variable length big endian to integer."""
        return int.from_bytes(b, byteorder='big')

    @staticmethod
    def int2bytes(n):
        """Integer to variable length big endian."""
        return n.to_bytes((n.bit_length() + 7) // 8, byteorder='big')

    @staticmethod
    def sha256(s):
        """sha256"""
        return hashlib.sha256(s).digest()


class FiSHSLiM:
    class BlowfishECB:

        @staticmethod
        def encrypt(key: bytes, data: bytes) -> bytes:
            cipher = Blowfish.new(key, Blowfish.MODE_ECB)
            return cipher.encrypt(data)

        @staticmethod
        def decrypt(key: bytes, data: bytes) -> bytes:
            cipher = Blowfish.new(key, Blowfish.MODE_ECB)
            return cipher.decrypt(data)

    class BlowfishCBC:
        @staticmethod
        def encrypt(key: bytes, data: bytes) -> bytes:
            cipher = Blowfish.new(key, Blowfish.MODE_CBC)
            return cipher.iv + cipher.encrypt(data)

        @staticmethod
        def decrypt(key: bytes, data: bytes, iv: bytes) -> bytes:
            blowfish = Blowfish.new(key, Blowfish.MODE_CBC, iv)
            return blowfish.decrypt(data)

    @staticmethod
    def zero_pad(msg: bytes, length: int):
        """Pads 'msg' with zeroes until it's length is divisible by 'length'.
        If the length of msg is already a multiple of 'length', does nothing."""
        l_ = len(msg)
        if l_ % length:
            msg += b'\x00' * (length - l_ % length)
        assert len(msg) % length == 0
        return msg

    # XXX: Unstable.
    @staticmethod
    def blowcrypt_b64encode(s: bytes) -> str:
        """A non-standard base64-encode."""
        b64 = "./0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
        res = ''
        while s:
            left, right = struct.unpack('>LL', s[:8])
            for i in range(6):
                res += b64[right & 0x3f]
                right >>= 6
            for i in range(6):
                res += b64[left & 0x3f]
                left >>= 6
            s = s[8:]
        return res

    @staticmethod
    def blowcrypt_b64decode(s: str) -> bytes:
        """A non-standard base64-decode."""
        b64 = "./0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
        res = b''
        while s:
            left, right = 0, 0
            for i, p in enumerate(s[0:6]):
                right |= b64.index(p) << (i * 6)
            for i, p in enumerate(s[6:12]):
                left |= b64.index(p) << (i * 6)

            # Mask to ensure values are within 32-bit unsigned integer range
            left &= 0xFFFFFFFF
            right &= 0xFFFFFFFF
            res += struct.pack('>LL', left, right)
            s = s[12:]
        return res

    @staticmethod
    def ecb_encrypt(message: str, key: bytes) -> str | None:
        try:
            padded_data = FiSHSLiM.zero_pad(
                message.encode('utf-8'),
                8
            )
            encrypted_msg = FiSHSLiM.blowcrypt_b64encode(FiSHSLiM.BlowfishECB.encrypt(key, padded_data))

            return f'+OK {encrypted_msg}'
        except Exception as e:
            print(e)
            return None

    @staticmethod
    def ecb_decrypt(encrypted_data: str, key: bytes) -> str | None:
        if len(encrypted_data) < 12:
            return None

        try:
            raw = FiSHSLiM.blowcrypt_b64decode(encrypted_data)
            if not raw:
                return None

            message = FiSHSLiM.BlowfishECB.decrypt(key, raw)
            return message.strip(b'\x00').decode('utf-8')
        except (TypeError, ValueError, UnicodeDecodeError):
            return None

    @staticmethod
    def cbc_encrypt(message: str, key: bytes) -> str | None:
        try:
            padded_data = FiSHSLiM.zero_pad(
                message.encode('utf-8'),
                8  # Encrypt in block of 8 bytes for ECB and CBC
            )
            encrypted_msg = base64.b64encode(FiSHSLiM.BlowfishCBC.encrypt(key, padded_data)).decode('utf-8')
        except Exception:
            return None

        return f'+OK *{encrypted_msg}'

    @staticmethod
    def cbc_decrypt(encrypted_data: str, key: bytes) -> str | None:
        if len(encrypted_data) % 4:
            encrypted_data += '=' * (4 - len(encrypted_data) % 4)

        try:
            encrypted_data = base64.b64decode(encrypted_data)
        except binascii.Error:
            return None

        iv = encrypted_data[:8]
        raw = encrypted_data[8:]
        message = FiSHSLiM.BlowfishCBC.decrypt(key, FiSHSLiM.zero_pad(raw, 8), iv)

        try:
            return message.strip(b'\x00').decode('utf-8')
        except UnicodeDecodeError:
            return None

    @staticmethod
    def parse_key(key_data: str) -> Tuple[str, bytes]:
        if key_data.casefold().startswith('cbc:'):
            return 'cbc', key_data[4:].encode('utf-8')[:56]
        elif key_data.casefold().startswith('ecb:'):
            return 'ecb', key_data[4:].encode('utf-8')[:56]
        else:
            return 'cbc', key_data.encode('utf-8')[:56]


class KeyNotFound(Exception):
    pass


class InvalidText(Exception):
    pass


class MessageType(int, Enum):
    MESSAGE = 0
    ACTION = 1
    TOPIC = 2
    NOTICE = 3


if into_znc:
    class fishslim(znc.Module):
        """
        For network modules we use GetNetwork() that return a CIRCNetwork object
         - source code doc: https://github.com/znc/znc/blob/bf253640d33d03331310778e001fb6f5aba2989e/src/IRCNetwork.cpp#L828
        """
        module_types = [znc.CModInfo.NetworkModule]
        description = 'FISHSLiM encryption for ZNC with support for CBC and ECB modes, and key exchange using DH1080'
        wiki_page = 'https://github.com/BakasuraRCE/znc-fishlim-reloaded'
        dh_keys: dict

        def get_nick_mask(self):
            """
            Retrieves the Nick mask for the current IRC network.

            This method obtains the Nick mask which typically consists of the user's
            nickname, username, and hostname in the IRC (Internet Relay Chat) network.

            Returns:
            - str: The Nick mask associated with the user in the current IRC network.
            """
            return self.GetNetwork().GetIRCNick().GetHostMask()

        def get_nick(self):
            return self.GetNetwork().GetIRCNick().GetNick()

        def OnLoad(self, args, message):
            self.dh_keys = {}
            return True

        def put_user_message(self, target: str, message: str, command: str = 'PRIVMSG'):
            """
            Sends a user message to a specified target over the network.

            This method composes a "raw" command to send a PRIVMSG and then dispatches
            it to all connected clients.

            Args:
            - target (str): The target (e.g., a channel or a username) to send the message to.
            - message (str): The content of the message to be sent.
            """
            # :nick!~nick@127.0.0.1 PRIVMSG target :message
            raw_command = f':{self.get_nick_mask()} {command} {target} :{message}'
            # Sends the message to all connected clients
            self.GetNetwork().PutUser(raw_command)

        def handle_outgoing(self, target, original_message, message_type: MessageType = MessageType.MESSAGE):
            try:
                feedback_message, encrypted_msg = self.encrypt(target, original_message)
            except KeyNotFound:
                # we don't have a key, just continue
                return znc.CONTINUE
            except InvalidText:
                # we have a key but can't encrypt the message, not send leaked message
                return znc.HALT

            # send encrypted message to irc server
            command = 'PRIVMSG'
            final_feedback_message = feedback_message
            final_encrypted_msg = encrypted_msg

            if message_type == MessageType.MESSAGE:
                final_encrypted_msg = encrypted_msg
                final_feedback_message = feedback_message

            elif message_type == MessageType.ACTION:
                final_encrypted_msg = f'\x01ACTION {encrypted_msg}\x01'
                final_feedback_message = f'\x01ACTION {feedback_message}\x01'

            elif message_type == MessageType.TOPIC:
                command = 'TOPIC'
            elif message_type == MessageType.NOTICE:
                command = 'NOTICE'

            self.PutIRC(f'{command} {target} :{final_encrypted_msg}')
            # send feedback message to clients
            self.put_user_message(target, final_feedback_message, command)
            return znc.HALTCORE

        def OnUserTextMessage(self, message):
            target = message.GetTarget()
            original_message = message.GetText()
            return self.handle_outgoing(target, original_message)

        def OnUserActionMessage(self, message):
            target = message.GetTarget()
            original_message = message.GetText()
            return self.handle_outgoing(target, original_message, MessageType.ACTION)

        def OnUserTopicMessage(self, message):
            target = message.GetTarget()
            original_message = message.GetText()
            return self.handle_outgoing(target, original_message, MessageType.TOPIC)

        def OnUserNoticeMessage(self, message):
            target = message.GetTarget()
            original_message = message.GetText()
            return self.handle_outgoing(target, original_message, MessageType.NOTICE)

        def handle_incoming(self, target: str, message):
            old_message = message.GetText()

            decrypted_msg = self.decrypt(target, old_message)
            message.SetText(decrypted_msg)
            return znc.CONTINUE

        def OnChanTextMessage(self, message):
            target = message.GetTarget()
            return self.handle_incoming(target, message)

        def OnChanNoticeMessage(self, message):
            target = message.GetTarget()
            return self.handle_incoming(target, message)

        def OnChanActionMessage(self, message):
            target = message.GetTarget()
            return self.handle_incoming(target, message)

        def OnPrivTextMessage(self, message):
            source_nick = message.GetNick().GetNick()
            return self.handle_incoming(source_nick, message)

        def OnPrivActionMessage(self, message):
            source_nick = message.GetNick().GetNick()
            return self.handle_incoming(source_nick, message)

        def OnTopicMessage(self, message):
            target = message.GetTarget()
            return self.handle_incoming(target, message)

        def OnPrivNoticeMessage(self, message):
            source_nick = message.GetNick().GetNick()

            old_message = message.GetText()
            tokens = old_message.split(maxsplit=3)

            command: str = tokens[0].upper() if 0 < len(tokens) else None
            public_key = tokens[1] if 1 < len(tokens) else None

            # we are receiving a key exchange init
            if command and command.startswith('DH1080_INIT') and public_key:
                mode = tokens[2] if 2 < len(tokens) else None
                if mode:
                    mode = mode.casefold()

                # default mode CBC
                if not any(mode == m for m in ['ecb', 'cbc']):
                    mode = 'cbc'

                cbc_suffix = False
                if command == 'DH1080_INIT_CBC':
                    cbc_suffix = True
                    mode = 'cbc'

                dh1080 = DH1080()
                if dh1080.finish(public_key):
                    self.nv[source_nick] = f'{mode}:{dh1080.secret()}'
                    self.put_user_message(
                        source_nick,
                        f'Your key is set and your messages will now be encrypted, sending DH1080_FINISH to {source_nick}.',
                        'NOTICE'
                    )
                    prefix = 'DH1080_FINISH_CBC' if cbc_suffix else 'DH1080_FINISH'
                    self.PutIRC(f'NOTICE {source_nick} :{prefix} {dh1080.public_key()}')
                else:
                    self.put_user_message(
                        source_nick,
                        f'Failed to validate public key for encryption DH1080 for user {source_nick}.',
                        'NOTICE'
                    )

                return znc.HALT
            # we are receiving a key exchange finish
            elif command and command.startswith('DH1080_FINISH') and public_key:
                self.put_user_message(source_nick, f'Received DH1080_FINISH from {source_nick}', 'NOTICE')

                try:
                    dh1080 = self.dh_keys.get(source_nick)
                except TypeError:
                    self.put_user_message(
                        source_nick,
                        f'DH1080 key does not exist for user {source_nick}. Key exchange failed.',
                        'NOTICE'
                    )
                    return znc.HALT

                if dh1080.finish(public_key):
                    self.nv[source_nick] = f'cbc:{dh1080.secret()}'
                    self.put_user_message(
                        source_nick,
                        f' Successfully parsed DH1080_FINISH sent by {source_nick}. '
                        'Your key is set and your messages will now be encrypted.',
                        'NOTICE'
                    )
                else:
                    self.put_user_message(
                        source_nick,
                        f'Failed to parse DH1080_FINISH sent by {source_nick}. Key exchange failed.',
                        'NOTICE'
                    )

                return znc.HALT

            # handle incoming as usual
            return self.handle_incoming(source_nick, message)

        def OnNumericMessage(self, message):
            # Only handle topic message
            if message.GetCode() != 332:
                return znc.CONTINUE

            target = message.GetParam(1)
            old_message = message.GetParam(2)
            decrypted_msg = self.decrypt(target, old_message)
            message.SetParam(2, decrypted_msg)
            return znc.CONTINUE

        def OnModCommand(self, command):
            cmd = command.split()
            command = cmd[0].lower()

            if command == 'setkey':
                if 4 > len(cmd[2]) > 56:
                    self.PutModule(f'Key size MUST BE 4-56 bytes.')
                else:
                    self.nv[cmd[1]] = cmd[2]
                    self.PutModule(f'Key set for {cmd[1]}.')
            elif command == 'delkey':
                if cmd[1] in self.nv:
                    del self.nv[cmd[1]]
                    self.PutModule(f'Key deleted for {cmd[1]}.')
                else:
                    self.PutModule(f'No key found for {cmd[1]}.')
            elif command == 'keyx':
                target = cmd[1]

                dh1080 = DH1080()
                self.dh_keys[target] = dh1080
                self.PutIRC(f'NOTICE {target} :DH1080_INIT {dh1080.public_key()} CBC')
                self.put_user_message(
                    target,
                    f'Beginning DH1080 key exchange with {target}.',
                    'NOTICE'
                )

            elif command == 'listkeys':
                has_keys = False
                for key, value in self.nv.items():
                    has_keys = True
                    self.PutModule(f'{key}: {value}')

                if not has_keys:
                    self.PutModule('No keys found, use `setkey target key` to add one')
            else:
                self.PutModule('Unknown command')

        def encrypt(self, target, message) -> Tuple[str, str]:
            key_data = self.nv.get(target)
            original_message = message

            # we do not have a key, do nothing
            if not key_data:
                raise KeyNotFound

            mode, key = FiSHSLiM.parse_key(key_data)

            try:
                if mode == 'ecb':
                    message = FiSHSLiM.ecb_encrypt(message, key)

                if mode == 'cbc':
                    message = FiSHSLiM.cbc_encrypt(message, key)

                if not message:
                    raise Exception('Empty encrypted message')
            except Exception as e:
                self.PutModule(f'Error on encrypt message {message}\n{str(e)}\n{traceback.format_exc()}')
                raise InvalidText(str(e))

            # indicate the current mode
            prefix = ''
            if mode == 'ecb':
                prefix = 'E🔓'
            if mode == 'cbc':
                prefix = 'C🔒'

            return f'{prefix} {original_message}', message

        def decrypt(self, source, message):
            key_data = self.nv.get(source)
            original_message = message

            def unsecure_message():
                return f'❌ {message}'

            def encrypted_message():
                return f'⚠️ {original_message}'

            # we do not have a key, do nothing
            if not key_data:
                return message

            # we check if the message has a known FiSH encryption prefix
            if not message.startswith(('+OK ', 'mcps')):
                return unsecure_message()

            encrypted_data = message.split(' ', maxsplit=1)[1]
            # remove *
            encrypted_data = encrypted_data[1:] if encrypted_data.startswith('*') else encrypted_data

            mode, key = FiSHSLiM.parse_key(key_data)
            real_mode = mode

            try:
                if mode == 'ecb':
                    message = FiSHSLiM.ecb_decrypt(encrypted_data, key)
                    # try CBC
                    if not message:
                        message = FiSHSLiM.cbc_decrypt(encrypted_data, key)
                        real_mode = 'cbc'

                elif mode == 'cbc':
                    message = FiSHSLiM.cbc_decrypt(encrypted_data, key)
                    # try ECB
                    if not message:
                        message = FiSHSLiM.ecb_decrypt(encrypted_data, key)
                        real_mode = 'ecb'

                if not message:
                    raise Exception('empty plaintext')

                prefix = ''
                # indicate a change of mode
                if real_mode != mode:
                    prefix = '🔄'
                    mode = real_mode

                # indicate the current mode
                if mode == 'ecb':
                    prefix = prefix + 'E🔓'
                if mode == 'cbc':
                    prefix = prefix + 'C🔒'

                return f'{prefix} {message}'

            except Exception as e:
                self.PutModule(f'Error on decrypt message {message}\n{str(e)}\n{traceback.format_exc()}')
                # if something goes wrong during the decryption process, we return the encrypted message.
                return encrypted_message()


## TESTS

def generate_random_utf8_characters(length: int):
    utf8_characters = []
    for _ in range(length):
        code_point = random.randint(0x01, 0x10FFFF)
        if code_point <= 0x7F:
            utf8_characters.append(chr(code_point))
        elif code_point <= 0x7FF:
            utf8_characters.append(chr((code_point >> 6) | 0xC0) + chr((code_point & 0x3F) | 0x80))
        elif code_point <= 0xFFFF:
            utf8_characters.append(chr((code_point >> 12) | 0xE0) + chr(((code_point >> 6) & 0x3F) | 0x80) + chr((code_point & 0x3F) | 0x80))
        else:
            utf8_characters.append(chr((code_point >> 18) | 0xF0) + chr(((code_point >> 12) & 0x3F) | 0x80) + chr(((code_point >> 6) & 0x3F) | 0x80) + chr((code_point & 0x3F) | 0x80))
    return ''.join(utf8_characters)


def generate_random_ascii(length: int):
    return ''.join(random.choices(string.printable, k=length))


def test_dh1080():
    for _ in range(0, 51):
        alice = DH1080()
        bob = DH1080()

        # from alice to bob
        bob.finish(alice.public_key())
        alice.finish(bob.public_key())
        assert alice.secret() == bob.secret()

        # from bob to alice
        alice.finish(bob.public_key())
        bob.finish(alice.public_key())
        assert bob.secret() == alice.secret()


def test_blowfish_ecb_random():
    # test from 4 to 56 bytes key length
    for key_len in range(4, 57):
        key = get_random_bytes(key_len)
        # form 1 to 51 carters
        for msg_len in range(1, 52):
            for rand_func in [generate_random_utf8_characters, generate_random_ascii]:
                # test 5 times the same message length
                for _ in range(1, 6):
                    old_message = rand_func(msg_len)
                    encrypted_data = FiSHSLiM.ecb_encrypt(old_message, key)
                    assert encrypted_data is not None
                    encrypted_data = encrypted_data.split()[1]
                    message = FiSHSLiM.ecb_decrypt(encrypted_data, key)
                    assert message == old_message


def test_blowfish_cbc_random():
    # test from 4 to 56 bytes key length
    for key_len in range(4, 57):
        key = get_random_bytes(key_len)
        # form 1 to 51 carters
        for msg_len in range(1, 52):
            for rand_func in [generate_random_utf8_characters, generate_random_ascii]:
                # test 5 times the same message length
                for _ in range(1, 6):
                    old_message = rand_func(msg_len)
                    encrypted_data = FiSHSLiM.cbc_encrypt(old_message, key)
                    assert encrypted_data is not None
                    encrypted_data = encrypted_data.split()[1][1:]
                    message = FiSHSLiM.cbc_decrypt(encrypted_data, key)
                    assert message == old_message
