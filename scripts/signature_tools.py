import struct
import bisect
from pathlib import Path


class Elf:
    def __init__(self, path):
        self.path = Path(path)
        self.data = self.path.read_bytes()
        if self.data[:6] != b'\x7fELF\x02\x01':
            raise ValueError('Expected a little-endian ELF64 file')
        if struct.unpack_from('<H', self.data, 18)[0] != 183:
            raise ValueError('Expected an ARM64 binary')
        phoff, shoff = struct.unpack_from('<QQ', self.data, 32)
        phsize, phcount, shsize, shcount, strings = struct.unpack_from('<HHHHH', self.data, 54)
        self.segments = []
        for index in range(phcount):
            kind, flags, offset, address, _, filesz, memsz, _ = struct.unpack_from('<IIQQQQQQ', self.data, phoff + index * phsize)
            if kind == 1:
                self.segments.append((address, offset, filesz, flags))
        self.sections = {}
        self.relocations = None
        self.entries = None
        if shoff and shcount:
            headers = [struct.unpack_from('<IIQQQQIIQQ', self.data, shoff + index * shsize) for index in range(shcount)]
            string_header = headers[strings]
            names = self.data[string_header[4]:string_header[4] + string_header[5]]
            for header in headers:
                end = names.find(b'\0', header[0])
                name = names[header[0]:end].decode('ascii', errors='replace')
                self.sections[name] = header

    def offset(self, address):
        for base, offset, size, _ in self.segments:
            if base <= address < base + size:
                return offset + address - base
        raise ValueError(f'Unmapped file address {address:#x}')

    def words(self, address, size):
        offset = self.offset(address)
        return list(struct.unpack_from('<' + 'I' * (size // 4), self.data, offset))

    def read(self, address, size):
        for base, offset, length, _ in self.segments:
            if base <= address and size <= base + length - address:
                start = offset + address - base
                return self.data[start:start + size]
        return b''

    def pointers(self):
        if self.relocations is None:
            self.relocations = {}
            for name in ('.rela.dyn', '.rela.plt'):
                section = self.sections.get(name)
                if section is None:
                    continue
                for address, info, addend in struct.iter_unpack('<QQq', self.data[section[4]:section[4] + section[5]]):
                    if info & 0xffffffff == 1027:
                        self.relocations[address] = addend
        return self.relocations

    def u64(self, address):
        pointers = self.pointers()
        if address in pointers:
            return pointers[address]
        data = self.read(address, 8)
        return struct.unpack('<Q', data)[0] if len(data) == 8 else 0

    def vtables(self, name):
        needle = name.encode() + b'\0'
        names = set()
        for base, offset, size, flags in self.segments:
            cursor = offset
            while True:
                found = self.data.find(needle, cursor, offset + size)
                if found < 0:
                    break
                names.add(base + found - offset)
                cursor = found + len(needle)
        pointers = self.pointers()
        types = {address - 8 for address, value in pointers.items() if value in names}
        return sorted({address + 8 for address, value in pointers.items() if value in types and self.u64(address - 8) == 0})

    def function_entry(self, anchor, size):
        if self.entries is None:
            self.entries = []
            header = self.sections.get('.eh_frame_hdr')
            if header is not None:
                data = self.data[header[4]:header[4] + header[5]]
                if data[:4] == b'\x01\x1b\x03\x3b':
                    count = struct.unpack_from('<I', data, 8)[0]
                    self.entries = [header[3] + struct.unpack_from('<i', data, 12 + index * 8)[0] for index in range(count)]
        index = bisect.bisect_right(self.entries, anchor)
        if not index:
            return None
        start = self.entries[index - 1]
        if anchor - start > 4096 or (index < len(self.entries) and anchor + size > self.entries[index]):
            return None
        return start

    def executable(self):
        for address, offset, size, flags in self.segments:
            if flags & 5 == 5:
                yield address, self.data[offset:offset + size]

    def build_id(self):
        header = self.sections.get('.note.gnu.build-id')
        if not header:
            return ''
        data = self.data[header[4]:header[4] + header[5]]
        namesz, size, kind = struct.unpack_from('<III', data)
        start = 12 + ((namesz + 3) & ~3)
        return data[start:start + size].hex() if kind == 3 else ''


def parse_pattern(text):
    pattern = []
    for token in text.split():
        if token in ('?', '??'):
            pattern.append(None)
        elif len(token) == 2 and all(character in '0123456789abcdefABCDEF' for character in token):
            pattern.append(int(token, 16))
        else:
            raise ValueError(f'Invalid byte-pattern token {token!r}')
    if not pattern or all(value is None for value in pattern):
        raise ValueError('Empty or all-wildcard pattern')
    return pattern


def format_pattern(pattern):
    return ' '.join('??' if value is None else f'{value:02X}' for value in pattern)


def sigmaker_pattern(data, address):
    try:
        from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
        from capstone.arm64 import ARM64_OP_IMM, ARM64_OP_MEM, ARM64_OP_FP
    except ImportError as error:
        raise SystemExit('Install capstone to generate ARM64 byte signatures') from error
    engine = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    engine.detail = True
    pattern = []
    for instruction in engine.disasm(data, address):
        if instruction.size != 4 or instruction.address != address + len(pattern):
            raise ValueError(f'Unexpected ARM64 instruction boundary at {instruction.address:#x}')
        wildcard = any(operand.type == ARM64_OP_MEM or
                       (operand.type == ARM64_OP_IMM and operand.imm != 0) or
                       (operand.type == ARM64_OP_FP and operand.fp != 0)
                       for operand in instruction.operands)
        pattern.extend([None, None, None, instruction.bytes[3]] if wildcard else instruction.bytes)
    if len(pattern) != len(data):
        raise ValueError(f'Undecodable ARM64 bytes at {address + len(pattern):#x}')
    return pattern


def exact_anchor(pattern):
    best = (0, 0)
    start = 0
    for index, value in enumerate(pattern + [None]):
        if value is not None:
            continue
        if index - start > best[1]:
            best = (start, index - start)
        start = index + 1
    if not best[1]:
        raise ValueError('Signature has no exact byte anchor')
    return best[0], bytes(pattern[best[0]:best[0] + best[1]])


def find_matches(segments, pattern, maximum=2):
    if isinstance(pattern, str):
        pattern = parse_pattern(pattern)
    anchor_offset, anchor = exact_anchor(pattern)
    found = []
    for base, data in segments:
        position = 0
        while True:
            position = data.find(anchor, position)
            if position < 0:
                break
            start = position - anchor_offset
            position += 1
            if start < 0 or start + len(pattern) > len(data):
                continue
            if all(value is None or data[start + index] == value for index, value in enumerate(pattern)):
                found.append(base + start)
                if len(found) >= maximum:
                    return found
    return found


def branch_target(word, address):
    if word & 0xfc000000 != 0x94000000:
        raise ValueError(f'Expected BL at {address:#x}')
    displacement = word & 0x03ffffff
    if displacement & 0x02000000:
        displacement -= 0x04000000
    return address + displacement * 4
