# -*- coding: utf-8 -*-

from ghidra.program.model.data import PointerDataType, DWordDataType
from ghidra.program.model.listing import CodeUnit
from ghidra.program.model.symbol import SourceType
import re

MAX_STRING_LEN = 64
MIN_STRING_LEN = 2
MAX_REFERENCES_TO_CONSIDER = 64
BACKSCAN_BYTES = 0x1000
POINTER_SIZE = 4
MAX_POINTER_FIELDS = 6
ALWAYS_LABEL_STRINGS = True
DEBUG = True

CLASS_NAME_RE = re.compile(r'^T[A-Z][A-Za-z0-9_]{1,60}$')

def is_printable_ascii(s):
    try:
        for ch in s:
            if ord(ch) < 0x20 or ord(ch) > 0x7e:
                return False
        return True
    except Exception:
        return False


def get_strings():
    res = []
    mem = currentProgram.getMemory()

    def flush(buf, start_addr):
        if not buf:
            return
        s = ''.join(buf)
        if len(s) >= MIN_STRING_LEN and len(s) <= MAX_STRING_LEN and CLASS_NAME_RE.match(s):
            res.append((start_addr, s))

    for b in mem.getBlocks():
        try:
            if not b.isInitialized():
                continue
        except Exception:
            pass
        addr_space = b.getStart().getAddressSpace()
        start_off = b.getStart().getOffset()
        end_off = start_off + b.getSize()
        buf = []
        buf_start = None
        off = start_off
        while off < end_off:
            a = addr_space.getAddress(off)
            try:
                byte = mem.getByte(a) & 0xff
            except Exception:
                if buf:
                    flush(buf, buf_start)
                buf = []
                buf_start = None
                off += 1
                continue
            if 0x20 <= byte <= 0x7e:
                ch = chr(byte)
                if not buf:
                    buf_start = a
                buf.append(ch)
                if len(buf) > MAX_STRING_LEN:
                    flush(buf, buf_start)
                    buf = []
                    buf_start = None
            elif byte == 0x00:
                flush(buf, buf_start)
                buf = []
                buf_start = None
            else:
                flush(buf, buf_start)
                buf = []
                buf_start = None
            off += 1
    return res


def find_references_to(addr):
    rm = currentProgram.getReferenceManager()
    refs = rm.getReferencesTo(addr)
    return list(refs)


def find_raw_occurrences(s):
    mem = currentProgram.getMemory()
    pattern = [ord(c) for c in s] + [0]
    occ = []
    for b in mem.getBlocks():
        try:
            if not b.isInitialized():
                continue
        except Exception:
            pass
        addr_space = b.getStart().getAddressSpace()
        start_off = b.getStart().getOffset()
        end_off = start_off + b.getSize()
        i = start_off
        j = 0
        while i < end_off:
            a = addr_space.getAddress(i)
            try:
                byte = mem.getByte(a) & 0xff
            except Exception:
                j = 0
                i += 1
                continue
            if byte == pattern[j]:
                j += 1
                if j == len(pattern):
                    occ.append(addr_space.getAddress(i - len(pattern) + 1))
                    j = 0
            else:
                j = 0
            i += 1
        
    return occ


def mem_block(addr):
    return currentProgram.getMemory().getBlock(addr)


def is_probably_data_region(addr):
    b = mem_block(addr)
    if b is None:
        return False
    try:
        if b.isExecute():
            return False
    except Exception:
        pass
    try:
        if not b.isInitialized():
            return False
    except Exception:
        pass
    return True


def backscan_for_pointer(start_addr):
    mem = currentProgram.getMemory()
    start_offset = start_addr.getOffset()
    min_off = max(0, start_offset - BACKSCAN_BYTES)
    addr_space = currentProgram.getAddressFactory().getDefaultAddressSpace()

    off = start_offset
    while off >= min_off:
        a = addr_space.getAddress(off)
        try:
            val = mem.getInt(a)
        except Exception:
            off -= 1
            continue
        try:
            targ = toAddr(val)
            if mem.getBlock(targ) is not None and is_probably_data_region(a):
                return a
        except Exception:
            pass
        off -= 1
    return None


def safe_create_pointer(listing, addr, pdt):
    if listing.getInstructionAt(addr) is not None:
        return False
    existing = listing.getDataAt(addr)
    if existing is not None:
        try:
            if existing.getLength() == pdt.getLength():
                return True
        except Exception:
            pass
        try:
            listing.clearCodeUnits(addr, addr.add(POINTER_SIZE-1), False)
        except Exception:
            return False
    else:
        try:
            listing.clearCodeUnits(addr, addr.add(POINTER_SIZE-1), False)
        except Exception:
            pass
    try:
        listing.createData(addr, pdt)
        return True
    except Exception:
        return False


def label_string_addr(addr, s):
    if not ALWAYS_LABEL_STRINGS:
        return
    try:
        st = currentProgram.getSymbolTable()
        st.createLabel(addr, "STR_%s" % s, SourceType.USER_DEFINED)
        cu = currentProgram.getListing().getCodeUnitAt(addr)
        if cu:
            cu.setComment(CodeUnit.PLATE_COMMENT, "Class-like string: %s" % s)
    except Exception:
        pass


def create_vmt_label(vmt_addr, class_name):
    listing = currentProgram.getListing()
    st = currentProgram.getSymbolTable()
    try:
        st.createLabel(vmt_addr, "VMT_%s_%x" % (class_name, vmt_addr.getOffset()), SourceType.USER_DEFINED)
    except Exception:
        pass
    cu = listing.getCodeUnitAt(vmt_addr)
    if cu is not None:
        cu.setComment(CodeUnit.PLATE_COMMENT, "Possible Delphi VMT for class: %s" % class_name)
    try:
        pdt = PointerDataType(DWordDataType())
    except Exception:
        return
    for i in range(MAX_POINTER_FIELDS):
        a = vmt_addr.add(i * POINTER_SIZE)
        safe_create_pointer(listing, a, pdt)


def run_script():
    print('[DelphiGhidra] Starting heuristic VMT scan...')
    candidates = get_strings()
    print('[DelphiGhidra] Found %d class-like strings' % len(candidates))

    MAX_CLASSES = 300
    processed = 0
    marked = 0

    for (saddr, s) in candidates:
        if processed >= MAX_CLASSES:
            break
        processed += 1

        print('[DelphiGhidra] Processing string %d: %s' % (processed, s))
        label_string_addr(saddr, s)

        raw_refs = find_raw_occurrences(s)
        if DEBUG:
            print('  refs(raw) = %d' % len(raw_refs))
        if len(raw_refs) == 0:
            xrefs = [r.getFromAddress() for r in find_references_to(saddr)]
        else:
            xrefs = raw_refs
        if DEBUG:
            print('  refs(total) = %d' % len(xrefs))

        if len(xrefs) == 0:
            if DEBUG:
                print('  skip: no references found for %s' % s)
            continue
        xrefs = xrefs[:MAX_REFERENCES_TO_CONSIDER]

        any_marked = False
        for from_addr in xrefs:
            cand = backscan_for_pointer(from_addr)
            if cand is None:
                if DEBUG:
                    print('   - no candidate via backscan from %s' % from_addr)
                continue
            if not is_probably_data_region(cand):
                if DEBUG:
                    print('   - rejected cand in executable/uninit block: %s' % cand)
                continue
            try:
                create_vmt_label(cand, s)
                marked += 1
                any_marked = True
                print('[DelphiGhidra] Marked candidate VMT at %s for class %s' % (cand, s))
            except Exception as e:
                print('[DelphiGhidra] Warning: could not mark %s: %s' % (cand, e))
        if DEBUG and not any_marked:
            print('  no VMT marked for %s' % s)

    print('[DelphiGhidra] Done. Marked %d candidates (processed %d strings).' % (marked, processed))


if __name__ == '__main__':
    run_script()
