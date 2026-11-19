#!/usr/bin/env python3
import random, struct, sys, zlib
import pefile
from unicorn import *
from unicorn.x86_const import *
import unicorn.x86_const as X86C
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

FORBIDDEN = {"popcnt", "crc32", "pcmpgtq", "pcmpestri", "pcmpestrm", "pcmpistri", "pcmpistrm",
             "lzcnt", "ptest", "pmovzxbw", "pblendvb", "pminud", "pmaxsd", "pmulld",
             "pcmpeqq", "packusdw", "pextrd", "pinsrd", "roundps", "dpps"}
GPRS = [UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_RBX, UC_X86_REG_RSP, UC_X86_REG_RBP,
        UC_X86_REG_RSI, UC_X86_REG_RDI] + [getattr(X86C, "UC_X86_REG_R%d" % i) for i in range(8, 16)]
XMMS = [getattr(X86C, "UC_X86_REG_XMM%d" % i) for i in range(16)]
STACK_BASE, STACK_SIZE = 0x7ff000000000, 0x100000
FL_MASK_ALL = 0x8D5
FL_MASK_POPCNT = 0x8C1

cs = Cs(CS_ARCH_X86, CS_MODE_64)
NONCANON = [False]
import os
DEBUG = bool(os.environ.get("VDEBUG"))


import ctypes, mmap
from capstone import CS_OP_MEM, CS_OP_REG
from capstone.x86 import X86_OP_MEM
cs.detail = True
_buf = mmap.mmap(-1, 4096, prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC)
_io = ctypes.create_string_buffer(96)

def native_pcmpstr(opbyte, imm, rexw, a, b, rax, rdx):
    code = bytes.fromhex("f30f6f0f" "f30f6f5710" "488b4720" "488b5728" "4889fe" "48c7c1efbeadde"
                         "66" + ("48" if rexw else "") + "0f3a%02xca%02x" % (opbyte, imm) +
                         "9c" "4158" "48894e30" "f30f7f4638" "4c894648" "c3")
    _buf.seek(0); _buf.write(code)
    struct.pack_into("<16s16sQQ", _io, 0, a, b, rax, rdx)
    f = ctypes.CFUNCTYPE(None, ctypes.c_void_p)(ctypes.addressof(ctypes.c_char.from_buffer(_buf)))
    f(ctypes.addressof(_io))
    rcx, x0, fl = struct.unpack_from("<Q16sQ", _io, 48)
    return rcx, x0, fl

def ensure_mapped(mu, addr, size):
    for p in range(addr & ~0xFFF, addr + size, 0x1000):
        try:
            mu.mem_read(p, 1)
        except UcError:
            mu.mem_map(p, 0x1000)
            rnd = random.Random(p)
            mu.mem_write(p, bytes(rnd.choice(b"\0\0abcxyz\xff\x80\x7f") if rnd.random() < .5 else rnd.getrandbits(8) for _ in range(0x1000)))

REGMAP = {}
def capreg_to_uc(name):
    import unicorn.x86_const as U
    return getattr(U, "UC_X86_REG_" + name.upper())

def expected_pcmpstr(mu, ins, st):
    ops = ins.operands
    a = st[capreg_to_uc(ins.reg_name(ops[0].reg))].to_bytes(16, "little")
    if ops[1].type == X86_OP_MEM:
        m = ops[1].mem
        ea = m.disp
        if m.base: ea += (ins.address + ins.size) if ins.reg_name(m.base) == "rip" else st[capreg_to_uc(ins.reg_name(m.base))]
        if m.index: ea += st[capreg_to_uc(ins.reg_name(m.index))] * m.scale
        ea &= 0xFFFFFFFFFFFFFFFF
        if ea >= 0x800000000000: return None
        ensure_mapped(mu, ea, 16)
        b = bytes(mu.mem_read(ea, 16))
    else:
        b = st[capreg_to_uc(ins.reg_name(ops[1].reg))].to_bytes(16, "little")
    opbyte = ins.bytes[-3]
    rexw = any(0x48 <= x <= 0x4f and (x & 8) for x in ins.bytes[:ins.bytes.index(0x0f)])
    rcx, x0, fl = native_pcmpstr(opbyte, ins.bytes[-1], rexw, a, b, st[UC_X86_REG_RAX], st[UC_X86_REG_RDX])
    out = {r: st[r] for r in GPRS + XMMS}
    if opbyte in (0x61, 0x63): out[UC_X86_REG_RCX] = rcx & 0xFFFFFFFF
    else: out[UC_X86_REG_XMM0] = int.from_bytes(x0, "little")
    out["rip"] = ins.address + ins.size
    out["fl"] = (st[UC_X86_REG_EFLAGS] & ~FL_MASK_ALL) | (fl & FL_MASK_ALL)
    return out


def load(path):
    pe = pefile.PE(path, fast_load=True)
    base = pe.OPTIONAL_HEADER.ImageBase
    size = (pe.OPTIONAL_HEADER.SizeOfImage + 0xFFFF) & ~0xFFFF
    mu = Uc(UC_ARCH_X86, UC_MODE_64, cpu=UC_CPU_X86_HASWELL)
    mu.mem_map(base, size)
    mu.mem_write(base, pe.get_data(0, 0x1000)[:0x1000])
    for s in pe.sections:
        data = s.get_data()
        if data:
            mu.mem_write(base + s.VirtualAddress, data[:max(s.Misc_VirtualSize, len(data))])
    mu.mem_map(STACK_BASE, STACK_SIZE)
    newsec = [s for s in pe.sections if s.Name.rstrip(b"\0") == b".sse42em"]
    ns = (base + newsec[0].VirtualAddress, base + newsec[0].VirtualAddress + newsec[0].Misc_VirtualSize) if newsec else None

    def unmapped(uc, access, addr, size, value, ud):
        if addr >= 0x800000000000 or addr + size > 0x800000000000:
            NONCANON[0] = True
            return False
        page = addr & ~0xFFF
        for p in (page, (addr + size - 1) & ~0xFFF):
            try:
                uc.mem_map(p, 0x1000)
                rnd = random.Random(p)
                uc.mem_write(p, bytes(rnd.choice(b"\0\0abcxyz\xff\x80\x7f") if rnd.random() < .5 else rnd.getrandbits(8) for _ in range(0x1000)))
            except UcError:
                pass
        return True
    mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED, unmapped)
    return mu, base, ns


def rand_state(rng, op):
    st = {}
    for r in GPRS:
        k = rng.random()
        if k < 0.5: v = 0x10000000 + rng.getrandbits(20)
        elif k < 0.7: v = rng.getrandbits(64) if rng.random() < .5 else rng.getrandbits(32)
        elif k < 0.85: v = rng.choice([0, 1, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0x8000000000000000, 0x80000000])
        else: v = rng.randrange(-20, 21) & 0xFFFFFFFFFFFFFFFF
        st[r] = v
    st[UC_X86_REG_RSP] = STACK_BASE + STACK_SIZE // 2 - rng.randrange(0, 64) * 8
    for x in XMMS:
        if rng.random() < .5:
            st[x] = rng.getrandbits(128)
        else:
            st[x] = int.from_bytes(bytes(rng.choice(b"\0abcz09\xff\x80") for _ in range(16)), "little")
    st[UC_X86_REG_EFLAGS] = 0x202 | (rng.getrandbits(12) & FL_MASK_ALL)
    return st


def run(mu, st, start, allowed, check=None):
    for r, v in st.items():
        mu.reg_write(r, v)
    mu.mem_write(STACK_BASE, b"\0" * STACK_SIZE)
    bad = []
    def code(uc, addr, size, ud):
        if not allowed(addr):
            uc.emu_stop()
            return
        if check is not None:
            ins = next(cs.disasm(bytes(uc.mem_read(addr, size)), addr), None)
            if ins is None or ins.mnemonic in FORBIDDEN:
                bad.append((addr, ins.mnemonic if ins else "??"))
    h = mu.hook_add(UC_HOOK_CODE, code)
    try:
        mu.emu_start(start, 0, count=400000)
        err = None
    except UcError as e:
        err = str(e)
    mu.hook_del(h)
    out = {r: mu.reg_read(r) for r in GPRS + XMMS}
    out["rip"] = mu.reg_read(UC_X86_REG_RIP)
    out["fl"] = mu.reg_read(UC_X86_REG_EFLAGS)
    return err, out, bad


def main():
    orig, patched, sites_file = sys.argv[1:4]
    trials = int(sys.argv[4]) if len(sys.argv) > 4 else 30
    sites = []
    for line in open(sites_file):
        if line.startswith("SITE "):
            rva, at, span, how, cave = (int(x, 16) for x in line.split()[1:6])
            sites.append((rva, at, span, how, cave))
    mo, base, _ = load(orig)
    mp, base2, ns = load(patched)
    assert base == base2 and ns
    fails = skipped = ok = 0
    for i, (rva, at, span, how, cave) in enumerate(sites):
        rng = random.Random(rva)
        a0, a1 = base + at, base + at + span
        site_ins = next(cs.disasm(bytes(mo.mem_read(base + rva, 16)), base + rva))
        fmask = FL_MASK_POPCNT if site_ins.mnemonic == "popcnt" else FL_MASK_ALL
        in_span = lambda a: a0 <= a < a1
        def allowed_p(a):
            return in_span(a) or ns[0] <= a < ns[1] or (cave and base + cave <= a < base + cave + 5)
        for t in range(trials):
            st = rand_state(rng, site_ins.mnemonic)
            NONCANON[0] = False
            if DEBUG: print("site %x trial %d orig" % (rva, t), flush=True)
            if site_ins.mnemonic.startswith("pcmp") and "str" in site_ins.mnemonic:
                if span != site_ins.size:
                    skipped += 1; continue
                r1 = expected_pcmpstr(mp, site_ins, st); e1 = None
                if r1 is None:
                    skipped += 1; continue
            else:
                e1, r1, _ = run(mo, st, a0, in_span)
            if e1 or NONCANON[0]:
                skipped += 1
                continue
            if DEBUG: print("site %x trial %d patched" % (rva, t), flush=True)
            e2, r2, bad = run(mp, st, a0, allowed_p, check=True)
            if NONCANON[0]:
                skipped += 1
                continue
            diffs = []
            if e2: diffs.append("patched faulted: " + e2)
            if bad: diffs.append("forbidden insn executed: %r" % bad[:3])
            for k in r1:
                if k == "fl":
                    if (r1[k] ^ r2[k]) & fmask: diffs.append("flags %x vs %x" % (r1[k], r2[k]))
                elif r1[k] != r2[k]:
                    diffs.append("%s %x vs %x" % (k, r1[k], r2[k]))
            if diffs:
                fails += 1
                if fails <= 15:
                    print("FAIL site rva=%x (%s %s) how=%d trial=%d: %s" % (rva, site_ins.mnemonic, site_ins.op_str, how, t, "; ".join(diffs[:4])))
                break
            ok += 1
        if (i + 1) % 100 == 0:
            print("  ...%d/%d sites" % (i + 1, len(sites)), flush=True)
    print("sites=%d trials_ok=%d skipped(orig faulted)=%d FAILED_SITES=%d" % (len(sites), ok, skipped, fails))
    sys.exit(1 if fails else 0)


main()
