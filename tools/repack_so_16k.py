#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
repack_so_16k.py — 将闭源 arm64 .so 重排为 Android 15+ 16KB 页大小合规。

做法（不改逻辑，只做 ELF 布局手术）：
  1. 第一个 PT_LOAD（RX, vaddr 0）内容与地址完全不动。
  2. 其余 RW PT_LOAD 整体搬到新 vaddr，文件偏移镜像新 vaddr（保证
     p_offset ≡ p_vaddr (mod 16KB)），段间空隙零填充。
     **平移量取 16KB 的整数倍**（三个库实际都取 +0x4000）：页内低 12 位
     不变，所有 ADRP 页偏移只需统一加 delta/4096。
  3. PT_GNU_RELRO 随段平移（vaddr/offset 更新，filesz/memsz 不变）：
     原库 relro 首尾本就在 16KB 边界（lld 保证），平移量为 16KB 整数倍
     → 仍保持对齐，保护范围与原来完全一致。
  4. 修补全部绝对 / PC 相对引用：
     - RELA 的 r_offset / r_addend（地址类重定位）
     - .dynsym 的 st_value
     - .dynamic 中地址类 DT_* 项（INIT_ARRAY/FINI_ARRAY/PLTGOT 等）
     - **可执行段内所有指向被搬段的 ADRP（页偏移）与 ADR（精确偏移）**
       —— 漏了这一步，PLT 桩与 .text 里取 GOT/数据地址的 adrp 仍算旧
       地址，dlopen 后第一次调用即 SIGSEGV（本仓库第一版就栽在这里）。
  5. 自校验：p_align / 同余 / 16KB 页不重叠 / relro 页对齐 / 内容逐字节
     比对（除 .dynamic/.rela/.dynsym/adrp 位域）、每条 ADRP/ADR 语义
     核对、PLT 桩目标必须落在 .got.plt 内。

用法：python3 repack_so_16k.py <in.so> <out.so>
"""
import struct
import sys

PAGE = 0x4000      # 16KB（内核 mmap 粒度）
PAGE4 = 0x1000     # ADRP/页内偏移粒度 4KB

PT_NULL, PT_LOAD, PT_DYNAMIC, PT_NOTE, PT_PHDR = 0, 1, 2, 4, 6
PT_GNU_EH_FRAME, PT_GNU_STACK, PT_GNU_RELRO = 0x6474e550, 0x6474e551, 0x6474e552

SHT_RELA, SHT_DYNSYM, SHT_NOBITS, SHT_PROGBITS = 4, 11, 8, 1
SHF_ALLOC, SHF_EXECINSTR = 0x2, 0x4

DT_ADDR_TAGS = {
    3, 4, 5, 6, 7, 12, 13, 25, 26,
    0x6ffffef5, 0x6ffffff0, 0x6ffffffe,
}
SHIFT_ADDEND_TYPES = {257, 275, 1025, 1026, 1027, 1032}

ADRP_MASK, ADRP_OP = 0x9F000000, 0x90000000
ADR_MASK, ADR_OP = 0x9F000000, 0x10000000
LDR_LIT_MASK, LDR_LIT_OP = 0x3B000000, 0x18000000

PHDR_FMT, PHDR_SZ = '<IIQQQQQQ', 56
SHDR_FMT, SHDR_SZ = '<IIQQQQIIQQ', 64


def align_up(x, a):
    return (x + a - 1) // a * a


def align_dn(x, a):
    return x // a * a


def sx(v, bits):
    return v - (1 << bits) if v & (1 << (bits - 1)) else v


class Phdr:
    def __init__(self, t, flags, off, va, fsz, msz, al):
        self.type, self.flags, self.offset = t, flags, off
        self.vaddr, self.filesz, self.memsz, self.align = va, fsz, msz, al


class Shdr:
    def __init__(self, name, t, flags, addr, off, size, link, info, al, es):
        self.name, self.type, self.flags = name, t, flags
        self.addr, self.offset, self.size = addr, off, size
        self.link, self.info, self.align, self.entsize = link, info, al, es


class ELF:
    def __init__(self, blob):
        assert blob[:4] == b'\x7fELF', 'not ELF'
        assert blob[4] == 2 and blob[5] == 1, 'need ELF64 little-endian'
        assert struct.unpack_from('<H', blob, 18)[0] == 183, 'need arm64'
        (self.e_type, self.e_machine, self.e_version) = struct.unpack_from('<HHI', blob, 16)
        (self.e_entry, self.e_phoff, self.e_shoff) = struct.unpack_from('<QQQ', blob, 24)
        self.e_flags = struct.unpack_from('<I', blob, 48)[0]
        (self.e_phentsize, self.e_phnum, self.e_shentsize,
         self.e_shnum, self.e_shstrndx) = struct.unpack_from('<HHHHH', blob, 54)
        self.phdrs = []
        for i in range(self.e_phnum):
            t, fl, off, va, pa, fsz, msz, al = struct.unpack_from(
                PHDR_FMT, blob, self.e_phoff + i * PHDR_SZ)
            self.phdrs.append(Phdr(t, fl, off, va, fsz, msz, al))
        self.shdrs = []
        for i in range(self.e_shnum):
            self.shdrs.append(Shdr(*struct.unpack_from(
                SHDR_FMT, blob, self.e_shoff + i * SHDR_SZ)))

    def phdr_bytes(self):
        out = bytearray()
        for p in self.phdrs:
            out += struct.pack(PHDR_FMT, p.type, p.flags, p.offset, p.vaddr,
                               p.vaddr, p.filesz, p.memsz, p.align)
        return bytes(out)


def layout(elf):
    """计算新布局。返回 (loads, segs)。segs = [(orig_vaddr, memsz, delta)]，delta 为 16KB 整数倍。"""
    loads = sorted([p for p in elf.phdrs if p.type == PT_LOAD], key=lambda p: p.vaddr)
    assert len(loads) in (2, 3), f'unexpected PT_LOAD count {len(loads)}'
    assert loads[0].vaddr == 0 and loads[0].filesz == loads[0].memsz, 'RX 段布局非常规'
    assert loads[0].offset == 0, 'RX 段文件偏移非 0'
    segs = []
    prev_end = loads[0].vaddr + loads[0].memsz
    for p in loads[1:]:
        base = align_up(prev_end, PAGE)          # 前段 16KB 映射页尾
        delta = align_up(base - p.vaddr, PAGE)   # 取 16KB 整数倍，使页内低 12 位不变
        assert PAGE * ((p.vaddr + delta) // PAGE) >= base
        segs.append((p.vaddr, p.memsz, delta))
        prev_end = p.vaddr + delta + p.memsz
    return loads, segs


def in_moved(x, segs):
    for v, msz, d in segs:
        if v <= x < v + msz:
            return d
    return None


def page_span(v, msz):
    """一条段覆盖的 4KB 页区间 [lo, hi]（含）。"""
    return align_dn(v, PAGE4), align_dn(v + msz - 1, PAGE4)


def moved_page_delta(page, segs):
    for v, msz, d in segs:
        lo, hi = page_span(v, msz)
        if lo <= page <= hi:
            return d
    return None


def patch_code_refs(new, elf, orig, segs, verbose=True):
    """修正可执行段内指向被搬段的 ADRP（页偏移）与 ADR（精确偏移）。"""
    n_adrp = n_adr = 0
    l1_end = min(p.vaddr + p.filesz for p in elf.phdrs if p.type == PT_LOAD)
    for sh in elf.shdrs:
        if not (sh.flags & SHF_EXECINSTR) or sh.type != SHT_PROGBITS:
            continue
        assert sh.addr + sh.size <= l1_end, '可执行段不在 RX 内，本脚本未覆盖'
        for i in range(0, sh.size - 3, 4):
            off = sh.offset + i          # RX 内 offset == addr
            pc = sh.addr + i
            insn = struct.unpack_from('<I', orig, off)[0]
            if (insn & ADRP_MASK) == ADRP_OP:
                imm = sx(((insn >> 5) & 0x7FFFF) << 2 | ((insn >> 29) & 3), 21) << 12
                tgt = (align_dn(pc, PAGE4) + imm) & ~(PAGE4 - 1)
                delta = moved_page_delta(tgt, segs)
                if delta is None:
                    continue
                new_imm = imm + delta
                assert -(1 << 32) < new_imm < (1 << 32), 'ADRP 立即数越界'
                immlo, immhi = (new_imm >> 12) & 3, (new_imm >> 14) & 0x7FFFF
                ni = (insn & ~((3 << 29) | (0x7FFFF << 5))) | (immlo << 29) | (immhi << 5)
                struct.pack_into('<I', new, off, ni)
                n_adrp += 1
            elif (insn & ADR_MASK) == ADR_OP:
                imm = sx(((insn >> 5) & 0x7FFFF) << 2 | ((insn >> 29) & 3), 21)
                tgt = pc + imm
                delta = in_moved(tgt, segs)
                if delta is None:
                    continue
                new_imm = imm + delta
                assert -(1 << 20) < new_imm < (1 << 20), 'ADR 立即数越界'
                immlo, immhi = new_imm & 3, (new_imm >> 2) & 0x7FFFF
                ni = (insn & ~((3 << 29) | (0x7FFFF << 5))) | (immlo << 29) | (immhi << 5)
                struct.pack_into('<I', new, off, ni)
                n_adr += 1
            elif (insn & LDR_LIT_MASK) == LDR_LIT_OP:
                imm = sx((insn >> 5) & 0x7FFFF, 19) << 2
                tgt = pc + imm
                assert in_moved(tgt, segs) is None, \
                    f'发现 LDR-literal 指向被搬段 @0x{pc:x} -> 0x{tgt:x}，脚本不支持该布局'
    if verbose:
        print(f'  修补代码引用: ADRP {n_adrp} 条, ADR {n_adr} 条')
    return n_adrp, n_adr


def repack(blob, verbose=True):
    elf = ELF(blob)
    orig = blob
    loads, segs = layout(elf)
    ld0, ld2 = loads[0], loads[1]
    ld3 = loads[2] if len(loads) == 3 else None
    v2, msz2, delta2 = segs[0]
    D2 = v2 + delta2
    delta3 = segs[1][2] if len(segs) > 1 else 0
    D3 = segs[1][0] + delta3 if len(segs) > 1 else None

    relro = next((p for p in elf.phdrs if p.type == PT_GNU_RELRO), None)
    assert relro is not None and relro.vaddr == ld2.vaddr, 'RELRO 不在 RW 段起始'
    relro_len = relro.memsz
    assert (v2 + relro_len) % PAGE == 0, \
        f'原库 relro 尾 0x{v2 + relro_len:x} 不在 16KB 边界，需改用缩/扩方案'

    # ---- 组装新文件 ----
    seg_tail = max(D2 + ld2.filesz, (D3 + ld3.filesz) if ld3 is not None else 0)
    tail_meta = []
    cur = align_up(seg_tail, 8)
    for sh in elf.shdrs:
        if sh.flags & SHF_ALLOC:
            continue
        if sh.type == SHT_NOBITS or sh.size == 0 or sh.type == 0:
            if sh.type != 0 and sh.size == 0:
                tail_meta.append((sh, cur))
            continue
        tail_meta.append((sh, cur))
        cur = align_up(cur + sh.size, 8)
    e_shoff_new = cur
    total = e_shoff_new + elf.e_shnum * SHDR_SZ
    new = bytearray(total)

    def copy_seg(ld, new_vaddr):
        new[new_vaddr:new_vaddr + ld.filesz] = orig[ld.offset:ld.offset + ld.filesz]

    copy_seg(ld0, 0)
    copy_seg(ld2, D2)
    if ld3 is not None:
        copy_seg(ld3, D3)
    for sh, off in tail_meta:
        new[off:off + sh.size] = orig[sh.offset:sh.offset + sh.size]

    def shift(x):
        d = in_moved(x, segs)
        return x + d if d is not None else x

    # ---- 修补 RELA ----
    n_rela = n_add = 0
    unknown_types = {}
    for sh in elf.shdrs:
        if sh.type != SHT_RELA:
            continue
        assert sh.addr < ld0.filesz and sh.addr == sh.offset, '.rela 不在 RX 段'
        for i in range(sh.size // 24):
            o = sh.addr + i * 24
            r_off, r_info, r_add = struct.unpack_from('<QQq', new, o)
            rtype = r_info & 0xffffffff
            new_off = shift(r_off)
            new_add = r_add
            if rtype in SHIFT_ADDEND_TYPES and r_add != 0:
                new_add = shift(r_add)
            elif rtype not in SHIFT_ADDEND_TYPES:
                unknown_types[rtype] = unknown_types.get(rtype, 0) + 1
            if new_off != r_off or new_add != r_add:
                struct.pack_into('<QQq', new, o, new_off, r_info, new_add)
            n_rela += 1
            if new_add != r_add:
                n_add += 1

    # ---- 修补 .dynsym ----
    n_sym = 0
    for sh in elf.shdrs:
        if sh.type != SHT_DYNSYM:
            continue
        for i in range(sh.size // 24):
            o = sh.addr + i * 24
            st_name, st_info, st_other, st_shndx, st_value, st_size = \
                struct.unpack_from('<IBBHQQ', new, o)
            if st_shndx != 0 and st_value != 0:
                nv = shift(st_value)
                if nv != st_value:
                    struct.pack_into('<Q', new, o + 8, nv)
                    n_sym += 1

    # ---- 修补 .dynamic ----
    n_dt = 0
    dyn_sh = next(s for s in elf.shdrs if s.type == 6)
    for i in range(dyn_sh.size // 16):
        o = shift(dyn_sh.addr) + i * 16
        tag, val = struct.unpack_from('<QQ', new, o)
        if tag == 0:
            break
        if tag in DT_ADDR_TAGS:
            nv = shift(val)
            if nv != val:
                struct.pack_into('<Q', new, o + 8, nv)
                n_dt += 1

    # ---- 修补代码中的 ADRP/ADR（关键） ----
    n_adrp, n_adr = patch_code_refs(new, elf, orig, segs, verbose)

    # ---- 重建 phdr ----
    for p in elf.phdrs:
        if p.type == PT_LOAD:
            if p is ld0:
                p.offset, p.vaddr, p.align = 0, 0, PAGE
            elif p is ld2:
                p.offset, p.vaddr, p.align = D2, D2, PAGE
            else:
                p.offset, p.vaddr, p.align = D3, D3, PAGE
        elif p.type == PT_DYNAMIC:
            p.vaddr = shift(p.vaddr)
            p.offset = p.vaddr
        elif p.type == PT_GNU_RELRO:
            p.vaddr, p.offset = D2, D2
    new[elf.e_phoff:elf.e_phoff + elf.e_phnum * PHDR_SZ] = elf.phdr_bytes()

    # ---- 重建 shdr ----
    tbl = bytearray()
    for sh in elf.shdrs:
        if sh.flags & SHF_ALLOC and sh.addr != 0 and sh.type != 0:
            if sh.type == SHT_NOBITS:
                if v2 <= sh.addr < v2 + msz2:
                    sh.offset = D2 + ld2.filesz
                elif ld3 is not None and segs[1][0] <= sh.addr < segs[1][0] + ld3.memsz:
                    sh.offset = D3 + ld3.filesz
                else:
                    sh.offset = sh.addr
                sh.addr = shift(sh.addr)
            else:
                sh.addr = shift(sh.addr)
                sh.offset = sh.addr
        else:
            sh.offset = dict(tail_meta).get(sh, sh.offset)
        tbl += struct.pack(SHDR_FMT, sh.name, sh.type, sh.flags, sh.addr,
                           sh.offset, sh.size, sh.link, sh.info, sh.align, sh.entsize)
    new[e_shoff_new:e_shoff_new + len(tbl)] = tbl
    struct.pack_into('<Q', new, 40, e_shoff_new)

    meta = {'D2': D2, 'D3': D3, 'delta2': delta2, 'delta3': delta3, 'segs': segs,
            'relro': (D2, D2 + relro_len), 'n_adrp': n_adrp, 'n_adr': n_adr}
    if verbose:
        print(f'  RX  [0, 0x{ld0.filesz:x}) 不变')
        print(f'  RW1 vaddr 0x{v2:x} -> 0x{D2:x} (Δ{delta2:+#x}), memsz 0x{msz2:x}')
        if ld3 is not None:
            print(f'  RW2 vaddr 0x{segs[1][0]:x} -> 0x{D3:x} (Δ{delta3:+#x}), memsz 0x{ld3.memsz:x}')
        print(f'  RELRO [{D2:#x}, {D2 + relro_len:#x})（原长度不变，两端仍 16KB 对齐）')
        print(f'  修补: RELA {n_rela} (addend {n_add}), dynsym {n_sym}, DT {n_dt}')
        if unknown_types:
            print(f'  注意: 未知 addend 重定位类型 {unknown_types}')
        print(f'  文件: {len(orig)} -> {len(new)} 字节')
    return bytes(new), meta


def verify(orig, new, meta, verbose=True):
    ok = True

    def chk(cond, msg):
        nonlocal ok
        if not cond:
            ok = False
            print(f'  VERIFY FAIL: {msg}')

    e, oe = ELF(new), ELF(orig)
    loads = sorted([p for p in e.phdrs if p.type == PT_LOAD], key=lambda p: p.vaddr)
    oloads = sorted([p for p in oe.phdrs if p.type == PT_LOAD], key=lambda p: p.vaddr)
    segs = meta['segs']

    # 1. p_align / 同余 / 16KB 页不重叠
    for p in loads:
        chk(p.align == PAGE, f'p_align {p.align:#x}')
        chk(p.offset % PAGE == p.vaddr % PAGE, 'offset/vaddr 不同余 mod 16KB')
    for a, b in zip(loads, loads[1:]):
        chk(align_dn(b.vaddr, PAGE) >= align_up(a.vaddr + a.memsz, PAGE),
            f'LOAD 0x{b.vaddr:x} 与上一段 16KB 页重叠')

    # 2. relro：两端 16KB 对齐，落在 RW1 的 16KB 映射内
    relro = next((p for p in e.phdrs if p.type == PT_GNU_RELRO), None)
    chk(relro is not None, 'RELRO 丢失')
    if relro:
        lo, hi = meta['relro']
        chk(relro.vaddr == lo and relro.vaddr + relro.memsz == hi, 'relro 范围不符')
        chk(align_dn(lo, PAGE) >= align_up(loads[0].vaddr + loads[0].memsz, PAGE),
            'relro 起点 16KB 页压到 RX 段')
        chk(hi % PAGE == 0, 'relro 尾未 16KB 对齐')
        nx = loads[2].vaddr if len(loads) > 2 else (1 << 62)
        chk(align_up(hi, PAGE) <= align_dn(nx, PAGE), 'relro 尾 16KB 页压到下一段')

    # 3. 内容比对：RX 只允许 ehdr/phdr/.rela/.dynsym/adrp 位域变化
    ld0 = loads[0]
    allow = [(0, e.e_phoff + e.e_phnum * PHDR_SZ)] + \
            [(s.offset, s.offset + s.size) for s in oe.shdrs
             if s.type in (SHT_RELA, SHT_DYNSYM)]
    exec_secs = [s for s in oe.shdrs if (s.flags & SHF_EXECINSTR) and s.type == SHT_PROGBITS]

    def in_exec(i):
        return any(s.offset <= i < s.offset + s.size for s in exec_secs)

    n_out = 0
    for i in range(ld0.filesz):
        if new[i] != orig[i] and not any(a <= i < b for a, b in allow) and not in_exec(i):
            n_out += 1
    chk(n_out == 0, f'RX 段出现 {n_out} 字节意外差异')

    o2 = oloads[1]
    d2 = meta['D2']
    dyn_sh = next(s for s in oe.shdrs if s.type == 6)
    dyn_rng = (dyn_sh.addr, dyn_sh.addr + dyn_sh.size)
    diff = sum(1 for i in range(o2.filesz)
               if new[d2 + i] != orig[o2.offset + i]
               and not (dyn_rng[0] <= o2.vaddr + i < dyn_rng[1]))
    chk(diff == 0, f'RW1 在 .dynamic 外有 {diff} 字节差异')
    if len(oloads) > 2:
        o3, d3 = oloads[2], meta['D3']
        chk(new[d3:d3 + o3.filesz] == orig[o3.offset:o3.offset + o3.filesz], 'RW2 内容被改')

    # 4. RELA / dynsym / DT 语义核对
    def shift_chk(x):
        for v, msz, d in segs:
            if v <= x < v + msz:
                return x + d
        return x

    bad = 0
    for sh in oe.shdrs:
        if sh.type != SHT_RELA:
            continue
        for i in range(sh.size // 24):
            a = struct.unpack_from('<QQq', orig, sh.addr + i * 24)
            b = struct.unpack_from('<QQq', new, sh.addr + i * 24)
            t = a[1] & 0xffffffff
            exp_add = shift_chk(a[2]) if (t in SHIFT_ADDEND_TYPES and a[2]) else a[2]
            if b[0] != shift_chk(a[0]) or b[2] != exp_add:
                bad += 1
    chk(bad == 0, f'{bad} 条 RELA 修补不符')
    bad = 0
    for sh in oe.shdrs:
        if sh.type != SHT_DYNSYM:
            continue
        for i in range(sh.size // 24):
            a = struct.unpack_from('<IBBHQQ', orig, sh.addr + i * 24)
            b = struct.unpack_from('<IBBHQQ', new, sh.addr + i * 24)
            exp = shift_chk(a[4]) if (a[3] != 0 and a[4]) else a[4]
            if b[4] != exp:
                bad += 1
    chk(bad == 0, f'{bad} 个 dynsym 不符')
    bad = 0
    for i in range(dyn_sh.size // 16):
        a = struct.unpack_from('<QQ', orig, dyn_sh.offset + i * 16)
        b = struct.unpack_from('<QQ', new, shift_chk(dyn_sh.addr) + i * 16)
        if a[0] != b[0]:
            bad += 1
        elif a[0] in DT_ADDR_TAGS and b[1] != shift_chk(a[1]):
            bad += 1
        elif a[0] not in DT_ADDR_TAGS and a[1] != b[1]:
            bad += 1
    chk(bad == 0, f'{bad} 个 DT 项不符')

    # 5. 逐指令核对：exec 段内除 adrp/adr 外指令必须原样；adrp/adr 语义正确
    n_adrp_ok = n_adr_ok = 0
    bad = 0
    for sh in exec_secs:
        for i in range(0, sh.size - 3, 4):
            a = struct.unpack_from('<I', orig, sh.offset + i)[0]
            b = struct.unpack_from('<I', new, sh.offset + i)[0]
            pc = sh.addr + i
            if a == b:
                continue
            if (a & ADRP_MASK) == ADRP_OP:
                imm_a = sx(((a >> 5) & 0x7FFFF) << 2 | ((a >> 29) & 3), 21) << 12
                imm_b = sx(((b >> 5) & 0x7FFFF) << 2 | ((b >> 29) & 3), 21) << 12
                tgt_a = (align_dn(pc, PAGE4) + imm_a) & ~(PAGE4 - 1)
                tgt_b = (align_dn(pc, PAGE4) + imm_b) & ~(PAGE4 - 1)
                d = moved_page_delta(tgt_a, segs)
                if d is not None and tgt_b == tgt_a + d:
                    n_adrp_ok += 1
                else:
                    bad += 1
            elif (a & ADR_MASK) == ADR_OP:
                imm_a = sx(((a >> 5) & 0x7FFFF) << 2 | ((a >> 29) & 3), 21)
                imm_b = sx(((b >> 5) & 0x7FFFF) << 2 | ((b >> 29) & 3), 21)
                d = in_moved(pc + imm_a, segs)
                if d is not None and pc + imm_b == pc + imm_a + d:
                    n_adr_ok += 1
                else:
                    bad += 1
            else:
                bad += 1     # 非 adrp/adr 的指令被改动
    chk(bad == 0, f'{bad} 条指令改动异常')
    chk(n_adrp_ok == meta['n_adrp'], f'ADRP 核对数 {n_adrp_ok} != 修补数 {meta["n_adrp"]}')
    chk(n_adr_ok == meta['n_adr'], f'ADR 核对数 {n_adr_ok} != 修补数 {meta["n_adr"]}')

    # 6. PLT 桩：adrp 目标页 + ldr 低 12 位 必须落在 GOT（.got.plt 或 .got）内
    shstr = oe.shdrs[oe.e_shstrndx]
    names = orig[shstr.offset:shstr.offset + shstr.size]

    def shname(s):
        return names[s.name:names.find(b'\0', s.name)].decode()

    # GOT 区：优先 .got.plt，没有则用 DT_PLTGOT 所在节（如 SogouShell 的 .got）
    gp = None
    try:
        gp = next(s for s in e.shdrs if shname(s) == '.got.plt')
    except StopIteration:
        pltgot = None
        for i in range(dyn_sh.size // 16):
            t, v = struct.unpack_from('<QQ', new, shift_chk(dyn_sh.addr) + i * 16)
            if t == 3:
                pltgot = v
                break
        if pltgot is not None:
            gp = next((s for s in e.shdrs
                       if s.addr <= pltgot < s.addr + s.size), None)
    gp_addr = gp.addr if gp else -1
    gp_end = gp.addr + gp.size if gp else -2
    bad = n_plt = 0
    for sh in oe.shdrs:
        if shname(sh) != '.plt' or sh.type != SHT_PROGBITS:
            continue
        for i in range(0, sh.size - 4, 4):
            a = struct.unpack_from('<I', new, sh.offset + i)[0]
            if (a & ADRP_MASK) != ADRP_OP:
                continue
            imm = sx(((a >> 5) & 0x7FFFF) << 2 | ((a >> 29) & 3), 21) << 12
            page = (align_dn(sh.addr + i, PAGE4) + imm) & ~(PAGE4 - 1)
            nxt = struct.unpack_from('<I', new, sh.offset + i + 4)[0]
            if (nxt & 0xFFC00000) != 0xF9400000:
                continue
            low = ((nxt >> 10) & 0xfff) << 3
            n_plt += 1
            if not (gp_addr <= page + low < gp_end):
                bad += 1
    chk(bad == 0, f'{bad} 个 PLT 桩未指向 .got.plt（共 {n_plt}）')
    if verbose:
        print(f'  ADRP 核对 {n_adrp_ok} 条、ADR {n_adr_ok} 条、PLT 桩 {n_plt} 个；'
              + ('全部通过 ✔' if ok else '存在失败项 ✘'))
    return ok


def main():
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(1)
    src, dst = sys.argv[1], sys.argv[2]
    with open(src, 'rb') as f:
        orig = f.read()
    print(f'== {src} ({len(orig)} 字节)')
    new, meta = repack(orig)
    if not verify(orig, new, meta):
        print('校验失败, 不写出')
        sys.exit(1)
    with open(dst, 'wb') as f:
        f.write(new)
    print(f'  写出 {dst}')


if __name__ == '__main__':
    main()
