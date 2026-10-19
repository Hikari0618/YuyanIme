#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
repack_so_16k.py — 将闭源 arm64 .so 重排为 Android 15+ 16KB 页大小合规。

做法（不反汇编、不改任何指令字节）：
  1. 第一个 PT_LOAD（RX, vaddr 0）内容与地址完全不动。
  2. 其余 RW PT_LOAD 整体搬到 16KB 对齐的新 vaddr，文件偏移 == 新 vaddr
     （保证 p_offset ≡ p_vaddr (mod 16KB)），段间空隙为零填充。
  3. PT_GNU_RELRO 对齐到 16KB 整页：relro 覆盖全部文件后端内容时，
     扩展 LOAD memsz 用全新匿名零页补齐到边界（全量保护保留）；
     否则收缩到 16KB 边界（尾部少量 .got 保持可写，仅损失加固）；
     收缩后为空则置 PT_NULL。
  4. 同步修补所有绝对引用：RELA 的 r_offset / r_addend（地址类重定位）、
     .dynsym 的 st_value、.dynamic 中地址类 DT_* 项、节表地址/偏移。
  5. 自校验：p_align/同余/页不重叠/relro 对齐/内容逐字节比对（除 .dynamic）。

用法：python3 repack_so_16k.py <in.so> <out.so>
"""
import struct
import sys

PAGE = 0x4000  # 16KB

PT_NULL, PT_LOAD, PT_DYNAMIC, PT_NOTE, PT_PHDR = 0, 1, 2, 4, 6
PT_GNU_EH_FRAME, PT_GNU_STACK, PT_GNU_RELRO = 0x6474e550, 0x6474e551, 0x6474e552

SHT_RELA, SHT_DYNSYM, SHT_NOBITS = 4, 11, 8
SHF_ALLOC = 0x2

# 取地址值的 dynamic 标签
DT_ADDR_TAGS = {
    3,          # DT_PLTGOT
    4,          # DT_HASH
    5,          # DT_STRTAB
    6,          # DT_SYMTAB
    7,          # DT_RELA
    12, 13,     # DT_INIT / DT_FINI
    21,         # DT_DEBUG (进程注入, 无需改)
    25, 26,     # DT_INIT_ARRAY / DT_FINI_ARRAY
    0x6ffffef5, # DT_GNU_HASH
    0x6ffffff0, # DT_VERSYM
    0x6ffffffe, # DT_VERNEED
}

# addend 是绝对 vaddr 的 arm64 重定位类型
SHIFT_ADDEND_TYPES = {
    257,    # R_AARCH64_ABS64
    275,    # R_AARCH64_DIR64 (偶尔出现, 语义同 ABS64)
    1025,   # R_AARCH64_GLOB_DAT
    1026,   # R_AARCH64_JUMP_SLOT
    1027,   # R_AARCH64_RELATIVE
    1032,   # R_AARCH64_IRELATIVE
}

PHDR_FMT, PHDR_SZ = '<IIQQQQQQ', 56
SHDR_FMT, SHDR_SZ = '<IIQQQQIIQQ', 64


def align_up(x, a):
    return (x + a - 1) // a * a


def align_dn(x, a):
    return x // a * a


class Phdr:
    def __init__(self, t, flags, off, va, filesz, memsz, align):
        self.type, self.flags, self.offset = t, flags, off
        self.vaddr, self.filesz, self.memsz, self.align = va, filesz, memsz, align


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


def repack(blob, verbose=True):
    elf = ELF(blob)
    orig = blob
    loads = sorted([p for p in elf.phdrs if p.type == PT_LOAD], key=lambda p: p.vaddr)
    assert len(loads) in (2, 3), f'unexpected PT_LOAD count {len(loads)}'
    ld0, ld2 = loads[0], loads[1]
    ld3 = loads[2] if len(loads) == 3 else None
    assert ld0.vaddr == 0 and ld0.filesz == ld0.memsz, 'RX 段不是 vaddr0 且无 bss 的标准布局'
    assert ld0.offset == 0, 'RX 段文件偏移非 0'

    relro = next((p for p in elf.phdrs if p.type == PT_GNU_RELRO), None)
    assert relro is not None, 'no PT_GNU_RELRO'
    relro_len = relro.memsz
    assert relro.vaddr == ld2.vaddr, 'RELRO 不在 RW 段起始'

    # ---- 新布局 ----
    L1_end = ld0.filesz
    D2 = align_up(L1_end, PAGE)
    delta2 = D2 - ld2.vaddr
    memsz2_new = ld2.memsz
    relro_end_raw = D2 + relro_len
    if relro_end_raw % PAGE == 0:
        relro_end, relro_mode = relro_end_raw, 'exact'
    elif ld2.filesz <= relro_len:
        # relro 已覆盖全部文件后端内容 -> 扩展匿名零页补齐到整页（全量保护）
        relro_end = align_up(relro_end_raw, PAGE)
        memsz2_new = max(memsz2_new, relro_end - D2)
        relro_mode = 'extend'
    else:
        # relro 之后还有可写文件内容（.data）-> 收缩到整页，避免把 .data 头部密封
        relro_end = align_dn(relro_end_raw, PAGE)
        relro_mode = 'shrink'
    relro_new_memsz = relro_end - D2
    relro_nullified = relro_new_memsz <= 0

    D3 = None
    delta3 = 0
    if ld3 is not None:
        D3 = align_up(D2 + memsz2_new, PAGE)
        delta3 = D3 - ld3.vaddr
    else:
        D3 = None

    # ---- 平移映射（按原始 vaddr 区间） ----
    ranges = [(ld2.vaddr, ld2.vaddr + max(ld2.memsz, relro_len), delta2, 'RW1')]
    if ld3 is not None:
        ranges.append((ld3.vaddr, ld3.vaddr + ld3.memsz, delta3, 'RW2'))
    for a, b, _d, _n in ranges:
        assert b - a > 0

    def shift(x):
        for a, b, d, _n in ranges:
            if a <= x < b:
                return x + d
        return x

    # ---- 组装新文件 ----
    seg_tail = max(D2 + ld2.filesz, (D3 + ld3.filesz) if ld3 is not None else 0)
    tail_meta = []          # (shdr, new_offset) 非分配节
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

    # ---- 修补 RELA ----
    n_rela = n_add = 0
    unknown_types = {}
    for sh in elf.shdrs:
        if sh.type != SHT_RELA:
            continue
        n = sh.size // 24
        assert sh.link < len(elf.shdrs), 'rela sh_link bad'
        base = shift(sh.addr) if (sh.flags & SHF_ALLOC) else dict(tail_meta)[sh]
        for i in range(n):
            o = base + i * 24
            r_off, r_info, r_add = struct.unpack_from('<QQq', new, o)
            rtype = r_info & 0xffffffff
            new_off = shift(r_off)
            new_add = r_add
            if rtype in SHIFT_ADDEND_TYPES and r_add != 0:
                new_add = shift(r_add)
            if rtype not in SHIFT_ADDEND_TYPES:
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
        n = sh.size // 24
        base = shift(sh.addr)
        for i in range(n):
            o = base + i * 24
            st_name, st_info, st_other, st_shndx, st_value, st_size = \
                struct.unpack_from('<IBBHQQ', new, o)
            if st_shndx != 0 and st_value != 0:
                nv = shift(st_value)
                if nv != st_value:
                    struct.pack_into('<Q', new, o + 8, nv)
                    n_sym += 1

    # ---- 修补 .dynamic ----
    n_dt = 0
    dyn_sh = next(s for s in elf.shdrs if s.type == 6)  # SHT_DYNAMIC
    dyn_base = shift(dyn_sh.addr)
    n_dyn = dyn_sh.size // 16
    for i in range(n_dyn):
        o = dyn_base + i * 16
        tag, val = struct.unpack_from('<QQ', new, o)
        if tag == 0:
            break
        if tag in DT_ADDR_TAGS:
            nv = shift(val)
            if nv != val:
                struct.pack_into('<Q', new, o + 8, nv)
                n_dt += 1

    # ---- 重建 phdr ----
    for p in elf.phdrs:
        if p.type == PT_LOAD:
            if p is ld0:
                p.offset, p.vaddr, p.align = 0, 0, PAGE
            elif p is ld2:
                p.offset, p.vaddr, p.filesz, p.memsz, p.align = D2, D2, ld2.filesz, memsz2_new, PAGE
            else:
                p.offset, p.vaddr, p.align = D3, D3, PAGE
        elif p.type == PT_DYNAMIC:
            p.vaddr = shift(p.vaddr)
            p.offset = p.vaddr
        elif p.type == PT_GNU_RELRO:
            if relro_nullified:
                p.type = PT_NULL
            else:
                p.vaddr, p.offset, p.filesz, p.memsz = \
                    D2, D2, relro_new_memsz, relro_new_memsz
    new[elf.e_phoff:elf.e_phoff + elf.e_phnum * PHDR_SZ] = elf.phdr_bytes()

    # ---- 重建 shdr ----
    tbl = bytearray()
    for sh in elf.shdrs:
        if sh.flags & SHF_ALLOC and sh.addr != 0 and sh.type != 0:
            if sh.type == SHT_NOBITS:
                # NOBITS 放在所属 LOAD 文件后端内容末尾
                if ld2.vaddr <= sh.addr < ld2.vaddr + max(ld2.memsz, relro_len):
                    sh.offset = D2 + ld2.filesz
                elif ld3 is not None and ld3.vaddr <= sh.addr < ld3.vaddr + ld3.memsz:
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
    struct.pack_into('<Q', new, 40, e_shoff_new)  # e_shoff

    if verbose:
        print(f'  RX  [0,        0x{L1_end:x}) vaddr 不变, 内容原样')
        print(f'  RW1 vaddr 0x{ld2.vaddr:x} -> 0x{D2:x} (Δ{delta2:+#x}), '
              f'filesz 0x{ld2.filesz:x}, memsz 0x{ld2.memsz:x} -> 0x{memsz2_new:x}')
        if ld3 is not None:
            print(f'  RW2 vaddr 0x{ld3.vaddr:x} -> 0x{D3:x} (Δ{delta3:+#x}), filesz 0x{ld3.filesz:x}')
        print(f'  RELRO: [{D2:#x}, {relro_end:#x}) mode={relro_mode}'
              + (' (置 PT_NULL, 无 relro 保护)' if relro_nullified else ''))
        print(f'  修补: RELA {n_rela} 条 (addend 改 {n_add}), dynsym st_value {n_sym} 个, DT 地址项 {n_dt} 个')
        if unknown_types:
            print(f'  注意: 未识别 addend 语义的重定位类型 {unknown_types}（未改其 addend）')
        print(f'  文件: {len(orig)} -> {len(new)} 字节')
    return bytes(new), {
        'D2': D2, 'D3': D3, 'delta2': delta2, 'delta3': delta3,
        'relro_mode': relro_mode, 'relro_nullified': relro_nullified,
        'relro_new': (D2, relro_end),
        'memsz2_new': memsz2_new,
    }


def verify(orig, new, meta, verbose=True):
    """对重排结果做独立断言校验，全部通过返回 True。"""
    ok = True

    def chk(cond, msg):
        nonlocal ok
        if not cond:
            ok = False
            print(f'  VERIFY FAIL: {msg}')

    e = ELF(new)
    loads = sorted([p for p in e.phdrs if p.type == PT_LOAD], key=lambda p: p.vaddr)
    # 1. p_align 与同余
    for p in loads:
        chk(p.align == PAGE, f'p_align {p.align:#x} != {PAGE:#x}')
        chk(p.offset % PAGE == p.vaddr % PAGE,
            f'offset {p.offset:#x} 与 vaddr {p.vaddr:#x} 不同余 mod 16KB')
    # 2. 16KB 页区间互不重叠
    prev_end = 0
    for p in loads:
        chk(p.vaddr == 0 or p.vaddr % PAGE == 0, f'LOAD vaddr {p.vaddr:#x} 未 16KB 对齐')
        chk(align_up(prev_end, PAGE) <= align_dn(p.vaddr, PAGE) if p.vaddr else True,
            f'LOAD vaddr {p.vaddr:#x} 与上一段 16KB 页重叠')
        prev_end = p.vaddr + p.memsz
    # 3. relro 16KB 对齐且落在 RW1 内
    relro = next((p for p in e.phdrs if p.type == PT_GNU_RELRO), None)
    if meta['relro_nullified']:
        chk(relro is None, '应已置 PT_NULL 但仍有 GNU_RELRO')
    else:
        chk(relro is not None, 'GNU_RELRO 丢失')
        if relro:
            chk(relro.vaddr % PAGE == 0, 'relro 起始未 16KB 对齐')
            chk(relro.memsz % PAGE == 0, 'relro 长度非 16KB 整数倍')
            rw1 = loads[1]
            chk(rw1.vaddr <= relro.vaddr and
                relro.vaddr + relro.memsz <= rw1.vaddr + rw1.memsz,
                'relro 越出 RW1 段')
    # 4. RX 内容：仅允许 ehdr/phdr 表、.rela、.dynsym 范围内被改动
    ld0 = loads[0]
    oe0 = ELF(orig)
    patch_ranges = [(0, e.e_phoff + e.e_phnum * PHDR_SZ)]
    for s in oe0.shdrs:
        if s.type in (SHT_RELA, SHT_DYNSYM):
            patch_ranges.append((s.offset, s.offset + s.size))
    n_out = 0
    for i in range(ld0.filesz):
        if new[i] != orig[i] and not any(a <= i < b for a, b in patch_ranges):
            n_out += 1
    chk(n_out == 0, f'RX 段在 .rela/.dynsym 之外有 {n_out} 字节差异')
    oe = oe0
    oloads = sorted([p for p in oe.phdrs if p.type == PT_LOAD], key=lambda p: p.vaddr)
    dyn_sh = next(s for s in oe.shdrs if s.type == 6)
    dyn_rng = (dyn_sh.addr, dyn_sh.addr + dyn_sh.size)
    d2, d3 = meta['D2'], meta['D3']
    o2 = oloads[1]
    diff_out_dyn = 0
    for i in range(o2.filesz):
        if new[d2 + i] != orig[o2.offset + i]:
            if not (dyn_rng[0] <= o2.vaddr + i < dyn_rng[1]):
                diff_out_dyn += 1
    chk(diff_out_dyn == 0, f'RW1 段在 .dynamic 之外有 {diff_out_dyn} 字节差异')
    if d3 is not None and len(oloads) > 2:
        o3 = oloads[2]
        chk(new[d3:d3 + o3.filesz] == orig[o3.offset:o3.offset + o3.filesz],
            'RW2 段内容被改动')
    # 6. RELA 逐条核对（要求 .rela 节都在 RX 段内且 offset==addr）
    def shift_chk(x, orels):
        for a, b, d, _ in orels:
            if a <= x < b:
                return x + d
        return x

    orel = [(oloads[1].vaddr, oloads[1].vaddr + max(oloads[1].memsz,
            next(p for p in oe.phdrs if p.type == PT_GNU_RELRO).memsz), meta['delta2'], 'rw1')]
    if len(oloads) > 2:
        orel.append((oloads[2].vaddr, oloads[2].vaddr + oloads[2].memsz, meta['delta3'], 'rw2'))
    n_bad = 0
    for sh_o, sh_n in zip(oe.shdrs, e.shdrs):
        if sh_o.type != SHT_RELA:
            continue
        assert sh_o.addr < oloads[0].filesz and sh_o.addr == sh_o.offset, \
            '.rela 节不在 RX 段（本脚本未覆盖该布局）'
        bo = sh_o.addr  # 原偏移 == 原 vaddr（均在 RX）
        for i in range(sh_o.size // 24):
            r_off_o, r_info_o, r_add_o = struct.unpack_from('<QQq', orig, bo + i * 24)
            r_off_n, r_info_n, r_add_n = struct.unpack_from('<QQq', new, bo + i * 24)
            t = r_info_o & 0xffffffff
            exp_off = shift_chk(r_off_o, orel)
            exp_add = shift_chk(r_add_o, orel) if (t in SHIFT_ADDEND_TYPES and r_add_o) else r_add_o
            if r_off_n != exp_off or r_add_n != exp_add:
                n_bad += 1
    chk(n_bad == 0, f'{n_bad} 条 RELA 修补结果与预期不符')
    # 7. dynsym 核对
    n_bad = 0
    for sh_o in oe.shdrs:
        if sh_o.type != SHT_DYNSYM:
            continue
        bo, bn = sh_o.addr, sh_o.addr
        for i in range(sh_o.size // 24):
            so = struct.unpack_from('<IBBHQQ', orig, bo + i * 24)
            sn = struct.unpack_from('<IBBHQQ', new, bn + i * 24)
            exp = shift_chk(so[4], orel) if (so[3] != 0 and so[4]) else so[4]
            if sn[4] != exp:
                n_bad += 1
    chk(n_bad == 0, f'{n_bad} 个 dynsym st_value 与预期不符')
    if verbose:
        print('  VERIFY: ' + ('全部通过 ✔' if ok else '存在失败项 ✘'))
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
