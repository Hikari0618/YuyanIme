#!/usr/bin/env bash
# 语燕输入法 —— 日常打包流程（构建 → 归档 → 签名/zip → 严格 ELF 16KB 校验）
#
# 用法:  tools/build_and_check.sh
#
# 严格判据（比 zipalign -P 16 严得多，后者只查 APK 里条目的存储偏移）：
#   1. 每个 PT_LOAD: p_align >= 0x4000
#   2. 每个 PT_LOAD: p_offset ≡ p_vaddr (mod 0x4000)   —— 同余，很多脚本漏查
#   3. 相邻 LOAD 的 16KB 页区间不重叠
#   4. PT_GNU_RELRO 终点 16KB 对齐
#      （起点【不必】对齐：连 NDK 自己编的 libyuyanime 起点也不对齐，真机一直正常；
#        真正致命的是终点不对齐 —— bionic 的 mprotect 会把后面的 .data 头封成只读）
#   5. 校验对象是【归档 APK 里解出来的 .so】，不是源目录（源目录合规 ≠ 打包产物合规）
#
# 退出码: 全部通过 0，否则非 0（构建失败 / 归档异常 / ELF 不合规）
set -uo pipefail

export JAVA_HOME=/home/cheny/jdk17
export ANDROID_HOME=/home/cheny/android-sdk
BT="$ANDROID_HOME/build-tools/35.0.0"
ROOT=/mnt/f/语燕输入法/YuyanIme
cd "$ROOT" || exit 1

echo "== 0) 内存检查 =="
AVAIL=$(free -m | awk '/^Mem:/{print $7}')
echo "  available=${AVAIL}MB"
if [ "$AVAIL" -lt 1500 ]; then
    ./gradlew --stop >/dev/null 2>&1
    # 注意中括号写法：pkill -f GradleDaemon 会匹配到自己这条命令行
    pkill -f "[G]radleDaemon" 2>/dev/null
    pkill -f "[K]otlinCompileDaemon" 2>/dev/null
    sleep 4
    echo "  已清理 daemon"
fi

echo "== 1) 构建 (debug + release) =="
LOG="/home/cheny/.hermes/cache/scratch/build_$(date +%H%M%S).log"
START=$(date +%s)
./gradlew :app:assembleOfflineDebug :app:assembleOfflineRelease --max-workers=2 >"$LOG" 2>&1
RC=$?
# /mnt/f 是 Windows 挂载点，Gradle daemon 偶发 "Could not read directory path ..."（上一版同样的
# 代码能过，纯瞬时 IO 错误）。这种情况重试一次，别让 4 分钟白等。
if [ "$RC" -ne 0 ] && grep -q "Could not read directory" "$LOG"; then
    echo "  ⚠ /mnt/f 瞬时 IO 错误（Could not read directory），重试一次"
    sleep 3
    ./gradlew :app:assembleOfflineDebug :app:assembleOfflineRelease --max-workers=2 >"$LOG" 2>&1
    RC=$?
fi
ELAPSED=$(( $(date +%s) - START ))
echo "  EXIT=$RC  用时 $((ELAPSED / 60))分$((ELAPSED % 60))秒"
if [ "$RC" -ne 0 ]; then
    grep -E "^e: |FAILED|Cannot allocate" "$LOG" | head -20
    echo "✗ 构建失败，未归档（日志: $LOG）"
    exit 1
fi

echo "== 2) 归档 =="
TS=$(date +%Y%m%d_%H%M)
OUT="/mnt/f/语燕输入法/输出/$TS"
mkdir -p "$OUT"
find app/build/outputs/apk -name "*.apk" -newermt "-12 minutes" -exec cp {} "$OUT/" \;
CNT=$(ls -1 "$OUT" 2>/dev/null | wc -l)
if [ "$CNT" -lt 2 ]; then
    echo "✗ 只找到 $CNT 个 APK（可能混入了旧包），撤销归档"
    rm -rf "$OUT"
    exit 1
fi
echo "  → $OUT （$CNT 个）"
ls -l --time-style=+"%H:%M" "$OUT" | tail -n +2

echo "== 3) 签名 / zip 内 16K 偏移 =="
for f in "$OUT"/*.apk; do
    SIGN="✗"; ZIP="✗"
    "$BT/apksigner" verify "$f" >/dev/null 2>&1 && SIGN="✓"
    "$BT/zipalign" -c -P 16 -v 4 "$f" >/dev/null 2>&1 && ZIP="✓"
    printf "  %-42s 签名:%s  zipalign16K:%s\n" "$(basename "$f")" "$SIGN" "$ZIP"
done

echo "== 4) 严格 ELF 校验（APK 内解出全部 .so）=="
APK="$OUT/$(ls -1 "$OUT" | grep release | head -1)"
[ -z "$APK" ] && APK=$(ls -1 "$OUT"/*.apk | head -1)
python3 - "$APK" <<'PY'
import sys, zipfile, struct
PAGE = 0x4000
PT_LOAD, PT_RELRO = 1, 0x6474E552

def align_dn(x): return x // PAGE * PAGE
def align_up(x): return (x + PAGE - 1) // PAGE * PAGE

z = zipfile.ZipFile(sys.argv[1])
bad = n = 0
for name in sorted(x for x in z.namelist() if x.startswith("lib/") and x.endswith(".so")):
    b = z.read(name)
    n += 1
    if b[:4] != b"\x7fELF" or b[4] != 2 or b[5] != 1:
        print(f"  SKIP {name}（非 64 位小端 ELF）")
        continue
    phoff = struct.unpack_from("<Q", b, 32)[0]
    phentsize, phnum = struct.unpack_from("<HH", b, 54)
    loads, relro = [], None
    for i in range(phnum):
        p = phoff + i * phentsize
        t = struct.unpack_from("<I", b, p)[0]
        off, va, _pa, _fsz, msz, al = struct.unpack_from("<QQQQQQ", b, p + 8)
        if t == PT_LOAD:
            loads.append((off, va, msz, al))
        elif t == PT_RELRO:
            relro = (va, msz)
    errs = []
    for off, va, _msz, al in loads:
        if al < PAGE:
            errs.append(f"p_align={al:#x} < 0x4000")
        if off % PAGE != va % PAGE:
            errs.append(f"offset={off:#x} 与 vaddr={va:#x} 不同余 mod 16K")
    s = sorted(loads, key=lambda x: x[1])
    for a, c in zip(s, s[1:]):
        if align_dn(a[1]) + align_up(a[2]) > align_dn(c[1]):
            errs.append(f"16K 页重叠: {a[1]:#x}+{a[2]:#x} 与 {c[1]:#x}")
    if relro and (relro[0] + relro[1]) % PAGE:
        errs.append(f"RELRO 终点 {relro[0] + relro[1]:#x} 未 16K 对齐")
    if errs:
        bad += 1
    print(f"  {'OK  ' if not errs else 'FAIL'} {name.split('/')[-1]:24s} LOAD={len(loads)} " + "; ".join(errs))
print(f"\n共 {n} 个 .so，不合规 {bad} 个")
sys.exit(1 if bad else 0)
PY
RC=$?

echo
if [ "$RC" -eq 0 ] && [ "$CNT" -ge 2 ]; then
    echo "✓✓ 全部通过 —— $OUT"
else
    echo "✗ ELF 校验未通过 —— $OUT（不要在真机上把它当「通过」的包）"
fi
exit "$RC"
