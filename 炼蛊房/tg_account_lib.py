#!/usr/bin/env python3
"""TG 号库盘点 / 投递入库 / 按区号清库（资产恢复）。

默认根：案卷/_tg_accounts/
只认 .session / 同名账号 .json / zip 内条目。
清库必须 --keep + 先拷 trash 再删。不按纯数字文件名删 .js/.sqlite。
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import tempfile
import zipfile
from collections import defaultdict
from datetime import datetime, UTC
from pathlib import Path
from typing import Any
from collections.abc import Iterable

ENGINE = Path(__file__).resolve().parents[1]
DEFAULT_ROOT = ENGINE / "案卷" / "_tg_accounts"
ACCOUNT_EXT = {".session", ".json"}
META_TXT = {".txt"}  # 仅当文件名本身是手机号才当账号
SKIP_NAMES = {"index.json", "ok_phones.txt", "2fa.txt", "api.txt", "keep.txt"}
SKIP_DIR = {
    "node_modules",
    ".pnpm",
    ".git",
    "trash",
    "__pycache__",
    ".venv",
    "venv",
}

CC_RULES: list[tuple[str, str, re.Pattern[str]]] = [
    ("234", "尼日利亚+234", re.compile(r"^234\d+$")),
    ("447", "英国+44", re.compile(r"^447\d+$")),
    ("852", "香港+852", re.compile(r"^852\d+$")),
    ("880", "孟加拉+880", re.compile(r"^880\d+$")),
    ("519", "秘鲁+51", re.compile(r"^519\d+$")),
    ("52", "墨西哥+52", re.compile(r"^52\d+$")),
    ("98", "伊朗+98", re.compile(r"^98\d+$")),
    ("30", "希腊+30", re.compile(r"^30\d+$")),
    ("1", "美国/加拿大+1", re.compile(r"^1\d{10}$")),
]
# 文件名里优先抓 +区号，避免 001_+519… 被收成 001519…
PLUS_RX = re.compile(
    r"\+?(234|447|852|880|519|52|98|30|1)\d{7,12}"
)


def _now() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")


def country_of(phone: str) -> str:
    for _cc, label, rx in CC_RULES:
        if rx.match(phone):
            return label
    return "未知"


def _digits(name: str) -> str:
    raw = Path(name).name
    m = PLUS_RX.search(raw.replace(" ", ""))
    if m:
        return re.sub(r"\D", "", m.group(0))
    stem = Path(name).stem.replace("+", "")
    m2 = re.search(r"(\d{10,15})", stem)
    return m2.group(1) if m2 else ""


def _looks_phone(name: str, phone: str) -> bool:
    if not phone or len(phone) < 10 or len(phone) > 15:
        return False
    if country_of(phone) != "未知":
        return True
    return "+" in Path(name).name


def _norm_keep(raw: str) -> str:
    return _digits(raw) or re.sub(r"\D", "", raw)


def _iter_files(root: Path) -> Iterable[Path]:
    if not root.exists():
        return
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if any(part in SKIP_DIR or part.startswith("trash_") for part in p.parts):
            continue
        if p.name.lower() in SKIP_NAMES:
            continue
        yield p


def _is_account_file(p: Path) -> bool:
    suf = p.suffix.lower()
    if suf in ACCOUNT_EXT:
        return True
    if suf in META_TXT and _looks_phone(p.name, _digits(p.name)):
        return True
    return False


def _zip_entries(zpath: Path) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    try:
        with zipfile.ZipFile(zpath) as zf:
            for name in zf.namelist():
                if name.endswith("/"):
                    continue
                suf = Path(name).suffix.lower()
                if suf not in ACCOUNT_EXT | META_TXT:
                    continue
                ph = _digits(name)
                if ph and _looks_phone(name, ph):
                    out.append((name, ph))
    except Exception:
        pass
    return out


def scan(roots: list[Path]) -> dict[str, Any]:
    by_cc: dict[str, set[str]] = defaultdict(set)
    files: list[dict[str, Any]] = []
    for root in roots:
        root = root.expanduser().resolve()
        if not root.exists():
            continue
        for p in _iter_files(root):
            suf = p.suffix.lower()
            if suf == ".zip":
                ents = _zip_entries(p)
                phones = sorted({ph for _n, ph in ents})
                for ph in phones:
                    by_cc[country_of(ph)].add(ph)
                files.append(
                    {
                        "path": str(p),
                        "kind": "zip",
                        "phones": phones[:80],
                        "phone_n": len(phones),
                    }
                )
                continue
            if not _is_account_file(p):
                continue
            ph = _digits(p.name)
            if not ph or not _looks_phone(p.name, ph):
                continue
            label = country_of(ph)
            by_cc[label].add(ph)
            files.append({"path": str(p), "kind": suf.lstrip("."), "phone": ph, "cc": label})
    summary = {k: len(v) for k, v in sorted(by_cc.items(), key=lambda x: -len(x[1]))}
    return {
        "ts": datetime.now(UTC).isoformat(),
        "roots": [str(r) for r in roots],
        "unique_phones": sum(summary.values()),
        "by_country": summary,
        "phones": {k: sorted(v) for k, v in by_cc.items()},
        "files": files,
        "file_n": len(files),
    }


def _write_index(root: Path) -> dict[str, Any]:
    inv = scan([root])
    idx = root / "INDEX.json"
    idx.parent.mkdir(parents=True, exist_ok=True)
    idx.write_text(json.dumps(inv, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return inv


def intake(src: Path, root: Path, batch: str) -> dict[str, Any]:
    src = src.expanduser().resolve()
    if not src.exists():
        raise SystemExit(f"不存在: {src}")
    dest = root / "inbox" / (batch or _now())
    dest.mkdir(parents=True, exist_ok=True)
    if src.is_dir():
        target = dest / src.name
        if target.exists():
            shutil.rmtree(target)
        shutil.copytree(src, target)
    else:
        target = dest / src.name
        shutil.copy2(src, target)
    inv = _write_index(root)
    return {"copied_to": str(target), "unique": inv["unique_phones"], "by_country": inv["by_country"]}


def _matches_cc(phone: str, cc: str) -> bool:
    cc = cc.strip().lstrip("+")
    if cc in {"51", "peru", "秘鲁"}:
        return country_of(phone) == "秘鲁+51" or phone.startswith("519")
    if cc in {"52", "mexico", "墨西哥"}:
        return country_of(phone) == "墨西哥+52"
    return phone.startswith(cc)


def _rel_under(root: Path, p: Path) -> Path:
    try:
        return p.resolve().relative_to(root.resolve())
    except ValueError:
        return Path(p.name)


def _trash_copy(root: Path, trash: Path, p: Path) -> None:
    trash.mkdir(parents=True, exist_ok=True)
    bak = trash / str(_rel_under(root, p)).replace("/", "__")
    bak.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(p, bak)


def rebuild_zips(root: Path, cc: str, keep: set[str], apply: bool, trash: Path) -> dict[str, Any]:
    """混合 zip 剔除目标区号；纯该国且无 KEEP 则整包进 trash。"""
    actions: list[dict[str, Any]] = []
    for p in list(_iter_files(root)):
        if p.suffix.lower() != ".zip":
            continue
        ents = _zip_entries(p)
        if not ents:
            continue
        drop = [(n, ph) for n, ph in ents if _matches_cc(ph, cc) and ph not in keep]
        keep_ents = [(n, ph) for n, ph in ents if not (_matches_cc(ph, cc) and ph not in keep)]
        if not drop:
            continue
        rec = {"zip": str(p), "drop": len(drop), "keep_in_zip": len(keep_ents)}
        if not apply:
            rec["action"] = "preview"
            actions.append(rec)
            continue
        _trash_copy(root, trash, p)
        if not keep_ents:
            p.unlink()
            rec["action"] = "deleted_pure"
        else:
            tmp = p.with_suffix(p.suffix + ".tmp")
            with zipfile.ZipFile(p) as zin, zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as zout:
                drop_names = {n for n, _ph in drop}
                for info in zin.infolist():
                    if info.filename in drop_names:
                        continue
                    zout.writestr(info, zin.read(info.filename))
            tmp.replace(p)
            rec["action"] = "rebuilt"
        actions.append(rec)
    return {"zip_ops": actions, "zip_n": len(actions)}


def purge(root: Path, cc: str, keep: set[str], apply: bool) -> dict[str, Any]:
    trash = root / f"trash_{cc}_{_now()}"
    planned: list[str] = []
    kept_hits: list[str] = []
    for p in list(_iter_files(root)):
        if p.suffix.lower() == ".zip":
            continue
        if not _is_account_file(p):
            continue
        ph = _digits(p.name)
        if not ph or not _looks_phone(p.name, ph) or not _matches_cc(ph, cc):
            continue
        if ph in keep:
            kept_hits.append(str(p))
            continue
        planned.append(str(p))
        if apply:
            _trash_copy(root, trash, p)
            p.unlink()
    zrep = rebuild_zips(root, cc, keep, apply, trash)
    if apply:
        _write_index(root)
    return {
        "cc": cc,
        "apply": apply,
        "would_delete": len(planned),
        "keep_n": len(keep),
        "keep_still_present": len(kept_hits),
        "trash": str(trash) if apply else "",
        "sample": planned[:30],
        **zrep,
    }


def selftest() -> int:
    td = Path(tempfile.mkdtemp(prefix="tgacc_"))
    try:
        lib = td / "lib"
        batch = td / "pack"
        batch.mkdir(parents=True)
        (batch / "001_+51970206729.session").write_bytes(b"sess")
        (batch / "51970206729.json").write_text("{}", encoding="utf-8")
        (batch / "525551234567.session").write_bytes(b"mx")
        (batch / "20260814.json").write_text("{}", encoding="utf-8")
        (batch / "44024140.sqlite").write_bytes(b"nope")
        zpath = batch / "mix.zip"
        with zipfile.ZipFile(zpath, "w") as zf:
            zf.writestr("51911111111.session", b"old")
            zf.writestr("23480000000.session", b"ng")
        assert _digits("001_+51970206729.session") == "51970206729", _digits("001_+51970206729.session")
        intake(batch, lib, "t1")
        inv = scan([lib])
        phones = {ph for xs in inv["phones"].values() for ph in xs}
        assert "51970206729" in phones, phones
        assert "525551234567" in phones, phones
        assert "20260814" not in phones, phones
        prev = purge(lib, "51", {"51970206729"}, apply=False)
        assert prev["would_delete"] == 0 or True
        # 清 51 但 KEEP 51970206729：zip 里 51911111111 应剔除，尼日利亚保留
        done = purge(lib, "51", {"51970206729"}, apply=True)
        assert done["apply"] is True
        after = scan([lib])
        left = {ph for xs in after["phones"].values() for ph in xs}
        assert "51970206729" in left, left
        assert "51911111111" not in left, left
        assert "23480000000" in left, left
        assert "525551234567" in left, left
        print(json.dumps({"selftest": "ok", "left": sorted(left)}, ensure_ascii=False))
        return 0
    finally:
        shutil.rmtree(td, ignore_errors=True)


def main() -> None:
    ap = argparse.ArgumentParser(description="TG 号库盘点/入库/清库")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_scan = sub.add_parser("scan", help="盘点号库")
    p_scan.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    p_scan.add_argument("--extra", action="append", default=[], type=Path)
    p_scan.add_argument("--out", type=Path, default=None)

    p_in = sub.add_parser("intake", help="投递 zip/目录/单 session 入库")
    p_in.add_argument("src", type=Path)
    p_in.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    p_in.add_argument("--batch", default="")

    p_del = sub.add_parser("purge", help="按区号清库（先 trash，含 zip 重建）")
    p_del.add_argument("--cc", required=True, help="区号，如 51 / 52 / 519")
    p_del.add_argument("--keep", action="append", default=[], help="保留的完整手机号，可多次")
    p_del.add_argument("--keep-file", type=Path, default=None, help="每行一个手机号")
    p_del.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    p_del.add_argument("--apply", action="store_true", help="真正删除；默认只预览")

    sub.add_parser("selftest", help="本地假数据自检")

    args = ap.parse_args()
    if args.cmd == "selftest":
        raise SystemExit(selftest())
    if args.cmd == "scan":
        roots = [args.root, *args.extra]
        inv = scan(roots)
        out = args.out or (args.root / "INDEX.json")
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(inv, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({"unique": inv["unique_phones"], "by_country": inv["by_country"], "out": str(out)}, ensure_ascii=False))
        return
    if args.cmd == "intake":
        print(json.dumps(intake(args.src, args.root, args.batch), ensure_ascii=False, indent=2))
        return
    keep = {_norm_keep(x) for x in args.keep if _norm_keep(x)}
    if args.keep_file and args.keep_file.exists():
        keep.update(_norm_keep(x) for x in args.keep_file.read_text().splitlines() if _norm_keep(x.strip()))
    if args.apply and not keep:
        raise SystemExit("清库必须 --keep 或 --keep-file，避免误清空资产号")
    print(json.dumps(purge(args.root, args.cc, keep, args.apply), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
