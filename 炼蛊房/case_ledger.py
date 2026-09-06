#!/usr/bin/env python3
"""大爱仙尊假设/证据/裁决账本。追加式，SHA-256 校验工件。

案卷名会落到 案卷/<案卷>/证据/。
STATUS.md 仍是人类结论；本账本是长时多假设的机器真源。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
import time
from datetime import datetime, UTC
from pathlib import Path


def _utf8_stdio() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconf = getattr(stream, "reconfigure", None)
        if reconf:
            try:
                reconf(encoding="utf-8")
            except Exception:
                pass

_utf8_stdio()

ENGINE = Path(__file__).resolve().parents[1]
RECOVERY = ENGINE / "案卷"

SCHEMA_VERSION = 1
TYPES = {"hypothesis", "evidence", "verdict"}
REQUIRED_ROLES = ("observation", "reproduction", "impact")
ROLE_LABELS = {"observation": "观察", "reproduction": "复现", "impact": "影响", "refutation": "反证"}
ROLES = set(ROLE_LABELS)
EFFECTS = {"supports", "refutes", "context"}
STATUSES = {"confirmed", "killed", "inconclusive", "deferred", "provisional"}
STATUS_LABELS = {"active": "活跃", "confirmed": "已确认", "killed": "已证伪",
                 "inconclusive": "无定论", "deferred": "暂缓", "provisional": "暂定已确认"}
LIMITS = {"claim": 240, "scope": 160, "summary": 240, "reason": 500, "disprove_if": 240}
BOARD_LIMIT = 8000
ID_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9._-]{0,63}$")


class LedgerError(Exception):
    pass


class ReportWriteError(OSError):
    pass


WRITE_CMDS = {"hypothesis", "evidence", "verdict", "init", "attach"}


def resolve_case_dir(case_arg: str, *, create: bool = False) -> Path:
    """案卷名 → 案卷/<名>/证据；已是目录则用该目录。"""
    raw = Path(str(case_arg)).expanduser()
    if raw.is_dir():
        case = raw.resolve()
        if (case / "STATUS.md").is_file() or (case / "测绘").is_dir():
            ev = case / "证据"
            if create:
                ev.mkdir(parents=True, exist_ok=True)
            return ev
        return case
    named = RECOVERY / str(case_arg)
    ev = named / "证据"
    if ev.is_dir():
        return ev.resolve()
    if create:
        ev.mkdir(parents=True, exist_ok=True)
        return ev.resolve()
    raise LedgerError(f"案卷账本不存在: {case_arg}（先 case_ledger.py init）")


def paths(case_arg, *, create: bool = False):
    case = resolve_case_dir(case_arg, create=create)
    return case, case / "ledger.jsonl", case / "evidence-validation.md"


def ensure_case(case):
    case.mkdir(parents=True, exist_ok=True)
    (case / "artifacts").mkdir(exist_ok=True)
    (case / "ledger.jsonl").touch(exist_ok=True)


def now():
    return datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def validate_short_text(value, field):
    value = " ".join(str(value).split())
    if not value:
        raise LedgerError(f"{field} must not be empty")
    if len(value) > LIMITS[field]:
        raise LedgerError(f"{field} exceeds {LIMITS[field]} characters")
    return value


def check_id(value, prefix):
    if not isinstance(value, str) or not ID_PATTERN.fullmatch(value):
        raise LedgerError(f"invalid id: {value}")
    if not value.startswith(prefix):
        raise LedgerError(f"{value} must start with {prefix}")


def engagement_root(case: Path) -> Path:
    """账本在 证据/ 时，案卷根（STATUS.md / 测绘）也算合法工件范围。"""
    case = case.resolve()
    parent = case.parent
    if case.name == "证据" and (
        (parent / "STATUS.md").is_file()
        or (parent / "测绘").is_dir()
        or (parent / "TRIAGE.md").is_file()
    ):
        return parent
    return case


def resolve_artifact(case, relative):
    candidate = Path(relative)
    if candidate.is_absolute():
        raise LedgerError("artifact path must be relative to the case directory")
    ev = case.resolve()
    root = engagement_root(ev)
    tried = [(ev / candidate).resolve(), (root / candidate).resolve()]
    for resolved in tried:
        try:
            resolved.relative_to(root)
        except ValueError:
            continue
        if resolved.is_file():
            return resolved
    raise LedgerError(f"artifact does not exist: {relative}")


def artifact_relpath(case, resolved: Path) -> str:
    ev = case.resolve()
    try:
        return resolved.relative_to(ev).as_posix()
    except ValueError:
        return Path("..").joinpath(resolved.relative_to(engagement_root(ev))).as_posix()


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def read_records(ledger):
    if not ledger.exists():
        return []
    try:
        text = ledger.read_bytes().decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise LedgerError(f"ledger is not valid UTF-8 at byte {exc.start}") from exc
    records = []
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            raise LedgerError(f"line {number}: blank lines are not allowed")
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise LedgerError(f"line {number}: invalid JSON: {exc.msg}") from exc
        if not isinstance(record, dict):
            raise LedgerError(f"line {number}: record must be a JSON object")
        records.append(record)
    return records


def validate(case, records):
    all_ids, hypotheses, evidence = {}, {}, {}
    prefixes = {"hypothesis": "H", "evidence": "E", "verdict": "V"}
    for line, record in enumerate(records, 1):
        kind, record_id = record.get("type"), record.get("id")
        if record.get("v") != SCHEMA_VERSION:
            raise LedgerError(f"line {line}: v must be {SCHEMA_VERSION}")
        if kind not in TYPES:
            raise LedgerError(f"line {line}: unknown record type {kind!r}")
        check_id(record_id, prefixes[kind])
        if record_id in all_ids:
            raise LedgerError(f"line {line}: duplicate id {record_id}")
        all_ids[record_id] = record

        if kind == "hypothesis":
            validate_short_text(record.get("claim", ""), "claim")
            validate_short_text(record.get("scope", ""), "scope")
            conditions = record.get("disprove_if")
            if not isinstance(conditions, list) or not conditions:
                raise LedgerError(f"line {line}: disprove_if must be a non-empty list")
            for condition in conditions:
                if not isinstance(condition, str):
                    raise LedgerError(f"line {line}: disprove_if entries must be strings")
                validate_short_text(condition, "disprove_if")
            hypotheses[record_id] = record
            continue

        hypothesis = record.get("hypothesis")
        if hypothesis not in hypotheses:
            raise LedgerError(f"line {line}: missing prior hypothesis {hypothesis}")
        if kind == "evidence":
            if record.get("role") not in ROLES:
                raise LedgerError(f"line {line}: invalid evidence role")
            if record.get("effect") not in EFFECTS:
                raise LedgerError(f"line {line}: invalid evidence effect")
            validate_short_text(record.get("summary", ""), "summary")
            relative = record.get("artifact")
            if not isinstance(relative, str):
                raise LedgerError(f"line {line}: artifact must be a string")
            if record.get("sha256") != digest(resolve_artifact(case, relative)):
                raise LedgerError(f"line {line}: {record_id} artifact SHA-256 mismatch")
            evidence[record_id] = record
            continue

        status, refs = record.get("status"), record.get("evidence")
        if status not in STATUSES:
            raise LedgerError(f"line {line}: invalid verdict status")
        if not isinstance(refs, list) or not refs:
            raise LedgerError(f"line {line}: verdict must reference evidence")
        selected = []
        for evidence_id in refs:
            if evidence_id not in evidence:
                raise LedgerError(f"line {line}: missing prior evidence {evidence_id}")
            item = evidence[evidence_id]
            if item["hypothesis"] != hypothesis:
                raise LedgerError(f"line {line}: evidence {evidence_id} belongs to another hypothesis")
            selected.append(item)
        validate_short_text(record.get("reason", ""), "reason")
        if status == "confirmed":
            missing = set(REQUIRED_ROLES) - {item["role"] for item in selected}
            if missing:
                raise LedgerError(f"line {line}: confirmed verdict missing roles: {', '.join(sorted(missing))}")
        if status == "provisional":
            missing = {"observation", "reproduction"} - {item["role"] for item in selected}
            if missing:
                raise LedgerError(f"line {line}: provisional verdict missing roles: {', '.join(sorted(missing))}")
        if status == "killed" and not any(
            item["role"] == "refutation" or item["effect"] == "refutes" for item in selected
        ):
            raise LedgerError(f"line {line}: killed verdict requires role=refutation or effect=refutes evidence")
    return all_ids


def verified(case):
    ledger = paths(case)[1]
    records = read_records(ledger)
    validate(case, records)
    return records


def derive_state(records):
    hypotheses = {r["id"]: r for r in records if r["type"] == "hypothesis"}
    evidence = {key: [] for key in hypotheses}
    verdicts = {}
    for record in records:
        if record["type"] == "evidence":
            evidence[record["hypothesis"]].append(record)
        elif record["type"] == "verdict":
            verdicts[record["hypothesis"]] = record
    return hypotheses, evidence, verdicts


def report_gate(records):
    hypotheses, evidence, verdicts = derive_state(records)
    gaps = []
    for hypothesis_id, item in hypotheses.items():
        verdict = verdicts.get(hypothesis_id)
        if verdict is None:
            continue
        if verdict["status"] == "provisional":
            gaps.append(f"{hypothesis_id} 仍是 provisional，未闭环")
        elif verdict["status"] == "confirmed":
            referenced = [e for e in evidence[hypothesis_id] if e["id"] in verdict["evidence"]]
            missing = set(REQUIRED_ROLES) - {e["role"] for e in referenced}
            if missing:
                gaps.append(f"{hypothesis_id} confirmed 缺角色：{', '.join(sorted(missing))}")
    if gaps:
        raise LedgerError("REPORT gate 未通过：" + "；".join(gaps))


def render_blackboard(records):
    hypotheses, evidence, verdicts = derive_state(records)

    def build(defer_collapse, evidence_cap):
        counts = {"deferred": 0, "evidence_collapsed": 0}
        groups = {"confirmed": [], "provisional": [], "active": [], "deferred": []}
        for hypothesis_id, item in hypotheses.items():
            verdict = verdicts.get(hypothesis_id)
            status = verdict["status"] if verdict else "active"
            base = f"- {hypothesis_id} | {item['claim']} | 范围：{item['scope']}"
            if status == "confirmed":
                groups["confirmed"].append(f"{base} | 证据：{'、'.join(verdict['evidence'])}")
            elif status == "provisional":
                groups["provisional"].append(
                    f"{base} | 证据：{'、'.join(verdict['evidence'])} | 待补：影响"
                )
            elif status == "deferred":
                proof = "、".join(e["id"] for e in evidence[hypothesis_id]) or "无"
                if defer_collapse:
                    counts["deferred"] += 1
                    groups["deferred"].append(f"- {hypothesis_id} | 暂缓 | {item['claim'][:40]}")
                else:
                    groups["deferred"].append(f"{base} | 证据：{proof}")
            elif status in {"active", "inconclusive"}:
                roles = {e["role"] for e in evidence[hypothesis_id]}
                missing_roles = [role for role in REQUIRED_ROLES if role not in roles]
                missing = "、".join(ROLE_LABELS[role] for role in missing_roles) or "无"
                ids = [e["id"] for e in evidence[hypothesis_id]]
                if evidence_cap and len(ids) > evidence_cap:
                    counts["evidence_collapsed"] += len(ids) - evidence_cap
                    proof = "、".join(ids[-evidence_cap:]) + f" …共{len(ids)}条"
                else:
                    proof = "、".join(ids) or "无"
                groups["active"].append(
                    f"{base} | 证伪条件：{'; '.join(item['disprove_if'])} | 证据：{proof} | 缺失：{missing}"
                )
        return groups, counts

    def assemble(groups, markers):
        lines = ["[大爱仙尊假设黑板 v1]", "完整性：通过", "账本：证据/ledger.jsonl",
                 "报告：证据/evidence-validation.md", ""]
        lines.extend(markers)
        for title, key in (("已确认事实", "confirmed"), ("已确认·待补影响", "provisional"),
                           ("活跃假设", "active"), ("暂缓假设", "deferred")):
            lines.extend([title, *(groups[key] or ["- 无"]), ""])
        lines.extend(["错误", "- 无"])
        return "\n".join(lines).rstrip() + "\n"

    groups, _ = build(False, None)
    full = assemble(groups, [])
    if len(full) <= BOARD_LIMIT:
        return full
    groups, counts = build(True, None)
    markers = []
    if counts["deferred"]:
        markers.append(f"已折叠：暂缓假设 {counts['deferred']} 条")
    if markers:
        markers.append("")
    level1 = assemble(groups, markers)
    if len(level1) <= BOARD_LIMIT:
        return level1
    groups, counts = build(True, 3)
    markers = []
    if counts["deferred"]:
        markers.append(f"已折叠：暂缓假设 {counts['deferred']} 条")
    if counts["evidence_collapsed"]:
        markers.append(f"已折叠：活跃假设证据 {counts['evidence_collapsed']} 条")
    if markers:
        markers.append("")
    level2 = assemble(groups, markers)
    if len(level2) <= BOARD_LIMIT:
        return level2
    raise LedgerError(
        f"黑板溢出：折叠后仍 {len(level2)} 个字符超过上限 {BOARD_LIMIT}；"
        "请处理过期假设或缩短摘要"
    )


def error_board(error):
    message = " ".join(str(error).split())
    overflow = message.startswith("黑板溢出")
    if overflow:
        integrity = "通过\n黑板：溢出"
        action = "完整状态未被静默截断。请处理过期记录或缩短摘要。"
    elif isinstance(error, ReportWriteError):
        integrity = "通过\n报告写入：失败"
        action = "账本仍是唯一真相源；稍后运行 `render` 重新生成报告。"
    else:
        integrity = "失败"
        action = "在 `verify` 通过前，不要信任或修改此案件。"
    return (f"[大爱仙尊假设黑板 v1]\n完整性：{integrity}\n账本：证据/ledger.jsonl\n"
            f"报告：证据/evidence-validation.md\n\n错误\n- {message}\n- {action}\n")

def md(value):
    return " ".join(str(value).split()).replace("|", "\\|")


def markdown(records, blackboard):
    hypotheses, evidence, verdicts = derive_state(records)
    lines = ["# Evidence Validation", "", "> 由 `证据/ledger.jsonl` 生成。不要手改本文件。",
             "", "<!-- BLACKBOARD:BEGIN -->", "", "## 实时黑板", "", "```text",
             blackboard.removeprefix("[大爱仙尊假设黑板 v1]\n").rstrip(), "```", "",
             "<!-- BLACKBOARD:END -->", "", "## Detailed Evidence Chains", ""]
    if not hypotheses:
        lines.append("_No hypotheses recorded._")
    for hypothesis_id, item in hypotheses.items():
        verdict = verdicts.get(hypothesis_id)
        lines += [f"### {hypothesis_id} — {md(item['claim'])}", "", f"- **Scope:** {md(item['scope'])}",
                  f"- **Current status:** `{verdict['status'] if verdict else 'active'}`",
                  f"- **Disprove if:** {'; '.join(md(x) for x in item['disprove_if'])}", "",
                  "| Evidence | Role | Effect | Summary | Artifact |", "|---|---|---|---|---|"]
        for proof in evidence[hypothesis_id]:
            lines.append(f"| {proof['id']} | {proof['role']} | {proof['effect']} | {md(proof['summary'])} | `{md(proof['artifact'])}` |")
        if not evidence[hypothesis_id]:
            lines.append("| — | — | — | No evidence | — |")
        lines.append("")
        if verdict:
            lines += [f"**Latest verdict {verdict['id']}:** {md(verdict['reason'])}", ""]
    lines += ["## Artifact Integrity", "", "| Evidence | Artifact | SHA-256 | Result |", "|---|---|---|---|"]
    proofs = [r for r in records if r["type"] == "evidence"]
    lines += ([f"| {p['id']} | `{md(p['artifact'])}` | `{p['sha256']}` | PASS |" for p in proofs]
              or ["| — | — | — | No artifacts |"])
    lines += ["", "## Verdict History", "", "| Verdict | Hypothesis | Status | Evidence | Reason |",
              "|---|---|---|---|---|"]
    verdict_history = [r for r in records if r["type"] == "verdict"]
    lines += ([f"| {v['id']} | {v['hypothesis']} | {v['status']} | {','.join(v['evidence'])} | {md(v['reason'])} |"
               for v in verdict_history] or ["| — | — | — | — | No verdicts |"])
    return "\n".join(lines).rstrip() + "\n"


def stage_report(report, text):
    try:
        descriptor, name = tempfile.mkstemp(
            dir=report.parent,
            prefix=f".{report.name}.",
            suffix=".tmp",
        )
    except OSError as exc:
        raise ReportWriteError(f"无法创建报告临时文件：{exc}") from exc
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception as exc:
        try:
            os.close(descriptor)
        except OSError:
            pass
        temporary.unlink(missing_ok=True)
        if isinstance(exc, OSError):
            raise ReportWriteError(f"报告临时文件写入失败：{exc}") from exc
        raise
    return temporary


def publish_report(temporary, report, attempts=5, delay=0.05):
    for attempt in range(attempts):
        try:
            os.replace(temporary, report)
            return
        except PermissionError as exc:
            if attempt + 1 == attempts:
                raise ReportWriteError(
                    f"报告替换失败（已重试 {attempts} 次）：{exc}"
                ) from exc
            time.sleep(delay * (attempt + 1))
        except OSError as exc:
            raise ReportWriteError(f"报告替换失败：{exc}") from exc


def write_report(case, text):
    report = paths(case)[2]
    try:
        if report.read_text(encoding="utf-8") == text:
            return report
    except (OSError, UnicodeError):
        pass
    temporary = stage_report(report, text)
    try:
        publish_report(temporary, report)
    finally:
        temporary.unlink(missing_ok=True)
    return report


def render(case):
    ensure_case(case)
    records = verified(case)
    blackboard = render_blackboard(records)
    return records, blackboard, write_report(case, markdown(records, blackboard))


def append(case, record):
    ensure_case(case)
    ledger, report = paths(case)[1:]
    records = read_records(ledger)
    validate(case, records)
    updated = [*records, record]
    validate(case, updated)
    blackboard = render_blackboard(updated)
    report_text = markdown(updated, blackboard)
    temporary = stage_report(report, report_text)
    try:
        with ledger.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        publish_report(temporary, report)
    finally:
        temporary.unlink(missing_ok=True)
    return updated


def repair(case):
    ledger = paths(case)[1]
    try:
        verified(case)
    except LedgerError as original:
        message = str(original)
    else:
        raise LedgerError("ledger tail is not damaged")
    if not any(token in message for token in ("invalid JSON", "not valid UTF-8", "blank lines")):
        raise LedgerError("repair-tail only handles a syntactically damaged final line")
    data = ledger.read_bytes()
    lines = data.splitlines(keepends=True)
    if len(lines) < 2:
        raise LedgerError("cannot repair a ledger with no complete line")
    temporary = ledger.with_suffix(".jsonl.repaired")
    temporary.write_bytes(b"".join(lines[:-1]))
    try:
        validate(case, read_records(temporary))
    except Exception as exc:
        temporary.unlink(missing_ok=True)
        raise LedgerError("damage is not confined to the final line") from exc
    stamp = datetime.now().strftime("%Y%m%d%H%M%S%f")
    backup = ledger.with_name(f"ledger.jsonl.bak-{stamp}")
    shutil.copy2(ledger, backup)
    os.replace(temporary, ledger)
    render(case)
    return backup


def next_id(records, prefix: str) -> str:
    taken = {r.get("id") for r in records}
    n = 1
    while f"{prefix}{n}" in taken:
        n += 1
    return f"{prefix}{n}"


def last_open_hypothesis(records) -> str:
    hyps, _ev, verdicts = derive_state(records)
    for hid in reversed(list(hyps)):
        st = (verdicts.get(hid) or {}).get("status")
        if st not in {"confirmed", "killed"}:
            return hid
    if hyps:
        return list(hyps)[-1]
    raise LedgerError("没有假设，先 hypothesis")


def attach_file(case: Path, src: Path) -> str:
    ensure_case(case)
    if not src.is_file():
        raise LedgerError(f"文件不存在: {src}")
    dest = case / "artifacts" / src.name
    if dest.resolve() != src.resolve():
        shutil.copy2(src, dest)
    return artifact_relpath(case, dest.resolve())


def make_record(args, records):
    case = paths(args.case, create=True)[0]
    kind = args.command
    rid = getattr(args, "id", None) or next_id(
        records, {"hypothesis": "H", "evidence": "E", "verdict": "V"}[kind]
    )
    common = {"v": SCHEMA_VERSION, "type": kind, "id": rid, "at": args.at or now()}
    if kind == "hypothesis":
        return {**common, "claim": args.claim, "scope": args.scope, "disprove_if": args.disprove_if}
    hid = args.hypothesis or last_open_hypothesis(records)
    if kind == "evidence":
        rel = args.artifact
        if getattr(args, "file", None):
            rel = attach_file(case, Path(args.file).expanduser())
        if not rel:
            raise LedgerError("evidence 需要 --artifact 或 --file")
        artifact = resolve_artifact(case, rel)
        return {**common, "hypothesis": hid, "role": args.role, "effect": args.effect,
                "artifact": artifact_relpath(case, artifact),
                "sha256": args.sha256 or digest(artifact),
                "summary": args.summary}
    refs = list(args.evidence or [])
    if not refs:
        refs = [e["id"] for e in records if e.get("type") == "evidence" and e.get("hypothesis") == hid]
    if not refs:
        raise LedgerError("verdict 没有可引用的证据")
    return {**common, "hypothesis": hid, "status": args.status,
            "evidence": refs, "reason": args.reason}


def cli():
    root = argparse.ArgumentParser(description=__doc__)
    commands = root.add_subparsers(dest="command", required=True)

    def command(name):
        item = commands.add_parser(name)
        item.add_argument("case")
        return item

    hypothesis = command("hypothesis")
    hypothesis.add_argument("--id")
    hypothesis.add_argument("--claim", required=True)
    hypothesis.add_argument("--scope", required=True)
    hypothesis.add_argument("--disprove-if", action="append", required=True)
    hypothesis.add_argument("--at")

    evidence = command("evidence")
    evidence.add_argument("--id")
    evidence.add_argument("--hypothesis", help="默认最近一条未结案假设")
    evidence.add_argument("--artifact", help="相对案卷根或 证据/")
    evidence.add_argument("--file", help="复制到 artifacts/ 并作为工件")
    evidence.add_argument("--summary", required=True)
    evidence.add_argument("--role", choices=sorted(ROLES), required=True)
    evidence.add_argument("--effect", choices=sorted(EFFECTS), required=True)
    evidence.add_argument("--sha256")
    evidence.add_argument("--at")

    verdict = command("verdict")
    verdict.add_argument("--id")
    verdict.add_argument("--hypothesis", help="默认最近一条未结案假设")
    verdict.add_argument("--reason", required=True)
    verdict.add_argument("--status", choices=sorted(STATUSES), required=True)
    verdict.add_argument("--evidence", nargs="+", help="默认该假设下全部证据")
    verdict.add_argument("--at")

    verify = command("verify")
    verify.add_argument("--repair-tail", action="store_true")
    verify.add_argument("--report", action="store_true")
    command("render")
    command("init")
    command("next")
    attach = command("attach")
    attach.add_argument("--file", required=True, help="复制到 证据/artifacts/，打印相对路径")
    context = command("context")
    context.add_argument("--plain", action="store_true")
    return root


def delta(record, records):
    kind, record_id = record["type"], record["id"]
    if kind == "hypothesis":
        return (f"假设 {record_id} 已添加。\n黑板变更：\n"
                f"- {record_id} 现为活跃\n- 范围：{record['scope']}")
    _, evidence, verdicts = derive_state(records)
    hypothesis_id = record["hypothesis"]
    latest = verdicts.get(hypothesis_id)
    status = latest["status"] if latest else "active"
    status_label = STATUS_LABELS[status]
    if kind == "verdict":
        return (f"裁决 {record_id} 已添加。\n黑板变更：\n- {hypothesis_id} 现为{status_label}\n"
                f"- 证据：{'、'.join(record['evidence'])}")
    roles = {item["role"] for item in evidence[hypothesis_id]}
    missing = "、".join(ROLE_LABELS[role] for role in REQUIRED_ROLES if role not in roles) or "无"
    role_label = ROLE_LABELS[record["role"]]
    return (f"证据 {record_id} 已添加。\n黑板变更：\n"
            f"- {hypothesis_id} 新增{role_label}证据 {record_id}\n"
            f"- {hypothesis_id} 仍为{status_label}\n- 缺失：{missing}")


def print_next(case: Path) -> None:
    ledger = case / "ledger.jsonl"
    records = read_records(ledger) if ledger.is_file() else []
    if records:
        validate(case, records)
    hyps, evidence, verdicts = derive_state(records) if records else ({}, {}, {})
    if not hyps:
        print("无假设。下一步: hypothesis --claim ... --scope ... --disprove-if ...")
        return
    for hid, item in hyps.items():
        st = (verdicts.get(hid) or {}).get("status", "active")
        roles = {e["role"] for e in evidence.get(hid, [])}
        missing = [ROLE_LABELS[r] for r in REQUIRED_ROLES if r not in roles]
        print(f"{hid} {st} {item['claim']}")
        print(f"  缺: {'、'.join(missing) or '无（可 verdict / verify --report）'}")


def main(argv=None):
    args = cli().parse_args(argv)
    create = args.command in WRITE_CMDS
    try:
        case = paths(args.case, create=create)[0]
        if args.command in TYPES:
            records = read_records(case / "ledger.jsonl") if (case / "ledger.jsonl").is_file() else []
            record = make_record(args, records)
            print(delta(record, append(case, record)))
        elif args.command == "verify":
            if args.repair_tail:
                print(f"Tail repaired. Backup: {repair(case)}")
            records = verified(case)
            if args.report:
                report_gate(records)
                print(f"REPORT gate: PASS ({len(records)} records)")
            else:
                print(f"Integrity: PASS ({len(records)} records)")
        elif args.command == "render":
            print(render(case)[2])
        elif args.command == "init":
            ensure_case(case)
            root = engagement_root(case)
            print(f"账本目录: {case}")
            print(f"案卷根: {root}")
            print(f"ledger: {case / 'ledger.jsonl'}")
            print("下一步: hypothesis → attach/evidence → verdict → verify --report")
        elif args.command == "attach":
            print(attach_file(case, Path(args.file).expanduser()))
        elif args.command == "next":
            print_next(case)
        else:
            try:
                _, blackboard, _ = render(case)
            except (LedgerError, OSError) as exc:
                blackboard = error_board(exc)
            print(blackboard, end="")
        return 0
    except (LedgerError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
