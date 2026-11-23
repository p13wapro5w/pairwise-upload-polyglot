"""上传多态文件（polyglot）防护模块。

针对“GIF 头拼接 PHP 代码”一类攻击的纵深防御实现：

1. ``magic_bytes``        —— 按魔数识别真实文件类型，不信任 Content-Type / 扩展名。
2. ``content_type_check`` —— 校验声明类型与魔数识别结果一致。
3. ``reencode_image``     —— 服务端解码再重编码，剥离拼接在图片尾部的可执行 payload。
4. ``exec_isolation``     —— 检查落盘目录挂载在 noexec 分区。
5. ``extension_allowlist``—— 扩展名白名单，且要求与魔数类型双向一致。
6. ``filename_sanitize``  —— 文件名清洗 / 重命名，杜绝路径穿越与可执行后缀。
7. ``polyglot_detect``    —— 检测图片数据之后是否拼接了脚本/可执行内容。
8. ``storage_partition``  —— 校验上传目录位于独立分区且在 webroot 之外。
9. ``size_limit``         —— 大小限制。
10. ``validation``        —— 组合以上检查的总入口。
11. ``audit``             —— 审计日志。
12. ``error_map``         —— 内部错误到对外安全提示的映射（不泄露细节）。
13. ``antivirus_hook``    —— 杀毒扫描钩子。
14. ``versioning``        —— 文件版本化命名。
15. ``cleanup``           —— 临时文件清理。

所有函数对非法输入不抛异常，返回 ``{"ok": False, "error": ...}`` 结构，
由 ``error_map`` 统一转成对外文案。
"""

from __future__ import annotations

import hashlib
import os
import re
import secrets
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------

#: 魔数表：类型 -> (魔数, 偏移, MIME, 允许扩展名)
MAGIC_TABLE = {
    "gif": (b"\x47\x49\x46\x38", 0, "image/gif", {".gif"}),
    "png": (b"\x89\x50\x4e\x47\x0d\x0a\x1a\x0a", 0, "image/png", {".png"}),
    "jpeg": (b"\xff\xd8\xff", 0, "image/jpeg", {".jpg", ".jpeg"}),
    "bmp": (b"\x42\x4d", 0, "image/bmp", {".bmp"}),
    "webp": (b"\x52\x49\x46\x46", 0, "image/webp", {".webp"}),  # RIFF....WEBP
}

#: 扩展名 -> 类型 的反向索引
EXT_TO_TYPE = {
    ext: kind for kind, (_, _, _, exts) in MAGIC_TABLE.items() for ext in exts
}

#: 默认允许的扩展名（白名单）
DEFAULT_ALLOWLIST = set(EXT_TO_TYPE)

#: 拼接 payload 的典型特征
PAYLOAD_MARKERS = (
    b"<?php",
    b"<?=",
    b"<script",
    b"#!/bin/",
    b"#!/usr/bin/",
    b"MZ",          # PE 头（出现在非零偏移时）
    b"\x7fELF",     # ELF 头（出现在非零偏移时）
    b"eval(",
    b"system(",
    b"passthru(",
    b"shell_exec(",
)

#: 各图片格式的“逻辑结束”标记（用于检测尾部拼接）
TRAILERS = {
    "gif": b"\x00\x3b",
    "png": b"IEND\xaeB`\x82",
    "jpeg": b"\xff\xd9",
}

DEFAULT_MAX_SIZE = 10 * 1024 * 1024  # 10 MiB

_SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._-]+")

#: 内部错误码 -> 对外文案（不泄露内部细节）
ERROR_MESSAGES = {
    "bad_magic": "文件类型不被支持",
    "type_mismatch": "文件内容与声明类型不符",
    "polyglot": "文件内容异常，已拒绝",
    "too_large": "文件超出大小限制",
    "bad_extension": "文件扩展名不被允许",
    "bad_filename": "文件名非法",
    "av_reject": "文件未通过安全扫描",
    "reencode_failed": "图片处理失败",
    "storage_unsafe": "存储配置不安全",
    "unknown": "上传被拒绝",
}


def _err(code, **extra):
    out = {"ok": False, "error": code, "message": ERROR_MESSAGES.get(code, ERROR_MESSAGES["unknown"])}
    out.update(extra)
    return out


def _ok(**extra):
    out = {"ok": True}
    out.update(extra)
    return out


# ---------------------------------------------------------------------------
# 1. 魔数识别
# ---------------------------------------------------------------------------

def magic_bytes(data, filename=None):
    """按魔数识别真实文件类型，返回 {"ok", "type", "mime", "extensions"}。

    不信任调用方提供的 Content-Type 与扩展名。
    """
    if not isinstance(data, (bytes, bytearray)) or len(data) < 4:
        return _err("bad_magic", type=None)
    head = bytes(data[:16])
    for kind, (magic, offset, mime, exts) in MAGIC_TABLE.items():
        if head[offset:offset + len(magic)] == magic:
            if kind == "webp" and head[8:12] != b"WEBP":
                continue
            return _ok(type=kind, mime=mime, extensions=sorted(exts))
    return _err("bad_magic", type=None)


# ---------------------------------------------------------------------------
# 2. Content-Type / 扩展名 与魔数一致性
# ---------------------------------------------------------------------------

def content_type_check(declared, detected=None):
    """校验声明的 Content-Type（或扩展名）与魔数识别结果一致。

    ``declared`` 可以是 "image/gif" 或 "x.gif"；``detected`` 为
    ``magic_bytes`` 返回的类型字符串（缺省时视为未识别，直接拒绝）。
    """
    if not isinstance(declared, str) or not isinstance(detected, str):
        return _err("type_mismatch")
    info = MAGIC_TABLE.get(detected)
    if info is None:
        return _err("bad_magic")
    mime, exts = info[2], info[3]
    token = declared.strip().lower().split(";")[0]
    if "/" in token:  # 当作 MIME
        if token != mime:
            return _err("type_mismatch", declared=token, detected=detected)
    else:  # 当作文件名 / 扩展名
        ext = os.path.splitext(token)[1]
        if ext not in exts:
            return _err("type_mismatch", declared=ext, detected=detected)
    return _ok(type=detected, mime=mime)


# ---------------------------------------------------------------------------
# 3. 服务端重编码
# ---------------------------------------------------------------------------

def reencode_image(data, fmt=None):
    """解码后重新编码图片，剥离拼接在尾部的 payload 与元数据。

    优先使用 Pillow；不可用时对已知格式做尾部截断（裁剪到逻辑结束标记）。
    返回 {"ok", "data", "format"}。
    """
    if not isinstance(data, (bytes, bytearray)):
        return _err("reencode_failed")
    detected = magic_bytes(data)
    if not detected["ok"]:
        return _err("bad_magic")
    kind = detected["type"]
    target = (fmt or kind).lower()
    if target == "jpg":
        target = "jpeg"
    if target not in MAGIC_TABLE:
        return _err("reencode_failed", format=target)

    try:  # 首选：Pillow 完整解码重编码
        import io
        from PIL import Image

        with Image.open(io.BytesIO(bytes(data))) as im:
            im.load()
            if im.mode not in ("RGB", "L", "P") and target == "jpeg":
                im = im.convert("RGB")
            buf = io.BytesIO()
            pil_fmt = {"jpeg": "JPEG", "png": "PNG", "gif": "GIF",
                       "bmp": "BMP", "webp": "WEBP"}[target]
            im.save(buf, format=pil_fmt)
            return _ok(data=buf.getvalue(), format=target, reencoded="pillow")
    except ImportError:
        pass
    except Exception:
        return _err("reencode_failed")

    # 回退：按逻辑结束标记截断，丢弃尾部拼接内容
    trailer = TRAILERS.get(kind)
    if trailer is None:
        return _err("reencode_failed")
    idx = bytes(data).rfind(trailer)
    if idx < 0:
        return _err("reencode_failed")
    end = idx + len(trailer)
    return _ok(data=bytes(data)[:end], format=kind, reencoded="truncate")


# ---------------------------------------------------------------------------
# 4. 落盘目录 noexec 隔离
# ---------------------------------------------------------------------------

def exec_isolation(path, mounts_file="/proc/mounts"):
    """检查 ``path`` 所在挂载点是否带 noexec（且建议同时 nosuid/nodev）。"""
    if not isinstance(path, (str, os.PathLike)):
        return _err("storage_unsafe")
    try:
        target = os.path.realpath(path)
        best = None
        with open(mounts_file, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) < 4:
                    continue
                mount_point, opts = parts[1], parts[3].split(",")
                if target == mount_point or target.startswith(mount_point.rstrip("/") + "/"):
                    if best is None or len(mount_point) > len(best[0]):
                        best = (mount_point, opts)
        if best is None:
            return _err("storage_unsafe", reason="mount not found", path=target)
        mount_point, opts = best
        if "noexec" not in opts:
            return _err("storage_unsafe", reason="noexec missing",
                        mount=mount_point, options=opts)
        return _ok(mount=mount_point, options=opts,
                   nosuid="nosuid" in opts, nodev="nodev" in opts)
    except OSError:
        return _err("storage_unsafe")


# ---------------------------------------------------------------------------
# 5. 扩展名白名单（与魔数双向一致）
# ---------------------------------------------------------------------------

def extension_allowlist(filename, detected=None, allowlist=None):
    """扩展名必须在白名单内；若给出魔数识别结果，还要求二者一致。"""
    if not isinstance(filename, str) or not filename:
        return _err("bad_extension")
    allowed = set(allowlist) if allowlist else DEFAULT_ALLOWLIST
    ext = os.path.splitext(filename)[1].lower()
    if ext not in allowed:
        return _err("bad_extension", extension=ext)
    if detected is not None:
        expected = EXT_TO_TYPE.get(ext)
        if not isinstance(detected, str) or expected != detected:
            return _err("type_mismatch", extension=ext, detected=detected)
    return _ok(extension=ext)


# ---------------------------------------------------------------------------
# 6. 文件名清洗
# ---------------------------------------------------------------------------

def filename_sanitize(filename, default_ext=None):
    """清洗文件名：去路径、去特殊字符；返回安全文件名（含随机前缀）。"""
    if not isinstance(filename, str) or not filename.strip():
        return _err("bad_filename")
    base = filename.replace("\\", "/").split("/")[-1]  # 去路径穿越
    base = base.lstrip(".")                             # 去隐藏文件 / 裸扩展名
    base = _SAFE_NAME_RE.sub("_", base)
    if not base or base in {".", ".."}:
        return _err("bad_filename")
    stem, ext = os.path.splitext(base)
    ext = ext.lower()
    if default_ext and ext not in DEFAULT_ALLOWLIST:
        ext = default_ext
    if ext not in DEFAULT_ALLOWLIST:
        return _err("bad_extension", extension=ext)
    stem = stem[:64] or "file"
    safe = f"{stem}.{secrets.token_hex(8)}{ext}"
    return _ok(filename=safe, extension=ext)


# ---------------------------------------------------------------------------
# 7. 多态文件检测
# ---------------------------------------------------------------------------

def polyglot_detect(data, kind=None):
    """检测图片数据中是否拼接了脚本 / 可执行内容。

    策略：a) 逻辑结束标记之后仍有数据；b) 全文扫描危险特征串。
    """
    if not isinstance(data, (bytes, bytearray)):
        return _err("polyglot")
    blob = bytes(data)
    detected = magic_bytes(blob)
    if not detected["ok"]:
        return _err("bad_magic")
    kind = kind or detected["type"]

    trailer = TRAILERS.get(kind)
    if trailer is not None:
        idx = blob.rfind(trailer)
        if idx >= 0 and idx + len(trailer) < len(blob):
            return _err("polyglot", reason="trailing data after image end",
                        offset=idx + len(trailer))

    lower = blob.lower()
    for marker in PAYLOAD_MARKERS:
        pos = lower.find(marker.lower())
        if pos > 0:  # 偏移 0 处是魔数本身，忽略
            return _err("polyglot", reason="embedded payload marker",
                        marker=marker.decode("latin1"), offset=pos)
    return _ok(type=kind)


# ---------------------------------------------------------------------------
# 8. 存储分区隔离
# ---------------------------------------------------------------------------

def storage_partition(path, webroot=None):
    """校验上传目录：在 webroot 之外，且（尽量）位于独立挂载点。"""
    if not isinstance(path, (str, os.PathLike)):
        return _err("storage_unsafe")
    target = os.path.realpath(path)
    if webroot is not None:
        root = os.path.realpath(webroot)
        if target == root or target.startswith(root.rstrip("/") + "/"):
            return _err("storage_unsafe", reason="inside webroot", path=target)
    iso = exec_isolation(target)
    return _ok(path=target, outside_webroot=True, noexec=iso.get("ok", False),
               mount=iso.get("mount"))


# ---------------------------------------------------------------------------
# 9. 大小限制
# ---------------------------------------------------------------------------

def size_limit(size, max_size=DEFAULT_MAX_SIZE):
    """检查声明大小（字节数或数据本身）是否超限。"""
    if isinstance(size, (bytes, bytearray)):
        size = len(size)
    if not isinstance(size, (int, float)) or isinstance(size, bool) or size < 0:
        return _err("too_large")
    if not isinstance(max_size, (int, float)) or max_size <= 0:
        max_size = DEFAULT_MAX_SIZE
    if size > max_size:
        return _err("too_large", size=int(size), max=int(max_size))
    return _ok(size=int(size), max=int(max_size))


# ---------------------------------------------------------------------------
# 10. 组合校验入口
# ---------------------------------------------------------------------------

def validation(data, filename=None, declared_type=None, max_size=DEFAULT_MAX_SIZE):
    """上传总校验：大小 -> 魔数 -> 类型一致 -> 扩展名 -> 多态检测。"""
    steps = []

    def record(name, result):
        steps.append({"step": name, "ok": result["ok"],
                      "error": result.get("error")})
        return result["ok"]

    if not record("size_limit", size_limit(data if isinstance(data, (bytes, bytearray)) else 0, max_size)):
        return _err("too_large", steps=steps)

    magic = magic_bytes(data)
    if not record("magic_bytes", magic):
        return _err("bad_magic", steps=steps)
    detected = magic["type"]

    if declared_type is not None:
        if not record("content_type_check", content_type_check(declared_type, detected)):
            return _err("type_mismatch", steps=steps)

    if filename is not None:
        if not record("extension_allowlist", extension_allowlist(filename, detected)):
            return _err("bad_extension", steps=steps)

    if not record("polyglot_detect", polyglot_detect(data, detected)):
        return _err("polyglot", steps=steps)

    return _ok(type=detected, mime=magic["mime"], steps=steps)


# ---------------------------------------------------------------------------
# 11. 审计
# ---------------------------------------------------------------------------

_AUDIT_LOG = []


def audit(event, detail=None):
    """记录一条审计事件，返回该记录。"""
    record = {
        "ts": time.time(),
        "event": str(event),
        "detail": detail if isinstance(detail, (dict, list, str, int, float, bool, type(None))) else str(detail),
    }
    _AUDIT_LOG.append(record)
    return record


# ---------------------------------------------------------------------------
# 12. 对外错误映射
# ---------------------------------------------------------------------------

def error_map(code, default="unknown"):
    """把内部错误码映射为对外安全文案，不泄露内部细节。"""
    if isinstance(code, dict):  # 允许直接传 _err() 的结果
        code = code.get("error", default)
    if not isinstance(code, str):
        code = default
    if code not in ERROR_MESSAGES:
        code = default if default in ERROR_MESSAGES else "unknown"
    return {"ok": False, "message": ERROR_MESSAGES[code]}


# ---------------------------------------------------------------------------
# 13. 杀毒钩子
# ---------------------------------------------------------------------------

def antivirus_hook(data, scanner=None):
    """调用外部扫描器（如 clamd）扫描数据；无扫描器时默认放行并标记未扫描。"""
    if not isinstance(data, (bytes, bytearray)):
        return _err("av_reject")
    if scanner is None:
        return _ok(scanned=False, clean=True)
    try:
        result = scanner(bytes(data))
    except Exception:
        return _err("av_reject", reason="scanner error")
    clean = bool(result.get("clean")) if isinstance(result, dict) else bool(result)
    if not clean:
        return _err("av_reject", reason="malware detected")
    return _ok(scanned=True, clean=True)


# ---------------------------------------------------------------------------
# 14. 版本化命名
# ---------------------------------------------------------------------------

def versioning(filename, version=None):
    """生成带版本/摘要的文件名，避免覆盖与缓存投毒。"""
    if not isinstance(filename, str) or not filename:
        return _err("bad_filename")
    stem, ext = os.path.splitext(filename)
    if version is None:
        version = hashlib.sha256(f"{filename}{time.time_ns()}{secrets.token_hex(4)}".encode()).hexdigest()[:12]
    version = _SAFE_NAME_RE.sub("_", str(version))[:32] or "v1"
    return _ok(filename=f"{stem}.{version}{ext}", version=version)


# ---------------------------------------------------------------------------
# 15. 临时文件清理
# ---------------------------------------------------------------------------

def cleanup(paths, missing_ok=True):
    """删除临时文件列表，返回清理结果。"""
    if isinstance(paths, (str, os.PathLike)):
        paths = [paths]
    if not isinstance(paths, (list, tuple)):
        return _err("unknown")
    removed, failed = [], []
    for p in paths:
        try:
            os.remove(p)
            removed.append(str(p))
        except FileNotFoundError:
            if not missing_ok:
                failed.append(str(p))
        except OSError:
            failed.append(str(p))
    if failed:
        return _err("unknown", removed=removed, failed=failed)
    return _ok(removed=removed, failed=[])
