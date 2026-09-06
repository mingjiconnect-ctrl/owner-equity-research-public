#!/usr/bin/env python3
"""Bootstrap and verify the Linux x86_64 report-toolchain evidence bundle.

This helper intentionally runs only on Linux x86_64.  It downloads exact,
content-pinned upstream artifacts, builds the selective Tectonic v33 cache with
a substantive Chinese report fixture, then proves that the fixture can be
rebuilt with ``--only-cached`` inside a network namespace with no interfaces.

It does not update the packaged report-toolchain authority.  Its output is a
candidate evidence root for the separately reviewed authority bootstrap.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import platform
import shutil
import stat
import subprocess
import sys
import tarfile
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath

SCHEMA_VERSION = "1.0.0"
SOURCE_DATE_EPOCH = "946684800"
TECTONIC_VERSION = "0.16.9"
TECTONIC_RELEASE_TAG = "tectonic@0.16.9"
TECTONIC_ARCHIVE_NAME = "tectonic-0.16.9-x86_64-unknown-linux-gnu.tar.gz"
TECTONIC_ARCHIVE_URL = (
    "https://github.com/tectonic-typesetting/tectonic/releases/download/"
    "tectonic%400.16.9/tectonic-0.16.9-x86_64-unknown-linux-gnu.tar.gz"
)
TECTONIC_ARCHIVE_SHA256 = "f3c825128095dc3399ea11c08c18035b33050a216930c295c79e8eb11bd21de4"
TECTONIC_ARCHIVE_SIZE = 21_568_986
TECTONIC_BINARY_SHA256 = "93898e5680acc5ae857b96a3ac1447d84f3bb2eb8dd39398c9859e284afb5443"
TECTONIC_BINARY_SIZE = 55_785_912
TECTONIC_LICENSE_URL = (
    "https://raw.githubusercontent.com/tectonic-typesetting/tectonic/tectonic%400.16.9/LICENSE"
)
TECTONIC_LICENSE_SHA256 = "814a258f76e420b25cb3c07172eb2b3956f34cefbf0a650413b78e65c425f306"
TECTONIC_LICENSE_SIZE = 1_192
TECTONIC_SOURCE_URL = (
    "https://codeload.github.com/tectonic-typesetting/tectonic/tar.gz/refs/tags/tectonic%400.16.9"
)
TECTONIC_SOURCE_SHA256 = "9861d4d4230b987d8560f1b84fe6c8a550738401be65b9425b0c7d0466178f2b"
TECTONIC_SOURCE_SIZE = 3_277_181

PYPDF_VERSION = "6.16.1"
PYPDF_WHEEL_NAME = "pypdf-6.16.1-py3-none-any.whl"
PYPDF_WHEEL_URL = (
    "https://files.pythonhosted.org/packages/33/a1/"
    "724b18d6757ab7253a8fecd3a430eb8d980ed26872ba16651e7b5ddfc63f/"
    "pypdf-6.16.1-py3-none-any.whl"
)
PYPDF_WHEEL_SHA256 = "63fec31c4092ae50b6729beedcb469055b60d20c834bde1c402df241f371f644"
PYPDF_WHEEL_SIZE = 382_924
PYPDF_SOURCE_NAME = "pypdf-6.16.1.tar.gz"
PYPDF_SOURCE_URL = (
    "https://files.pythonhosted.org/packages/b6/5a/"
    "df92d1c1ef8806ca28f20f978ee059894868d93de797a7e2edebe7fe1a43/"
    "pypdf-6.16.1.tar.gz"
)
PYPDF_SOURCE_SHA256 = "c4d1b43ddae921387321cf63936cd16a7743b91d2da92f165c149a195c972ba9"
PYPDF_SOURCE_SIZE = 7_003_737

PYPDFIUM2_VERSION = "5.13.0"
PYPDFIUM2_WHEEL_NAME = "pypdfium2-5.13.0-py3-none-manylinux_2_17_x86_64.manylinux2014_x86_64.whl"
PYPDFIUM2_WHEEL_URL = (
    "https://files.pythonhosted.org/packages/d3/7c/"
    "74a2fb48e5b0d2402d9ca64b39074c722d67e9a8a2c58449a843a8c2329a/" + PYPDFIUM2_WHEEL_NAME
)
PYPDFIUM2_WHEEL_SHA256 = "81df25c1ab4c13ff773102d3cbea1967511d079123b067fc077bd0c4d57d91d8"
PYPDFIUM2_WHEEL_SIZE = 3_730_077
PYPDFIUM2_SOURCE_NAME = "pypdfium2-5.13.0.tar.gz"
PYPDFIUM2_SOURCE_URL = (
    "https://files.pythonhosted.org/packages/ec/78/"
    "a52cb80611339ec95f35c7a10d7bfe7a6f97f3b50a35a9f94283d062512e/" + PYPDFIUM2_SOURCE_NAME
)
PYPDFIUM2_SOURCE_SHA256 = "7ca2d8e31bd8d0d40c496416b7d8bea423388669ffd494929f50e8c3a82326b8"
PYPDFIUM2_SOURCE_SIZE = 273_639
PDFIUM_LIBRARY_PATH = "pypdfium2_raw/libpdfium.so"
PDFIUM_LIBRARY_SHA256 = "224f8ece41f7e35891f11c10073b7b7062d7a18e9ef870586162a85c46130f7d"
PDFIUM_LIBRARY_SIZE = 7_669_256
PYPDFIUM2_LICENSE_PREFIX = "pypdfium2-5.13.0.dist-info/licenses/"
PYPDFIUM2_BUILD_LICENSE_PREFIX = PYPDFIUM2_LICENSE_PREFIX + "data/linux_x64/BUILD_LICENSES/"

DEFAULT_BUNDLE_URL = "https://relay.fullyjustified.net/default_bundle_v33.tar"
DEFAULT_BUNDLE_IDENTITY_SHA256 = "6ffe055852f8faf66c0acbe1a7fb27f87b869a90bad1204f3bf4d9683f597c7c"
FONT_SHA256 = "2c76254f6fc379fddfce0a7e84fb5385bb135d3e399294f6eeb6680d0365b74b"
FONT_SIZE = 16_437_364
MAX_DOWNLOAD_BYTES = 256 * 1024 * 1024
MAX_CACHE_BYTES = 512 * 1024 * 1024
MAX_CACHE_MEMBERS = 8_192


class BootstrapError(RuntimeError):
    """The evidence bundle could not be reproduced safely."""


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _write_canonical_json(path: Path, value: object) -> None:
    path.write_bytes(_canonical_bytes(value) + b"\n")


def _read_regular(path: Path, *, limit: int) -> bytes:
    absolute = path.expanduser().absolute()
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    directory_flags = flags | getattr(os, "O_DIRECTORY", 0)
    parent_fd = os.open("/", directory_flags)
    try:
        for part in absolute.parent.parts[1:]:
            next_fd = os.open(part, directory_flags, dir_fd=parent_fd)
            os.close(parent_fd)
            parent_fd = next_fd
        descriptor = os.open(absolute.name, flags, dir_fd=parent_fd)
    except OSError as exc:
        os.close(parent_fd)
        raise BootstrapError(f"regular file is not no-follow readable: {path}") from exc
    os.close(parent_fd)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size > limit
        ):
            raise BootstrapError(f"unsafe or oversized regular file: {path}")
        chunks: list[bytes] = []
        consumed = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, limit - consumed + 1))
            if not chunk:
                break
            consumed += len(chunk)
            if consumed > limit:
                raise BootstrapError(f"oversized regular file: {path}")
            chunks.append(chunk)
        after = os.fstat(descriptor)
        identity = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
            before.st_mode,
            before.st_nlink,
            before.st_uid,
            before.st_gid,
        )
        if consumed != before.st_size or identity != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
            after.st_mode,
            after.st_nlink,
            after.st_uid,
            after.st_gid,
        ):
            raise BootstrapError(f"file changed while read: {path}")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _download(
    *, url: str, destination: Path, expected_sha256: str, expected_size: int
) -> dict[str, object]:
    if destination.exists():
        content = _read_regular(destination, limit=MAX_DOWNLOAD_BYTES)
    else:
        request = urllib.request.Request(url, headers={"User-Agent": "owner-equity-research/1"})
        with urllib.request.urlopen(request, timeout=120) as response:  # noqa: S310
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_DOWNLOAD_BYTES:
                    raise BootstrapError(f"download exceeds byte limit: {url}")
                chunks.append(chunk)
        content = b"".join(chunks)
        destination.write_bytes(content)
    if len(content) != expected_size or _sha256(content) != expected_sha256:
        raise BootstrapError(f"download identity mismatch: {url}")
    return {
        "url": url,
        "path": destination.name,
        "sha256": expected_sha256,
        "size": expected_size,
    }


def _safe_extract_tectonic(archive: Path, destination: Path) -> Path:
    content = _read_regular(archive, limit=MAX_DOWNLOAD_BYTES)
    with tarfile.open(fileobj=io.BytesIO(content), mode="r:gz") as bundle:
        members = bundle.getmembers()
        if len(members) != 1:
            raise BootstrapError("Tectonic release archive must contain exactly one member")
        member = members[0]
        if member.name != "tectonic" or not member.isfile() or member.issym() or member.islnk():
            raise BootstrapError("Tectonic release archive member is unsafe")
        extracted = bundle.extractfile(member)
        if extracted is None:
            raise BootstrapError("Tectonic release archive cannot be read")
        binary = extracted.read(256 * 1024 * 1024 + 1)
    if len(binary) != TECTONIC_BINARY_SIZE or _sha256(binary) != TECTONIC_BINARY_SHA256:
        raise BootstrapError("extracted Tectonic binary identity mismatch")
    destination.write_bytes(binary)
    destination.chmod(0o500)
    return destination


def _tree_identity(root: Path, *, include_directories: bool) -> dict[str, object]:
    digest = hashlib.sha256()
    count = 0
    total = 0
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        details = path.lstat()
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            raise BootstrapError(f"tree contains a symlink: {relative}")
        if path.is_dir():
            if include_directories:
                count += 1
                digest.update(relative.encode("utf-8"))
                digest.update(b"\0directory\0")
            continue
        if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
            raise BootstrapError(f"tree contains a non-regular member: {relative}")
        content = _read_regular(path, limit=MAX_CACHE_BYTES - total)
        count += 1
        total += len(content)
        if count > MAX_CACHE_MEMBERS or total > MAX_CACHE_BYTES:
            raise BootstrapError("tree exceeds the report-toolchain authority limits")
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(len(content)).encode("ascii"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(content).digest())
    if count == 0 or total == 0:
        raise BootstrapError("tree identity cannot be empty")
    return {"tree_sha256": digest.hexdigest(), "member_count": count, "total_bytes": total}


def _distribution_identity(python: Path, distribution: str) -> dict[str, object]:
    worker = r"""
import base64
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path, PurePosixPath
import stat
import sys

def read_regular(path):
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise SystemExit(f"unsafe distribution member: {path}")
        chunks = []
        consumed = 0
        maximum = 384 * 1024 * 1024
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, maximum - consumed + 1))
            if not chunk:
                break
            consumed += len(chunk)
            if consumed > maximum:
                raise SystemExit(f"oversized distribution member: {path}")
            chunks.append(chunk)
        after = os.fstat(descriptor)
        identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
                    before.st_ctime_ns, before.st_mode, before.st_nlink)
        if consumed != before.st_size or identity != (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
            after.st_ctime_ns, after.st_mode, after.st_nlink
        ):
            raise SystemExit(f"distribution member changed: {path}")
        return b"".join(chunks)
    finally:
        os.close(descriptor)

name = sys.argv[1]
dist = importlib.metadata.distribution(name)
excluded = {"INSTALLER", "RECORD", "REQUESTED", "direct_url.json", "uv_cache.json"}
files = []
for item in dist.files or ():
    relative = PurePosixPath(str(item))
    record_hash = getattr(item, "hash", None)
    record_size = getattr(item, "size", None)
    if (
        relative.name in excluded
        or "__pycache__" in relative.parts
        or relative.suffix == ".pyc"
        or ".." in relative.parts
        or record_hash is None
        or record_size is None
        or getattr(record_hash, "mode", None) != "sha256"
    ):
        continue
    record_sha256 = getattr(record_hash, "value", None)
    if (
        type(record_sha256) is not str
        or len(record_sha256) != 43
        or any(character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
               for character in record_sha256)
        or type(record_size) is not int
        or record_size < 0
    ):
        raise SystemExit(f"invalid RECORD entry: {relative}")
    files.append((item, record_sha256, record_size))
files.sort(key=lambda item: str(item[0]))
digest = hashlib.sha256()
total = 0
for member, record_sha256, record_size in files:
    relative = PurePosixPath(str(member)).as_posix()
    path = Path(dist.locate_file(member)).absolute()
    content = read_regular(path)
    if len(content) != record_size:
        raise SystemExit(f"distribution member differs from RECORD size: {relative}")
    content_record_sha256 = base64.urlsafe_b64encode(
        hashlib.sha256(content).digest()
    ).rstrip(b"=").decode("ascii")
    if content_record_sha256 != record_sha256:
        raise SystemExit(f"distribution member differs from RECORD SHA-256: {relative}")
    total += len(content)
    digest.update(relative.encode("utf-8"))
    digest.update(b"\0")
    digest.update(str(len(content)).encode("ascii"))
    digest.update(b"\0")
    digest.update(hashlib.sha256(content).digest())
print(json.dumps({
    "distribution": name,
    "version": dist.version,
    "tree_sha256": digest.hexdigest(),
    "member_count": len(files),
    "total_bytes": total,
}, sort_keys=True, separators=(",", ":")))
"""
    completed = subprocess.run(
        [str(python), "-c", worker, distribution],
        check=True,
        capture_output=True,
        text=True,
        timeout=120,
    )
    identity = json.loads(completed.stdout)
    if identity["version"] not in {PYPDF_VERSION, PYPDFIUM2_VERSION}:
        raise BootstrapError(f"unexpected {distribution} version")
    return identity


def _wheel_tree_identity(wheel: Path, prefix: str) -> dict[str, object]:
    digest = hashlib.sha256()
    members: list[dict[str, object]] = []
    total = 0
    with zipfile.ZipFile(wheel) as archive:
        names = tuple(sorted(name for name in archive.namelist() if name.startswith(prefix)))
        if not names:
            raise BootstrapError(f"wheel tree is empty: {prefix}")
        for name in names:
            info = archive.getinfo(name)
            if info.is_dir():
                continue
            relative = PurePosixPath(name).relative_to(PurePosixPath(prefix)).as_posix()
            if not relative or ".." in PurePosixPath(relative).parts:
                raise BootstrapError(f"unsafe wheel tree member: {name}")
            content = archive.read(name)
            total += len(content)
            digest.update(relative.encode("utf-8"))
            digest.update(b"\0")
            digest.update(str(len(content)).encode("ascii"))
            digest.update(b"\0")
            digest.update(hashlib.sha256(content).digest())
            members.append({"path": relative, "sha256": _sha256(content), "size": len(content)})
    return {
        "tree_sha256": digest.hexdigest(),
        "member_count": len(members),
        "total_bytes": total,
        "members": members,
    }


def _wheel_member_identity(wheel: Path, member: str) -> dict[str, object]:
    with zipfile.ZipFile(wheel) as archive:
        try:
            content = archive.read(member)
        except KeyError as exc:
            raise BootstrapError(f"wheel member is unavailable: {member}") from exc
    if len(content) != PDFIUM_LIBRARY_SIZE or _sha256(content) != PDFIUM_LIBRARY_SHA256:
        raise BootstrapError("bundled PDFium shared-library identity mismatch")
    return {"path": member, "sha256": _sha256(content), "size": len(content)}


def _fixture_tex() -> bytes:
    sections: list[str] = []
    for index in range(1, 31):
        revenue = 900 + index * 17
        margin = 12 + (index % 9)
        roic = 10 + (index % 8)
        sections.append(
            rf"""
\section{{验证章节 {index:02d}：所有者视角与证据边界}}
本页是 Linux x86\_64 报告工具链的实质性渲染样本。章节 {index:02d} 只用于验证排版、
中文字体嵌入、表格、页眉页脚、文本抽取与逐页图像渲染。所有数字均明确标记为测试夹具，
不代表任何真实证券、公司、建议或市场判断。

\subsection{{经营质量与资本效率}}
测试公司在场景 {index:02d} 中展示收入、经营利润率、投入资本回报率与现金转化的关系。
研究流程应先固定官方证据和会计口径，再讨论商业质量；未知信息保持 Unknown，不能把缺失
证据当作零，也不能用供应商快照覆盖监管披露。

\begingroup
\small
\begin{{longtable}}{{>{{\raggedright\arraybackslash}}p{{0.23\textwidth}}rrp{{0.42\textwidth}}}}
\toprule
测试指标 & 基准值 & 压力值 & 单位 \\
\midrule
\endfirsthead
\toprule
测试指标 & 基准值 & 压力值 & 单位 \\
\midrule
\endhead
\midrule
\multicolumn{{4}}{{r}}{{续下页}} \\
\endfoot
\bottomrule
\endlastfoot
收入 & {revenue} & {revenue - 73} & 百万美元 \\
经营利润率 & {margin} & {max(1, margin - 4)} & 百分比 \\
投入资本回报率 & {roic} & {max(1, roic - 5)} & 百分比 \\
\end{{longtable}}
\endgroup

\subsection{{风险、证伪与可追溯性}}
永久损失风险必须与短期波动分开。若客户留存、单位经济性、管理层资本配置或资产负债表
韧性偏离冻结假设，结论应降级或撤销。每个表格和结论都必须能回放到来源、期间、币种、
股类与计算程序；评分只能消费证据，不能改写事实或估值。

本章节至少包含一段完整的中文分析文本和一个结构化表格，用来阻止空白页、机械填充页或
仅标题页通过质量检查。唯一章节标记为 OER-LINUX-X64-{index:02d}。
"""
        )
        if index != 30:
            sections.append("\\clearpage\n")
    document = (
        r"""\documentclass[11pt,a4paper,UTF8,fontset=none]{ctexart}
\setCJKmainfont[Path=./,AutoFakeBold=2.2,AutoFakeSlant=0.18]{NotoSansCJKsc-Regular.otf}
\setCJKsansfont[Path=./,AutoFakeBold=2.2,AutoFakeSlant=0.18]{NotoSansCJKsc-Regular.otf}
\setCJKmonofont[Path=./,AutoFakeBold=2.2,AutoFakeSlant=0.18]{NotoSansCJKsc-Regular.otf}
\usepackage[a4paper,top=22mm,bottom=22mm,left=21mm,right=21mm]{geometry}
\usepackage{booktabs}
\usepackage{longtable}
\usepackage{array}
\usepackage{xcolor}
\usepackage{hyperref}
\usepackage{fancyhdr}
\usepackage{lastpage}
\usepackage{microtype}
\definecolor{OwnerNavy}{HTML}{17324D}
\definecolor{OwnerGray}{HTML}{5B6573}
\hypersetup{hidelinks,pdfcreator={owner-equity-research-linux-x64-bootstrap}}
\setlength{\parindent}{2em}
\setlength{\parskip}{0.45em}
\renewcommand{\arraystretch}{1.24}
\pagestyle{fancy}
\fancyhf{}
\fancyhead[L]{\small\color{OwnerGray}所有者视角研究工具链验证}
\fancyhead[R]{\small\color{OwnerGray}Linux x86\_64}
\fancyfoot[C]{\small\color{OwnerGray}第 \thepage\ 页 / 共 \pageref{LastPage} 页}
\setcounter{secnumdepth}{2}
\begin{document}
\begin{titlepage}
\centering
\vspace*{20mm}
{\Huge\bfseries\color{OwnerNavy} 所有者视角综合研究报告\par}
\vspace{8mm}
{\Large OER Linux x86\_64 bootstrap issuer\par}
\vspace{4mm}
{\large 数据截止日：2000-01-01\par}
{\large 配置：offline report toolchain bootstrap\par}
\vspace{8mm}
{\tiny Latin Modern tiny size runtime evidence probe.\par}
{\fontsize{5pt}{6pt}\selectfont Latin Modern five point runtime evidence probe.\par}
{\scriptsize Latin Modern scriptsize runtime evidence probe.\par}
{\fontsize{7pt}{8pt}\selectfont Latin Modern seven point runtime evidence probe.\par}
{\footnotesize Latin Modern footnotesize runtime evidence probe.\par}
{\small Latin Modern small size runtime evidence probe.\par}
{\normalsize Latin Modern normalsize runtime evidence probe.\par}
{\large Latin Modern large size runtime evidence probe.\par}
{\Large Latin Modern Large size runtime evidence probe.\par}
{\LARGE Latin Modern LARGE size runtime evidence probe.\par}
{\huge Latin Modern huge size runtime evidence probe.\par}
{\Huge\bfseries Latin Modern Huge bold runtime evidence probe.\par}
\vfill
{\small 证据有界、结果可重放、缺口不猜测。This substantive bootstrap cover exercises every
standard LaTeX font size used by the real report while preserving extractable text and visual
content for the all-page quality gate.\par}
\end{titlepage}
"""
        + "".join(sections)
        + "\n\\end{document}\n"
    )
    return document.encode("utf-8")


def _closed_environment(workspace: Path, cache: Path, executable: Path) -> dict[str, str]:
    return {
        "PATH": f"{executable.parent}:/usr/bin:/bin",
        "HOME": str(workspace),
        "TMPDIR": str(workspace),
        "TECTONIC_CACHE_DIR": str(cache),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "SOURCE_DATE_EPOCH": SOURCE_DATE_EPOCH,
        "TZ": "UTC",
        "openin_any": "p",
        "openout_any": "p",
        "shell_escape": "0",
    }


def _run_tectonic(
    *, executable: Path, cache: Path, workspace: Path, offline_network_namespace: bool
) -> subprocess.CompletedProcess[bytes]:
    command = [
        str(executable),
        *(["--only-cached"] if offline_network_namespace else []),
        "--untrusted",
        "--keep-logs",
        "--reruns",
        "1",
        "--outdir",
        ".",
        "report.tex",
    ]
    environment = _closed_environment(workspace, cache, executable)
    if offline_network_namespace:
        if shutil.which("sudo") is None or not Path("/usr/bin/unshare").is_file():
            raise BootstrapError("offline proof requires sudo and /usr/bin/unshare")
        command = [
            "sudo",
            "-n",
            "/usr/bin/unshare",
            "--net",
            "/usr/bin/env",
            "-i",
            *(f"{key}={value}" for key, value in sorted(environment.items())),
            *command,
        ]
        environment = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}
    completed = subprocess.run(
        command,
        cwd=workspace,
        env=environment,
        check=False,
        capture_output=True,
        timeout=600,
    )
    if completed.returncode != 0:
        stderr_sha = _sha256(completed.stderr)
        raise BootstrapError(
            f"Tectonic failed with code {completed.returncode}; stderr_sha256={stderr_sha}"
        )
    return completed


def _qa_pdf(python: Path, pdf: Path, pages: Path) -> dict[str, object]:
    worker = r"""
import hashlib
from io import BytesIO
import json
import os
from pathlib import Path
import re
import stat
import sys
from pypdf import PdfReader
import pypdfium2

pdf_path = Path(sys.argv[1])
pages_root = Path(sys.argv[2])
pages_root.mkdir(mode=0o700)
descriptor = os.open(
    pdf_path,
    os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
)
try:
    before = os.fstat(descriptor)
    maximum = 128 * 1024 * 1024
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > maximum:
        raise SystemExit("unsafe or oversized PDF")
    chunks = []
    consumed = 0
    while True:
        chunk = os.read(descriptor, min(1024 * 1024, maximum - consumed + 1))
        if not chunk:
            break
        consumed += len(chunk)
        if consumed > maximum:
            raise SystemExit("oversized PDF")
        chunks.append(chunk)
    after = os.fstat(descriptor)
    identity = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
                before.st_ctime_ns, before.st_mode, before.st_nlink)
    if consumed != before.st_size or identity != (
        after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
        after.st_ctime_ns, after.st_mode, after.st_nlink
    ):
        raise SystemExit("PDF changed while read")
    pdf_bytes = b"".join(chunks)
finally:
    os.close(descriptor)
reader = PdfReader(BytesIO(pdf_bytes))
texts = [page.extract_text() or "" for page in reader.pages]
counts = [len(re.sub(r"\s+", "", text)) for text in texts]
if not 30 <= len(texts) <= 60:
    raise SystemExit(f"unexpected page count: {len(texts)}")
if not counts or min(counts) < 180:
    raise SystemExit(f"blank or sparse page: {min(counts) if counts else 0}")
joined = "\n\f\n".join(texts)
if "所有者视角" not in joined or len(set(re.findall(r"OER-LINUX-X64-\d{2}", joined))) != 30:
    raise SystemExit("substantive fixture markers did not survive PDF extraction")
doc = pypdfium2.PdfDocument(pdf_bytes)
if len(doc) != len(texts):
    raise SystemExit("rendered page count differs from pypdf page count")
render_digest = hashlib.sha256()
non_white_ratios = []
page_hashes = []
for index in range(len(doc)):
    page = doc[index]
    bitmap = page.render(
        scale=48 / 72,
        fill_color=(255, 255, 255, 255),
        rev_byteorder=True,
        prefer_bgrx=False,
    )
    if bitmap.n_channels != 3 or bitmap.stride < bitmap.width * 3:
        raise SystemExit(f"unexpected PDFium bitmap format on page: {index + 1}")
    raw = bytes(bitmap.buffer)
    sample = b"".join(
        raw[offset : offset + bitmap.width * 3]
        for offset in range(0, bitmap.stride * bitmap.height, bitmap.stride)
    )
    non_white = sum(value != 255 for value in sample) / len(sample)
    if non_white < 0.003:
        raise SystemExit(f"visually blank page: {index + 1}")
    digest = hashlib.sha256(sample).hexdigest()
    page_hashes.append(digest)
    non_white_ratios.append(round(non_white, 8))
    render_digest.update(str(index + 1).encode("ascii"))
    render_digest.update(b"\0")
    render_digest.update(str(bitmap.width).encode("ascii"))
    render_digest.update(b"x")
    render_digest.update(str(bitmap.height).encode("ascii"))
    render_digest.update(b"\0")
    render_digest.update(bytes.fromhex(digest))
    ppm = f"P6\n{bitmap.width} {bitmap.height}\n255\n".encode("ascii") + sample
    (pages_root / f"page-{index + 1:02d}.ppm").write_bytes(ppm)
    bitmap.close()
    page.close()
doc.close()
print(json.dumps({
    "pdf_sha256": hashlib.sha256(pdf_bytes).hexdigest(),
    "pdf_size": len(pdf_bytes),
    "page_count": len(texts),
    "rendered_page_count": len(page_hashes),
    "extracted_text_sha256": hashlib.sha256(joined.encode("utf-8")).hexdigest(),
    "extracted_text_characters": len(joined),
    "page_text_character_counts": counts,
    "minimum_page_text_characters": min(counts),
    "page_render_sample_sha256": page_hashes,
    "render_tree_sha256": render_digest.hexdigest(),
    "page_non_white_ratios": non_white_ratios,
    "minimum_non_white_ratio": min(non_white_ratios),
}, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
"""
    completed = subprocess.run(
        [str(python), "-c", worker, str(pdf), str(pages)],
        check=True,
        capture_output=True,
        text=True,
        timeout=300,
    )
    return json.loads(completed.stdout)


def _deterministic_archive(root: Path, destination: Path) -> dict[str, object]:
    with destination.open("wb") as raw:
        with gzip.GzipFile(
            filename="", mode="wb", fileobj=raw, mtime=0, compresslevel=6
        ) as compressed:
            with tarfile.open(fileobj=compressed, mode="w") as archive:
                for path in sorted(
                    root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()
                ):
                    relative = path.relative_to(root).as_posix()
                    details = path.lstat()
                    if path.is_symlink():
                        raise BootstrapError(f"cannot archive symlink: {relative}")
                    info = tarfile.TarInfo(relative)
                    info.uid = 0
                    info.gid = 0
                    info.uname = "root"
                    info.gname = "root"
                    info.mtime = 0
                    if path.is_dir():
                        info.type = tarfile.DIRTYPE
                        info.mode = 0o555
                        archive.addfile(info)
                    elif stat.S_ISREG(details.st_mode):
                        content = _read_regular(path, limit=MAX_CACHE_BYTES)
                        info.size = len(content)
                        info.mode = 0o444
                        archive.addfile(info, io.BytesIO(content))
                    else:
                        raise BootstrapError(f"cannot archive non-regular member: {relative}")
    content = _read_regular(destination, limit=MAX_CACHE_BYTES)
    return {"path": destination.name, "sha256": _sha256(content), "size": len(content)}


def _wheel_license(wheel: Path) -> dict[str, object]:
    with zipfile.ZipFile(wheel) as archive:
        names = tuple(
            sorted(
                name
                for name in archive.namelist()
                if "license" in PurePosixPath(name).name.lower()
                or "copying" in PurePosixPath(name).name.lower()
            )
        )
        if not names:
            raise BootstrapError(f"wheel has no embedded license evidence: {wheel.name}")
        members = []
        for name in names:
            content = archive.read(name)
            members.append({"path": name, "sha256": _sha256(content), "size": len(content)})
    return {"members": members}


def _spdx_document(
    *, name: str, version: str, download_url: str, checksum: str, license_id: str
) -> dict[str, object]:
    namespace_seed = hashlib.sha256(f"{name}:{version}:{checksum}".encode()).hexdigest()
    return {
        "SPDXID": "SPDXRef-DOCUMENT",
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "name": f"owner-equity-research-{name}-{version}",
        "documentNamespace": f"https://owner-equity-research.invalid/spdx/{namespace_seed}",
        "creationInfo": {
            "created": "2000-01-01T00:00:00Z",
            "creators": ["Tool: bootstrap_linux_x64_report_toolchain.py"],
        },
        "packages": [
            {
                "SPDXID": "SPDXRef-Package",
                "name": name,
                "versionInfo": version,
                "downloadLocation": download_url,
                "filesAnalyzed": False,
                "licenseConcluded": license_id,
                "licenseDeclared": license_id,
                "checksums": [{"algorithm": "SHA256", "checksumValue": checksum}],
                "copyrightText": "NOASSERTION",
            }
        ],
        "relationships": [
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": "SPDXRef-Package",
            }
        ],
    }


def _pypdfium2_spdx_document() -> dict[str, object]:
    namespace_seed = hashlib.sha256(
        f"pypdfium2:{PYPDFIUM2_VERSION}:{PYPDFIUM2_WHEEL_SHA256}".encode()
    ).hexdigest()
    return {
        "SPDXID": "SPDXRef-DOCUMENT",
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "name": f"owner-equity-research-pypdfium2-{PYPDFIUM2_VERSION}",
        "documentNamespace": f"https://owner-equity-research.invalid/spdx/{namespace_seed}",
        "creationInfo": {
            "created": "2000-01-01T00:00:00Z",
            "creators": ["Tool: bootstrap_linux_x64_report_toolchain.py"],
        },
        "packages": [
            {
                "SPDXID": "SPDXRef-pypdfium2",
                "name": "pypdfium2",
                "versionInfo": PYPDFIUM2_VERSION,
                "downloadLocation": PYPDFIUM2_WHEEL_URL,
                "filesAnalyzed": False,
                "licenseConcluded": "Apache-2.0 OR BSD-3-Clause",
                "licenseDeclared": "Apache-2.0 OR BSD-3-Clause",
                "checksums": [{"algorithm": "SHA256", "checksumValue": PYPDFIUM2_WHEEL_SHA256}],
                "copyrightText": "NOASSERTION",
            },
            {
                "SPDXID": "SPDXRef-PDFium",
                "name": "PDFium bundled linux_x64 library",
                "versionInfo": f"pypdfium2-{PYPDFIUM2_VERSION}",
                "downloadLocation": PYPDFIUM2_WHEEL_URL,
                "filesAnalyzed": False,
                "licenseConcluded": "LicenseRef-PDFium-Build-License-Set",
                "licenseDeclared": "LicenseRef-PDFium-Build-License-Set",
                "checksums": [{"algorithm": "SHA256", "checksumValue": PDFIUM_LIBRARY_SHA256}],
                "copyrightText": "NOASSERTION",
            },
        ],
        "relationships": [
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": "SPDXRef-pypdfium2",
            },
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": "SPDXRef-PDFium",
            },
            {
                "spdxElementId": "SPDXRef-pypdfium2",
                "relationshipType": "CONTAINS",
                "relatedSpdxElement": "SPDXRef-PDFium",
            },
        ],
        "hasExtractedLicensingInfos": [
            {
                "licenseId": "LicenseRef-PDFium-Build-License-Set",
                "name": "Exact bundled PDFium BUILD_LICENSES inventory",
                "extractedText": (
                    "The exact license texts are retained and hashed from the wheel's "
                    "data/linux_x64/BUILD_LICENSES tree in the derivation evidence."
                ),
            }
        ],
    }


def _main(arguments: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--font", type=Path, required=True)
    args = parser.parse_args(arguments)

    if platform.system().lower() != "linux" or platform.machine().lower() != "x86_64":
        raise BootstrapError("this bootstrap must execute on Linux x86_64")
    output = args.output.absolute()
    if output.exists() and any(output.iterdir()):
        raise BootstrapError("output directory must be absent or empty")
    output.mkdir(parents=True, exist_ok=True, mode=0o700)
    downloads = output / "downloads"
    downloads.mkdir(mode=0o700)
    evidence = output / "evidence"
    evidence.mkdir(mode=0o700)

    font = args.font.absolute()
    font_bytes = _read_regular(font, limit=32 * 1024 * 1024)
    if len(font_bytes) != FONT_SIZE or _sha256(font_bytes) != FONT_SHA256:
        raise BootstrapError("Noto CJK font identity mismatch")

    tectonic_archive = downloads / TECTONIC_ARCHIVE_NAME
    tectonic_download = _download(
        url=TECTONIC_ARCHIVE_URL,
        destination=tectonic_archive,
        expected_sha256=TECTONIC_ARCHIVE_SHA256,
        expected_size=TECTONIC_ARCHIVE_SIZE,
    )
    tectonic_license = _download(
        url=TECTONIC_LICENSE_URL,
        destination=downloads / "tectonic-LICENSE-0.16.9",
        expected_sha256=TECTONIC_LICENSE_SHA256,
        expected_size=TECTONIC_LICENSE_SIZE,
    )
    tectonic_source = _download(
        url=TECTONIC_SOURCE_URL,
        destination=downloads / "tectonic-0.16.9-source.tar.gz",
        expected_sha256=TECTONIC_SOURCE_SHA256,
        expected_size=TECTONIC_SOURCE_SIZE,
    )
    pypdf_wheel = downloads / PYPDF_WHEEL_NAME
    pypdf_download = _download(
        url=PYPDF_WHEEL_URL,
        destination=pypdf_wheel,
        expected_sha256=PYPDF_WHEEL_SHA256,
        expected_size=PYPDF_WHEEL_SIZE,
    )
    pypdf_source = _download(
        url=PYPDF_SOURCE_URL,
        destination=downloads / PYPDF_SOURCE_NAME,
        expected_sha256=PYPDF_SOURCE_SHA256,
        expected_size=PYPDF_SOURCE_SIZE,
    )
    pypdfium2_wheel = downloads / PYPDFIUM2_WHEEL_NAME
    pypdfium2_download = _download(
        url=PYPDFIUM2_WHEEL_URL,
        destination=pypdfium2_wheel,
        expected_sha256=PYPDFIUM2_WHEEL_SHA256,
        expected_size=PYPDFIUM2_WHEEL_SIZE,
    )
    pypdfium2_source = _download(
        url=PYPDFIUM2_SOURCE_URL,
        destination=downloads / PYPDFIUM2_SOURCE_NAME,
        expected_sha256=PYPDFIUM2_SOURCE_SHA256,
        expected_size=PYPDFIUM2_SOURCE_SIZE,
    )

    executable = output / "tectonic"
    _safe_extract_tectonic(tectonic_archive, executable)
    version = (
        subprocess.run(
            [str(executable), "--version"],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
        )
        .stdout.strip()
        .splitlines()[0]
    )
    if version != "Tectonic 0.16.9":
        raise BootstrapError("Tectonic version differs from the locked version")

    venv = output / "venv"
    subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True, timeout=180)
    venv_python = venv / "bin" / "python"
    subprocess.run(
        [
            str(venv_python),
            "-m",
            "pip",
            "install",
            "--no-index",
            "--no-deps",
            "--disable-pip-version-check",
            str(pypdf_wheel),
            str(pypdfium2_wheel),
        ],
        check=True,
        timeout=300,
    )
    pypdf_identity = _distribution_identity(venv_python, "pypdf")
    pypdfium2_identity = _distribution_identity(venv_python, "pypdfium2")
    pdfium_library_identity = _wheel_member_identity(pypdfium2_wheel, PDFIUM_LIBRARY_PATH)
    pypdfium2_license_identity = _wheel_tree_identity(pypdfium2_wheel, PYPDFIUM2_LICENSE_PREFIX)
    pdfium_build_license_identity = _wheel_tree_identity(
        pypdfium2_wheel, PYPDFIUM2_BUILD_LICENSE_PREFIX
    )

    cache = output / "tectonic-cache"
    cache.mkdir(mode=0o700)
    warm = output / "warm-run"
    warm.mkdir(mode=0o700)
    (warm / "report.tex").write_bytes(_fixture_tex())
    (warm / "NotoSansCJKsc-Regular.otf").write_bytes(font_bytes)
    _run_tectonic(
        executable=executable,
        cache=cache,
        workspace=warm,
        offline_network_namespace=False,
    )
    cache_identity_before = _tree_identity(cache, include_directories=True)

    offline = output / "offline-run"
    offline.mkdir(mode=0o755)
    (offline / "report.tex").write_bytes(_fixture_tex())
    (offline / "NotoSansCJKsc-Regular.otf").write_bytes(font_bytes)
    _run_tectonic(
        executable=executable,
        cache=cache,
        workspace=offline,
        offline_network_namespace=True,
    )
    cache_identity_after = _tree_identity(cache, include_directories=True)
    if cache_identity_before != cache_identity_after:
        raise BootstrapError("offline render mutated the selective Tectonic cache")
    pdf = offline / "report.pdf"
    qa = _qa_pdf(venv_python, pdf, output / "rendered-pages")

    cache_archive = output / "tectonic-cache-linux-x64-v33.tar.gz"
    cache_archive_identity = _deterministic_archive(cache, cache_archive)
    cache_member_manifest = []
    for path in sorted(cache.rglob("*"), key=lambda item: item.relative_to(cache).as_posix()):
        if path.is_file():
            content = _read_regular(path, limit=MAX_CACHE_BYTES)
            cache_member_manifest.append(
                {
                    "path": path.relative_to(cache).as_posix(),
                    "sha256": _sha256(content),
                    "size": len(content),
                }
            )
    derivation = {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": "report-toolchain-cache-derivation",
        "platform_target": "linux-x64",
        "tectonic_version": version,
        "tectonic_target": "x86_64-unknown-linux-gnu",
        "upstream_bundle_url": DEFAULT_BUNDLE_URL,
        "upstream_bundle_identity_sha256": DEFAULT_BUNDLE_IDENTITY_SHA256,
        "upstream_digest_receipt": {
            "cache_path_encoding": (
                "bundles/hashes/https,58,,47,,47,relay.fullyjustified.net,47,default_bundle_v33.tar"
            ),
            "content": DEFAULT_BUNDLE_IDENTITY_SHA256 + "\n",
            "sha256": _sha256((DEFAULT_BUNDLE_IDENTITY_SHA256 + "\n").encode("ascii")),
        },
        "selected_cache_tree": cache_identity_after,
        "selected_regular_members": cache_member_manifest,
        "deterministic_archive": cache_archive_identity,
        "substantive_fixture_sha256": _sha256(_fixture_tex()),
        "offline_network_namespace": {
            "tool": "/usr/bin/unshare --net",
            "only_cached": True,
            "status": "passed",
        },
    }
    derivation_path = evidence / "tectonic-cache-derivation.json"
    _write_canonical_json(derivation_path, derivation)

    component_sboms = {
        "renderer": _spdx_document(
            name="tectonic",
            version=TECTONIC_VERSION,
            download_url=TECTONIC_ARCHIVE_URL,
            checksum=TECTONIC_ARCHIVE_SHA256,
            license_id="MIT",
        ),
        "offline_bundle": _spdx_document(
            name="tectonic-default-bundle-v33-selective-cache",
            version=DEFAULT_BUNDLE_IDENTITY_SHA256[:16],
            download_url=DEFAULT_BUNDLE_URL,
            checksum=DEFAULT_BUNDLE_IDENTITY_SHA256,
            license_id="LicenseRef-TeX-Live-Mixed",
        ),
        "pdf_text_backend": _spdx_document(
            name="pypdf",
            version=PYPDF_VERSION,
            download_url=PYPDF_WHEEL_URL,
            checksum=PYPDF_WHEEL_SHA256,
            license_id="BSD-3-Clause",
        ),
        "pdf_render_backend": _pypdfium2_spdx_document(),
    }
    sbom_receipts: dict[str, dict[str, object]] = {}
    for component, document in component_sboms.items():
        path = evidence / f"{component}.spdx.json"
        _write_canonical_json(path, document)
        content = _read_regular(path, limit=4 * 1024 * 1024)
        sbom_receipts[component] = {
            "path": path.relative_to(output).as_posix(),
            "sha256": _sha256(content),
        }

    runtime_components = {
        "renderer": {
            "engine": "tectonic",
            "basename": "tectonic",
            "sha256": TECTONIC_BINARY_SHA256,
            "size": TECTONIC_BINARY_SIZE,
            "version": version,
        },
        "offline_bundle": cache_identity_after,
        "pdf_text_backend": pypdf_identity,
        "pdf_render_backend": pypdfium2_identity,
    }
    provenance = {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": "linux-x64-report-toolchain-evidence",
        "platform": {
            "target": "linux-x64",
            "system": "Linux",
            "machine": "x86_64",
        },
        "runtime_components": runtime_components,
        "pdfium_runtime_evidence": {
            "library": pdfium_library_identity,
            "license_tree": pypdfium2_license_identity,
            "build_license_tree": pdfium_build_license_identity,
        },
        "downloads": {
            "tectonic": tectonic_download,
            "pypdf": pypdf_download,
            "pypdfium2": pypdfium2_download,
        },
        "sources": {
            "tectonic": tectonic_source,
            "pypdf": pypdf_source,
            "pypdfium2": pypdfium2_source,
        },
        "licenses": {
            "tectonic": tectonic_license,
            "pypdf_wheel": _wheel_license(pypdf_wheel),
            "pypdfium2_wheel": {
                "license_tree": pypdfium2_license_identity,
                "build_license_tree": pdfium_build_license_identity,
            },
            "offline_bundle": {
                "spdx_license_id": "LicenseRef-TeX-Live-Mixed",
                "status": "selected-cache-file-SBOM-recorded",
            },
        },
        "sboms": sbom_receipts,
        "cache_derivation": {
            "path": derivation_path.relative_to(output).as_posix(),
            "sha256": _sha256(_read_regular(derivation_path, limit=16 * 1024 * 1024)),
        },
        "qa": qa,
        "release_evidence_status": "ready",
        "missing_evidence_codes": [],
        "bootstrap_script_sha256": _sha256(
            _read_regular(Path(__file__), limit=16 * 1024 * 1024)
        ),
    }
    provenance["evidence_fingerprint"] = _sha256(_canonical_bytes(provenance))
    provenance_path = output / "linux-x64-report-toolchain-evidence.json"
    _write_canonical_json(provenance_path, provenance)

    derivation_receipt = {
        "path": provenance_path.name,
        "sha256": _sha256(_read_regular(provenance_path, limit=16 * 1024 * 1024)),
    }
    component_inputs = {
        "renderer": {
            "download": tectonic_download,
            "source": tectonic_source,
            "license_scope": "tectonic",
            "license_id": "MIT",
        },
        "offline_bundle": {
            "download": {
                "url": DEFAULT_BUNDLE_URL,
                "sha256": DEFAULT_BUNDLE_IDENTITY_SHA256,
            },
            "source": {
                "url": DEFAULT_BUNDLE_URL,
                "sha256": DEFAULT_BUNDLE_IDENTITY_SHA256,
            },
            "license_scope": "tectonic-default-bundle-v33-selective-cache",
            "license_id": "LicenseRef-TeX-Live-Mixed",
        },
        "pdf_text_backend": {
            "download": pypdf_download,
            "source": pypdf_source,
            "license_scope": "pypdf",
            "license_id": "BSD-3-Clause",
        },
        "pdf_render_backend": {
            "download": pypdfium2_download,
            "source": pypdfium2_source,
            "license_scope": "pypdfium2-and-pdfium",
            "license_id": "LicenseRef-PDFium-Build-License-Set",
        },
    }
    supply_components = {}
    for component_name, component_input in component_inputs.items():
        sbom = sbom_receipts[component_name]
        derivation = (
            {
                "path": derivation_path.relative_to(output).as_posix(),
                "sha256": _sha256(
                    _read_regular(derivation_path, limit=16 * 1024 * 1024)
                ),
            }
            if component_name == "offline_bundle"
            else derivation_receipt
        )
        supply_components[component_name] = {
            "component_name": component_name,
            "runtime_identity_sha256": _sha256(
                _canonical_bytes(runtime_components[component_name])
            ),
            "download_url": component_input["download"]["url"],
            "download_sha256": component_input["download"]["sha256"],
            "source_url": component_input["source"]["url"],
            "source_sha256": component_input["source"]["sha256"],
            "license_inventory": [
                {
                    "component_scope": component_input["license_scope"],
                    "spdx_license_id": component_input["license_id"],
                    "license_path": sbom["path"],
                    "license_sha256": sbom["sha256"],
                }
            ],
            "sbom_path": sbom["path"],
            "sbom_sha256": sbom["sha256"],
            "derivation_manifest_path": derivation["path"],
            "derivation_manifest_sha256": derivation["sha256"],
        }
    authority_identity = {
        "schema_version": SCHEMA_VERSION,
        "artifact_type": "report-toolchain-authority-entry",
        "platform_target": "linux-x64",
        "release_evidence_status": "ready",
        **runtime_components,
        "supply_chain": {
            "status": "ready",
            "components": supply_components,
            "missing_evidence_codes": [],
        },
    }
    authority_fingerprint = _sha256(_canonical_bytes(authority_identity))
    authority_identity["authority_id"] = (
        f"report-toolchain-authority:linux-x64:{authority_fingerprint[:24]}"
    )
    authority_identity["authority_fingerprint"] = authority_fingerprint
    _write_canonical_json(
        output / "linux-x64-report-toolchain-authority-candidate.json",
        authority_identity,
    )

    summary = {
        "status": provenance["release_evidence_status"],
        "platform_target": "linux-x64",
        "renderer": runtime_components["renderer"],
        "offline_bundle": runtime_components["offline_bundle"],
        "pdf_text_backend": runtime_components["pdf_text_backend"],
        "pdf_render_backend": runtime_components["pdf_render_backend"],
        "qa": qa,
        "evidence_path": str(provenance_path),
        "authority_candidate_path": str(
            output / "linux-x64-report-toolchain-authority-candidate.json"
        ),
    }
    print(json.dumps(summary, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(_main())
    except BootstrapError as exc:
        print(f"bootstrap failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
