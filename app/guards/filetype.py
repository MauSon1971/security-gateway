"""Detección PROPIA por tipo de fichero (861) — independiente de ClamAV.

ClamAV con `OLE2BlockMacros yes` ya marca `Heuristics.OLE2.ContainsMacros`, pero
sólo para OLE2 y sólo si alguien no le toca la configuración. Esto es la segunda
llave, y mira lo que el antivirus no considera «malware» pero el SOP #856 manda a
cuarentena:

    macro       docm/xlsm/pptm…, `vbaProject.bin` dentro de un OOXML (aunque se
                llame .docx), `_VBA_PROJECT` en un OLE2 (.doc/.xls/.ppt)
    ejecutable  por extensión (exe, scr, js, ps1, lnk, jar…) o por firma mágica
                (PE «MZ», ELF, Mach-O, «#!»), también DENTRO de un zip
    cifrado     zip con entradas cifradas, OOXML protegido con contraseña
                (`EncryptedPackage`), PDF con `/Encrypt`
    no_inspeccionable  rar/7z (no se puede saber si llevan contraseña ni qué
                llevan), zip corrupto o que excede los topes de inspección

Todo hallazgo es DUDA → cuarentena. No hay «probablemente bien».
"""
from __future__ import annotations

import io
import re
import subprocess
import zipfile
from dataclasses import dataclass
from pathlib import PurePosixPath

MACRO_EXT = {".docm", ".dotm", ".xlsm", ".xltm", ".xlam", ".xlsb", ".pptm", ".potm",
             ".ppsm", ".ppam", ".sldm"}
EXEC_EXT = {".exe", ".dll", ".scr", ".com", ".pif", ".cpl", ".msi", ".msp", ".msc",
            ".bat", ".cmd", ".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse", ".wsf",
            ".wsh", ".hta", ".jar", ".lnk", ".reg", ".sh", ".apk", ".app", ".dmg",
            ".iso", ".img", ".vhd", ".vhdx", ".appx", ".msix", ".application", ".gadget",
            ".inf", ".scf", ".url", ".chm", ".xll", ".elf", ".run", ".command"}
ZIP_EXT = {".zip", ".jar", ".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp", ".epub"}

OLE2_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
ZIP_MAGIC = b"PK\x03\x04"
RAR_MAGIC = b"Rar!\x1a\x07"
SEVENZ_MAGIC = b"7z\xbc\xaf\x27\x1c"
EXEC_MAGIC = {
    b"MZ": "pe",
    b"\x7fELF": "elf",
    b"\xcf\xfa\xed\xfe": "macho",
    b"\xce\xfa\xed\xfe": "macho",
    b"\xfe\xed\xfa\xcf": "macho",
    b"\xca\xfe\xba\xbe": "macho_fat",
}

def _u16(s: str) -> bytes:
    return s.encode("utf-16-le")


OLE_VBA = (_u16("_VBA_PROJECT"), _u16("VBA"), _u16("Macros"))
OLE_ENCRYPTED = (_u16("EncryptedPackage"), _u16("EncryptionInfo"))

MAX_DEPTH = 2
MAX_ENTRIES = 5_000
MAX_INNER_READ = 10 * 1024 * 1024     # un zip dentro de un zip, como mucho 10 MiB
MAX_TOTAL_READ = 50 * 1024 * 1024     # tope anti-bomba para todo lo que se descomprime


@dataclass(frozen=True)
class Hallazgo:
    categoria: str    # macro | ejecutable | cifrado | no_inspeccionable
    detalle: str

    def as_dict(self) -> dict:
        return {"categoria": self.categoria, "detalle": self.detalle}


def _ext(name: str) -> str:
    return PurePosixPath(name.replace("\\", "/")).suffix.lower()


def _magic_exec(data: bytes) -> str | None:
    for m, kind in EXEC_MAGIC.items():
        if data.startswith(m):
            # «MZ» sólo cuenta si hay cabecera PE de verdad o el fichero es pequeño
            if m == b"MZ" and len(data) >= 0x40:
                off = int.from_bytes(data[0x3C:0x40], "little")
                if not (0 < off < len(data) - 4 and data[off:off + 4] == b"PE\0\0"):
                    continue
            return kind
    if data.startswith(b"#!"):
        return "script"
    return None


def inspeccionar(data: bytes, filename: str, _depth: int = 0, _budget: list | None = None) -> list[Hallazgo]:
    """Hallazgos por tipo. Lista vacía = nada que objetar por tipo."""
    budget = _budget if _budget is not None else [MAX_TOTAL_READ]
    out: list[Hallazgo] = []
    name = filename or "upload"
    ext = _ext(name)
    where = "" if _depth == 0 else f"{name}:"

    if ext in MACRO_EXT:
        out.append(Hallazgo("macro", f"{where}extension{ext}"))
    if ext in EXEC_EXT:
        out.append(Hallazgo("ejecutable", f"{where}extension{ext}"))
    kind = _magic_exec(data)
    if kind:
        out.append(Hallazgo("ejecutable", f"{where}firma:{kind}"))

    if data.startswith(RAR_MAGIC):
        out.append(Hallazgo("no_inspeccionable", f"{where}rar"))
    elif data.startswith(SEVENZ_MAGIC):
        out.append(Hallazgo("no_inspeccionable", f"{where}7z"))
    elif data.startswith(OLE2_MAGIC):
        if any(m in data for m in OLE_ENCRYPTED):
            out.append(Hallazgo("cifrado", f"{where}office_con_contrasena"))
        if any(m in data for m in OLE_VBA[:1]) or (_u16("VBA") in data and _u16("PROJECT") in data):
            out.append(Hallazgo("macro", f"{where}ole2_vba"))
    elif data.startswith(b"%PDF"):
        if re.search(rb"/Encrypt\s*\d+\s+\d+\s+R|/Encrypt\s*<<", data):
            out.append(Hallazgo("cifrado", f"{where}pdf_cifrado"))
    elif data.startswith(ZIP_MAGIC) or ext in ZIP_EXT:
        out.extend(_inspeccionar_zip(data, name, _depth, budget))
    return out


def _inspeccionar_zip(data: bytes, name: str, depth: int, budget: list) -> list[Hallazgo]:
    out: list[Hallazgo] = []
    where = "" if depth == 0 else f"{name}:"
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
        infos = zf.infolist()
    except (zipfile.BadZipFile, ValueError, OSError):
        if data.startswith(ZIP_MAGIC):
            return [Hallazgo("no_inspeccionable", f"{where}zip_corrupto")]
        return out
    if len(infos) > MAX_ENTRIES:
        return [Hallazgo("no_inspeccionable", f"{where}zip_demasiadas_entradas:{len(infos)}")]
    for info in infos:
        inner = info.filename
        low = inner.lower()
        if info.flag_bits & 0x1:
            out.append(Hallazgo("cifrado", f"{where}zip_con_contrasena:{inner}"))
            continue
        if low.endswith("vbaproject.bin") or low.endswith("vbadata.xml"):
            out.append(Hallazgo("macro", f"{where}ooxml_vba:{inner}"))
        iext = _ext(inner)
        if iext in EXEC_EXT:
            out.append(Hallazgo("ejecutable", f"{where}dentro:{inner}"))
        if iext in MACRO_EXT:
            out.append(Hallazgo("macro", f"{where}dentro:{inner}"))
        nested = iext in ZIP_EXT | {".rar", ".7z"} or iext in {".doc", ".xls", ".ppt", ".pdf"}
        if nested and not info.is_dir():
            if depth + 1 > MAX_DEPTH:
                out.append(Hallazgo("no_inspeccionable", f"{where}anidado_demasiado:{inner}"))
                continue
            if info.file_size > MAX_INNER_READ or info.file_size > budget[0]:
                out.append(Hallazgo("no_inspeccionable", f"{where}anidado_grande:{inner}"))
                continue
            try:
                blob = zf.read(info)
            except Exception:  # noqa: BLE001
                out.append(Hallazgo("no_inspeccionable", f"{where}no_se_lee:{inner}"))
                continue
            budget[0] -= len(blob)
            out.extend(inspeccionar(blob, f"{where}{inner}", depth + 1, budget))
        elif not info.is_dir() and iext not in {".xml", ".rels", ".png", ".jpg", ".jpeg", ".gif", ".emf", ".wmf"}:
            # Ejecutable disfrazado con extensión inocente: se mira la firma mágica.
            if info.file_size and budget[0] > 0:
                try:
                    with zf.open(info) as fh:
                        head = fh.read(4096)
                    budget[0] -= len(head)
                    k = _magic_exec(head)
                    if k:
                        out.append(Hallazgo("ejecutable", f"{where}dentro_firma:{inner}:{k}"))
                except Exception:  # noqa: BLE001
                    pass
    return out


# ----------------------------------------------------------------------------
# Texto de un adjunto, para que el clasificador lo mire (#851 A: todo lo que entra)
# ----------------------------------------------------------------------------
TEXT_EXT = {".txt", ".csv", ".tsv", ".md", ".html", ".htm", ".xml", ".json", ".eml",
            ".ics", ".vcf", ".rtf", ".log", ".yaml", ".yml"}
_TAG = re.compile(rb"<[^>]{0,2000}>")


def extraer_texto(data: bytes, filename: str, pdftotext_bin: str = "pdftotext",
                  max_chars: int = 200_000, timeout_s: int = 20) -> tuple[str | None, str]:
    """→ (texto | None, método). None = no hay texto que se sepa sacar."""
    ext = _ext(filename or "")
    try:
        if data.startswith(b"%PDF"):
            proc = subprocess.run([pdftotext_bin, "-q", "-l", "200", "-enc", "UTF-8", "-", "-"],
                                  input=data, capture_output=True, timeout=timeout_s)
            if proc.returncode != 0:
                return None, f"pdftotext_rc={proc.returncode}"
            return proc.stdout.decode("utf-8", errors="replace")[:max_chars], "pdftotext"
        if data.startswith(ZIP_MAGIC):
            zf = zipfile.ZipFile(io.BytesIO(data))
            names = [n for n in zf.namelist()
                     if re.match(r"(word/document|word/header\d*|word/footer\d*|word/footnotes|word/comments"
                                 r"|xl/sharedStrings|ppt/slides/slide\d+|ppt/notesSlides/notesSlide\d+"
                                 r"|content)\.xml$", n)]
            if not names:
                return None, "zip_sin_texto"
            parts, total = [], 0
            for n in names:
                info = zf.getinfo(n)
                if info.flag_bits & 0x1:
                    continue
                raw = zf.read(n)[: max_chars * 4]
                txt = _TAG.sub(b" ", raw).decode("utf-8", errors="replace")
                txt = re.sub(r"\s+", " ", txt)
                parts.append(txt)
                total += len(txt)
                if total >= max_chars:
                    break
            return " ".join(parts)[:max_chars], "ooxml"
    except subprocess.TimeoutExpired:
        return None, "pdftotext_timeout"
    except FileNotFoundError:
        return None, "pdftotext_no_instalado"
    except (zipfile.BadZipFile, KeyError, ValueError, OSError) as e:
        return None, f"no_extraible:{type(e).__name__}"
    if ext in TEXT_EXT or (b"\0" not in data[:8192] and data[:4] != OLE2_MAGIC[:4]):
        try:
            return data.decode("utf-8")[:max_chars], "utf8"
        except UnicodeDecodeError:
            if ext in TEXT_EXT:
                return data.decode("latin-1")[:max_chars], "latin1"
    return None, "binario"
