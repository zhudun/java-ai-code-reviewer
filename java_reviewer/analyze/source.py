from __future__ import annotations

import re
from dataclasses import dataclass, field


_IDENT = r"[A-Za-z_$][A-Za-z0-9_$]*"
_TYPE = r"(?:[\w.<>,?\[\] $]+?)"
_MODIFIERS = {
    "public",
    "protected",
    "private",
    "static",
    "final",
    "abstract",
    "synchronized",
    "native",
    "strictfp",
    "default",
    "transient",
    "volatile",
    "sealed",
    "non-sealed",
}


@dataclass
class JavaField:
    name: str
    type: str
    modifiers: set[str]
    annotations: list[str]
    line: int
    initializer: str = ""


@dataclass
class JavaMethod:
    name: str
    return_type: str
    modifiers: set[str]
    annotations: list[str]
    parameters: list[tuple[str, str]]
    start_line: int
    end_line: int
    signature_line: int
    body: str
    raw: str

    @property
    def is_public(self) -> bool:
        return "public" in self.modifiers

    @property
    def is_private(self) -> bool:
        return "private" in self.modifiers

    @property
    def is_static(self) -> bool:
        return "static" in self.modifiers

    def has_annotation(self, name: str) -> bool:
        needle = name.lstrip("@")
        return any(_annotation_name(item) == needle for item in self.annotations)

    def annotation_text(self, name: str) -> str | None:
        needle = name.lstrip("@")
        for item in self.annotations:
            if _annotation_name(item) == needle:
                return item
        return None


@dataclass
class JavaClass:
    name: str
    kind: str
    package: str
    annotations: list[str]
    modifiers: set[str]
    start_line: int
    end_line: int
    fields: list[JavaField] = field(default_factory=list)
    methods: list[JavaMethod] = field(default_factory=list)
    raw: str = ""

    def has_annotation(self, name: str) -> bool:
        needle = name.lstrip("@")
        return any(_annotation_name(item) == needle for item in self.annotations)

    def is_spring_singleton(self) -> bool:
        markers = {
            "Service",
            "Component",
            "Controller",
            "RestController",
            "Repository",
            "Configuration",
        }
        return any(self.has_annotation(item) for item in markers)


@dataclass
class JavaCompilationUnit:
    path: str
    package: str
    imports: list[str]
    source: str
    clean: str
    lines: list[str]
    clean_lines: list[str]
    classes: list[JavaClass]

    def line_text(self, line: int) -> str:
        if 1 <= line <= len(self.lines):
            return self.lines[line - 1].rstrip("\n")
        return ""

    def snippet(self, line: int, radius: int = 2) -> str:
        start = max(1, line - radius)
        end = min(len(self.lines), line + radius)
        chunk = []
        for idx in range(start, end + 1):
            prefix = ">" if idx == line else " "
            chunk.append(f"{prefix} {idx:>4} | {self.line_text(idx)}")
        return "\n".join(chunk)


def parse_java(path: str, source: str) -> JavaCompilationUnit:
    clean = strip_comments_preserve_lines(source)
    package = _first_match(r"package\s+([\w.]+)\s*;", clean) or ""
    imports = re.findall(r"import\s+(?:static\s+)?([\w.*]+)\s*;", clean)
    classes = _parse_types(clean, package)
    return JavaCompilationUnit(
        path=path,
        package=package,
        imports=imports,
        source=source,
        clean=clean,
        lines=source.splitlines(),
        clean_lines=clean.splitlines(),
        classes=classes,
    )


def strip_comments_preserve_lines(source: str) -> str:
    out: list[str] = []
    i = 0
    n = len(source)
    in_block = False
    in_line = False
    in_string = False
    in_char = False
    escape = False
    while i < n:
        ch = source[i]
        nxt = source[i + 1] if i + 1 < n else ""
        if in_line:
            if ch == "\n":
                in_line = False
                out.append(ch)
            else:
                out.append(" ")
            i += 1
            continue
        if in_block:
            if ch == "\n":
                out.append(ch)
            elif ch == "*" and nxt == "/":
                out.extend([" ", " "])
                i += 2
                in_block = False
                continue
            else:
                out.append(" ")
            i += 1
            continue
        if in_string:
            out.append(ch)
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            i += 1
            continue
        if in_char:
            out.append(ch)
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == "'":
                in_char = False
            i += 1
            continue
        if ch == "/" and nxt == "/":
            in_line = True
            out.extend([" ", " "])
            i += 2
            continue
        if ch == "/" and nxt == "*":
            in_block = True
            out.extend([" ", " "])
            i += 2
            continue
        if ch == '"':
            in_string = True
            out.append(ch)
            i += 1
            continue
        if ch == "'":
            in_char = True
            out.append(ch)
            i += 1
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _parse_types(clean: str, package: str) -> list[JavaClass]:
    type_re = re.compile(
        rf"(?P<mods>(?:\b(?:public|protected|private|static|final|abstract|sealed|non-sealed)\b\s+)*)"
        rf"(?P<kind>class|interface|enum|record)\s+(?P<name>{_IDENT})"
    )
    classes: list[JavaClass] = []
    for match in type_re.finditer(clean):
        name = match.group("name")
        kind = match.group("kind")
        mods = set(re.findall(r"\b\w+\b", match.group("mods") or ""))
        start = match.start()
        brace = clean.find("{", match.end())
        if brace < 0:
            continue
        end = _matching_brace(clean, brace)
        if end < 0:
            continue
        header = clean[max(0, start - 400) : match.start()]
        annotations = _trailing_annotations(header)
        body = clean[brace + 1 : end]
        start_line = clean.count("\n", 0, start) + 1
        end_line = clean.count("\n", 0, end) + 1
        item = JavaClass(
            name=name,
            kind=kind,
            package=package,
            annotations=annotations,
            modifiers=mods,
            start_line=start_line,
            end_line=end_line,
            raw=clean[start:end + 1],
        )
        item.fields = _parse_fields(body, start_line)
        item.methods = _parse_methods(body, start_line)
        classes.append(item)
    return classes


def _parse_fields(body: str, body_start_line: int) -> list[JavaField]:
    fields: list[JavaField] = []
    depth = 0
    i = 0
    n = len(body)
    stmt_start = 0
    while i < n:
        ch = body[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
        elif ch == ";" and depth == 0:
            stmt = body[stmt_start : i + 1]
            parsed = _field_from_statement(stmt, body, stmt_start, body_start_line)
            if parsed:
                fields.append(parsed)
            stmt_start = i + 1
        elif ch == "{" and depth == 0:
            stmt_start = i + 1
        i += 1
        if ch == "{" and depth == 1:
            # skip method / initializer body
            close = _matching_brace(body, i - 1)
            if close < 0:
                break
            i = close + 1
            depth = 0
            stmt_start = i
    return fields


def _field_from_statement(
    stmt: str, body: str, offset: int, body_start_line: int
) -> JavaField | None:
    text = " ".join(stmt.split())
    if not text or text.startswith("return ") or text.startswith("throw "):
        return None
    if "(" in text and not re.search(r"=\s*new\s+", text):
        # likely a method forward decl / annotation leftover
        if re.search(rf"\b{_IDENT}\s*\(", text):
            return None
    match = re.search(
        rf"(?P<mods>(?:\b(?:public|protected|private|static|final|volatile|transient)\b\s+)*)"
        rf"(?P<type>{_TYPE})\s+(?P<name>{_IDENT})\s*(?:=\s*(?P<init>[^;]+))?;",
        text,
    )
    if not match:
        return None
    modifiers = set(re.findall(r"\b\w+\b", match.group("mods") or ""))
    type_name, extra_mods = _split_mods(" ".join(match.group("type").split()))
    modifiers.update(extra_mods)
    if not type_name or type_name in _MODIFIERS or type_name in {"class", "interface", "enum", "return", "if", "for"}:
        return None
    header = body[max(0, offset - 300) : offset]
    annotations = _trailing_annotations(header)
    name_at = stmt.find(match.group("name"))
    line = body_start_line + body.count("\n", 0, offset + max(0, name_at))
    return JavaField(
        name=match.group("name"),
        type=type_name,
        modifiers=modifiers,
        annotations=annotations,
        line=line,
        initializer=(match.group("init") or "").strip(),
    )


def _parse_methods(body: str, body_start_line: int) -> list[JavaMethod]:
    methods: list[JavaMethod] = []
    method_re = re.compile(
        rf"(?P<mods>(?:\b(?:public|protected|private|static|final|abstract|synchronized|native|default)\b\s+)*)"
        rf"(?P<ret>{_TYPE})\s+(?P<name>{_IDENT})\s*\((?P<params>[^;{{}}]*)\)\s*(?:throws\s+[^{{;]+)?\s*\{{",
        re.S,
    )
    for match in method_re.finditer(body):
        brace = match.end() - 1
        end = _matching_brace(body, brace)
        if end < 0:
            continue
        name = match.group("name")
        if name in {"if", "for", "while", "switch", "catch"}:
            continue
        header = body[max(0, match.start() - 400) : match.start()]
        annotations = _trailing_annotations(header)
        start_line = body_start_line + body.count("\n", 0, match.start())
        signature_line = body_start_line + body.count("\n", 0, match.start(0))
        # prefer the line of the method name
        name_pos = match.start("name")
        signature_line = body_start_line + body.count("\n", 0, name_pos)
        end_line = body_start_line + body.count("\n", 0, end)
        return_type, extra_mods = _split_mods(" ".join(match.group("ret").split()))
        modifiers = set(re.findall(r"\b\w+\b", match.group("mods") or ""))
        modifiers.update(extra_mods)
        methods.append(
            JavaMethod(
                name=name,
                return_type=return_type or "void",
                modifiers=modifiers,
                annotations=annotations,
                parameters=_parse_params(match.group("params")),
                start_line=start_line,
                end_line=end_line,
                signature_line=signature_line,
                body=body[brace + 1 : end],
                raw=body[match.start() : end + 1],
            )
        )
    return methods


def _parse_params(raw: str) -> list[tuple[str, str]]:
    items: list[tuple[str, str]] = []
    if not raw.strip():
        return items
    for part in _split_args(raw):
        part = re.sub(r"@\w+(?:\([^)]*\))?\s*", "", part).strip()
        part = part.replace("final ", "").strip()
        if not part:
            continue
        tokens = part.split()
        if len(tokens) >= 2:
            items.append((tokens[-1].replace("...", ""), " ".join(tokens[:-1])))
    return items


def _split_args(raw: str) -> list[str]:
    parts: list[str] = []
    buf: list[str] = []
    depth = 0
    for ch in raw:
        if ch in "<([":
            depth += 1
        elif ch in ">)]":
            depth = max(0, depth - 1)
        if ch == "," and depth == 0:
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    if buf:
        parts.append("".join(buf))
    return parts


def _split_mods(type_name: str) -> tuple[str, set[str]]:
    parts = type_name.split()
    mods: set[str] = set()
    while parts and parts[0] in _MODIFIERS:
        mods.add(parts.pop(0))
    return " ".join(parts), mods


def _trailing_annotations(header: str) -> list[str]:
    cut = max(header.rfind(";"), header.rfind("}"))
    header = header[cut + 1 :] if cut >= 0 else header
    found = list(re.finditer(r"@[\w.]+(?:\s*\([^;@]*\))?", header, re.S))
    if not found:
        return []
    return [re.sub(r"\s+", " ", match.group(0)).strip() for match in found]


def _annotation_name(annotation: str) -> str:
    match = re.match(r"@?([\w.]+)", annotation.strip())
    if not match:
        return annotation
    return match.group(1).split(".")[-1]


def _matching_brace(text: str, open_index: int) -> int:
    depth = 0
    i = open_index
    n = len(text)
    in_string = False
    in_char = False
    escape = False
    while i < n:
        ch = text[i]
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            i += 1
            continue
        if in_char:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == "'":
                in_char = False
            i += 1
            continue
        if ch == '"':
            in_string = True
        elif ch == "'":
            in_char = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def _first_match(pattern: str, text: str) -> str | None:
    match = re.search(pattern, text)
    return match.group(1) if match else None
