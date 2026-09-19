from __future__ import annotations

from dataclasses import dataclass


@dataclass
class XmlDocument:
    path: str
    text: str
    lines: list[str]


def parse_xml_text(path: str, text: str) -> XmlDocument:
    return XmlDocument(path=path, text=text, lines=text.splitlines())
