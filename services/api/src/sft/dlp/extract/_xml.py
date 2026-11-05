"""XML for Office and OpenDocument parts: streamed, with DTDs, entities and the network off.

Office Open XML and OpenDocument parts never carry a document type declaration, so a part that has
one is refused outright (`parse_error`) rather than parsed with its entities: that is the XML
entity bomb (T-93). Entities are never resolved, no external resource is ever loaded, and
libxml2's own size and depth limits stay on (no `huge_tree`).
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from typing import Any

from lxml import etree

from sft.dlp.extract._core import Readable

# Namespaces whose paragraph and text elements Office and OpenDocument use.
W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
A = "http://schemas.openxmlformats.org/drawingml/2006/main"
ODF_TEXT = "urn:oasis:names:tc:opendocument:xmlns:text:1.0"
ODF_TABLE = "urn:oasis:names:tc:opendocument:xmlns:table:1.0"
ODF_OFFICE = "urn:oasis:names:tc:opendocument:xmlns:office:1.0"
ODF_DRAW = "urn:oasis:names:tc:opendocument:xmlns:drawing:1.0"
ODF_PRESENTATION = "urn:oasis:names:tc:opendocument:xmlns:presentation:1.0"
ODF_STYLE = "urn:oasis:names:tc:opendocument:xmlns:style:1.0"

Element = Any  # lxml has no type stubs in this project; elements are handled through these helpers


class XmlRefused(Exception):  # noqa: N818
    """The part declares a DTD: refused, never parsed with it."""


def iterparse(source: Readable, tags: Iterable[str] | None = None) -> Iterator[Element]:
    """Each element named in `tags` (all if None) as it ends, in document order."""
    events = etree.iterparse(
        source,
        events=("end",),
        tag=list(tags) if tags is not None else None,
        resolve_entities=False,
        no_network=True,
        load_dtd=False,
        dtd_validation=False,
        huge_tree=False,
        remove_comments=True,
        remove_pis=True,
    )
    checked = False
    for _event, element in events:
        if not checked:
            if element.getroottree().docinfo.doctype:
                raise XmlRefused("DTD")
            checked = True
        yield element


def local(element: Element) -> str:
    """The element's name without its namespace; "" for an entity reference or other node."""
    tag = element.tag
    return tag.rpartition("}")[2] if isinstance(tag, str) else ""


def release(element: Element) -> None:
    """Free an element that has been read, and the siblings before it, to keep memory flat."""
    element.clear(keep_tail=True)
    parent = element.getparent()
    if parent is not None:
        while element.getprevious() is not None:
            del parent[0]


def nested_in(element: Element, *tags: str) -> bool:
    return next(element.iterancestors(*tags), None) is not None


def ooxml_text(element: Element, *, skip: frozenset[str] = frozenset({"p", "rPh"})) -> str:
    """A WordprocessingML or DrawingML paragraph's text: its runs' text, tabs and breaks.

    Only text elements carry text in Office Open XML; whitespace between elements is layout.
    Nested paragraphs (text boxes) are their own units, so they are skipped here.
    """
    out: list[str] = []

    def walk(node: Element) -> None:
        for child in node:
            name = local(child)
            if name in skip:
                continue
            if name in ("t", "delText"):
                out.append(child.text or "")
            elif name == "tab":
                out.append("\t")
            elif name in ("br", "cr"):
                out.append("\n")
            else:
                walk(child)

    walk(element)
    return "".join(out)


def odf_text(element: Element) -> str:
    """An OpenDocument paragraph's mixed content, with its spaces, tabs and line breaks.

    Nested paragraphs (notes, annotations, frames) are their own units, so only their tail counts.
    """
    out: list[str] = []

    def walk(node: Element) -> None:
        if node.text:
            out.append(node.text)
        for child in node:
            name = local(child)
            if name in ("p", "h"):
                pass
            elif name == "s":
                count = child.get(f"{{{ODF_TEXT}}}c") or "1"
                out.append(" " * min(int(count) if count.isdigit() else 1, 100))
            elif name == "tab":
                out.append("\t")
            elif name == "line-break":
                out.append("\n")
            else:
                walk(child)
            if child.tail:
                out.append(child.tail)

    walk(element)
    return "".join(out)


def leaf_texts(source: Readable) -> Iterator[str]:
    """The text of every element that has no children: document properties, chart labels."""
    for element in iterparse(source):
        if len(element) == 0 and element.text and element.text.strip():
            yield element.text
        release(element)
