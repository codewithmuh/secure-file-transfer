"""Fixtures for the DLP extraction tests, built in code when the tests run ([detectors] 8).

Nothing here is committed as a binary: each format is written from its specification's smallest
valid shape, so a reviewer can read what each fixture holds. The text in them is plain tokens such
as `TOKEN-0001`, never an identifier that passes a detector's check.
"""

from __future__ import annotations

import gzip as gzip_module
import io
import os
import tarfile
import zipfile
from collections.abc import Mapping, Sequence
from xml.sax.saxutils import escape

W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
A = "http://schemas.openxmlformats.org/drawingml/2006/main"
P = "http://schemas.openxmlformats.org/presentationml/2006/main"
S = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
R = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
PKG = "http://schemas.openxmlformats.org/package/2006/relationships"
CT = "http://schemas.openxmlformats.org/package/2006/content-types"
REL_DOC = f"{R}/officeDocument"
XML = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'


def zip_bytes(members: Mapping[str, bytes | str], *, stored: Sequence[str] = ()) -> bytes:
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in members.items():
            payload = data.encode() if isinstance(data, str) else data
            method = zipfile.ZIP_STORED if name in stored else zipfile.ZIP_DEFLATED
            zf.writestr(name, payload, compress_type=method)
    return out.getvalue()


def encrypt_flag(archive: bytes, name: str) -> bytes:
    """Set the "encrypted" flag on one member, as a password-protected zip has it.

    The data isn't really encrypted; the inspector must not read it either way.
    """
    raw = bytearray(archive)
    encoded = name.encode()
    for signature, flag_at, name_at in ((b"PK\x03\x04", 6, 30), (b"PK\x01\x02", 8, 46)):
        start = 0
        while (start := raw.find(signature, start)) != -1:
            if raw[start + name_at : start + name_at + len(encoded)] == encoded:
                raw[start + flag_at] |= 0x1
            start += 4
    return bytes(raw)


def cp932_names_zip(name: str, data: bytes) -> bytes:
    """A zip whose member name is CP932 without the UTF-8 flag, as Japanese archivers write it."""
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as zf:
        info = zipfile.ZipInfo("placeholder.txt")
        zf.writestr(info, data)
    raw = out.getvalue()
    old, new = b"placeholder.txt", name.encode("cp932")
    raw = raw.replace(old, new)
    # Fix the name lengths and the central directory's size and offset for the new name length.
    delta = len(new) - len(old)
    buf = bytearray(raw)
    buf[26:28] = len(new).to_bytes(2, "little")
    central = buf.find(b"PK\x01\x02")
    buf[central + 28 : central + 30] = len(new).to_bytes(2, "little")
    buf[central + 42 : central + 46] = (0).to_bytes(4, "little")
    end = buf.find(b"PK\x05\x06")
    size = int.from_bytes(buf[end + 12 : end + 16], "little") + delta
    buf[end + 12 : end + 16] = size.to_bytes(4, "little")
    offset = int.from_bytes(buf[end + 16 : end + 20], "little") + delta
    buf[end + 16 : end + 20] = offset.to_bytes(4, "little")
    return bytes(buf)


def gzip_bytes(data: bytes) -> bytes:
    return gzip_module.compress(data, mtime=0)


def tar_bytes(members: Mapping[str, bytes], *, symlink: str | None = None) -> bytes:
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w", format=tarfile.PAX_FORMAT) as tf:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
        if symlink:
            link = tarfile.TarInfo(symlink)
            link.type = tarfile.SYMTYPE
            link.linkname = "/etc/passwd"
            tf.addfile(link)
    return out.getvalue()


def nested_zip(depth: int, text: bytes) -> bytes:
    """`depth` zips, each inside the one before, with a text file in the innermost."""
    data = zip_bytes({"inner.txt": text})
    for level in range(depth - 1):
        data = zip_bytes({f"level{depth - level - 1}.zip": data})
    return data


def ratio_bomb(size: int) -> bytes:
    """One member of `size` zero bytes: deflate packs it about 1,000 to 1."""
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf, zf.open("zeros.txt", "w") as member:
        chunk = b"\0" * (1024 * 1024)
        left = size
        while left > 0:
            member.write(chunk[: min(left, len(chunk))])
            left -= len(chunk)
    return out.getvalue()


def many_members(count: int) -> bytes:
    return zip_bytes({f"m{i:05}.txt": f"TOKEN-{i:04}" for i in range(count)})


def cfb(*, encrypted: bool) -> bytes:
    """An OLE compound file header with a directory entry name: enough for the sniffing."""
    header = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\0" * 504
    name = ("EncryptedPackage" if encrypted else "WordDocument").encode("utf-16-le")
    return header + name + b"\0" * (512 - len(name))


# ---- Office Open XML ----


def _content_types(overrides: Mapping[str, str]) -> str:
    rows = "".join(
        f'<Override PartName="/{name}" ContentType="{kind}"/>' for name, kind in overrides.items()
    )
    return (
        f'{XML}<Types xmlns="{CT}"><Default Extension="rels" '
        'ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        f'<Default Extension="xml" ContentType="application/xml"/>{rows}</Types>'
    )


def _rels(targets: Sequence[tuple[str, str, str]]) -> str:
    rows = "".join(
        f'<Relationship Id="{rid}" Type="{kind}" Target="{target}"/>'
        for rid, kind, target in targets
    )
    return f'{XML}<Relationships xmlns="{PKG}">{rows}</Relationships>'


def _core(title: str) -> str:
    return (
        f'{XML}<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/'
        'metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/">'
        f"<dc:title>{escape(title)}</dc:title><dc:creator>Test Author</dc:creator>"
        "</cp:coreProperties>"
    )


def _w_p(text: str) -> str:
    return f'<w:p><w:r><w:t xml:space="preserve">{escape(text)}</w:t></w:r></w:p>'


def docx(
    paragraphs: Sequence[str],
    *,
    header: str | None = None,
    footer: str | None = None,
    comment: str | None = None,
    textbox: str | None = None,
    title: str = "",
    embedded: Mapping[str, bytes] | None = None,
    macro: bool = False,
    doctype: str = "",
    raw: str = "",
) -> bytes:
    """A Word document. `doctype` and `raw` go into the main part unescaped, for the bombs."""
    body = "".join(_w_p(text) for text in paragraphs) + raw
    if textbox is not None:
        body += (
            '<w:p><w:r><w:t>before box</w:t></w:r><w:r><w:pict><v:shape xmlns:v="urn:schemas-'
            f'microsoft-com:vml"><v:textbox><w:txbxContent>{_w_p(textbox)}</w:txbxContent>'
            "</v:textbox></v:shape></w:pict></w:r><w:r><w:t> after box</w:t></w:r></w:p>"
        )
    main = (
        "application/vnd.ms-word.document.macroEnabled.main+xml"
        if macro
        else "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"
    )
    members: dict[str, bytes | str] = {
        "[Content_Types].xml": _content_types({"word/document.xml": main}),
        "_rels/.rels": _rels([("rId1", REL_DOC, "word/document.xml")]),
        "word/document.xml": f'{XML}{doctype}<w:document xmlns:w="{W}"><w:body>{body}'
        "</w:body></w:document>",
        "docProps/core.xml": _core(title),
        "word/styles.xml": f'{XML}<w:styles xmlns:w="{W}"><w:style><w:name w:val="STYLE-NOISE"/>'
        "</w:style></w:styles>",
        "word/media/image1.png": b"\x89PNG\r\n\x1a\n" + b"\0" * 32,
    }
    if header is not None:
        members["word/header1.xml"] = f'{XML}<w:hdr xmlns:w="{W}">{_w_p(header)}</w:hdr>'
    if footer is not None:
        members["word/footer1.xml"] = f'{XML}<w:ftr xmlns:w="{W}">{_w_p(footer)}</w:ftr>'
    if comment is not None:
        members["word/comments.xml"] = (
            f'{XML}<w:comments xmlns:w="{W}"><w:comment w:id="0">{_w_p(comment)}'
            "</w:comment></w:comments>"
        )
    for name, data in (embedded or {}).items():
        members[f"word/embeddings/{name}"] = data
    return zip_bytes(members)


def xlsx(
    sheets: Mapping[str, Sequence[Sequence[str | int]]],
    *,
    comment: str | None = None,
    title: str = "",
    inline: bool = False,
) -> bytes:
    shared: list[str] = []
    members: dict[str, bytes | str] = {}
    sheet_entries, rels = [], []
    for index, (name, rows) in enumerate(sheets.items(), start=1):
        sheet_entries.append(f'<sheet name="{escape(name)}" sheetId="{index}" r:id="rId{index}"/>')
        rels.append((f"rId{index}", f"{R}/worksheet", f"worksheets/sheet{index}.xml"))
        xml_rows = []
        for row_number, row in enumerate(rows, start=1):
            cells = []
            for column, value in enumerate(row):
                ref = f"{chr(65 + column)}{row_number}"
                if isinstance(value, int):
                    cells.append(f'<c r="{ref}"><v>{value}</v></c>')
                elif inline:
                    cells.append(f'<c r="{ref}" t="inlineStr"><is><t>{escape(value)}</t></is></c>')
                elif value:
                    shared.append(value)
                    cells.append(f'<c r="{ref}" t="s"><v>{len(shared) - 1}</v></c>')
            xml_rows.append(f'<row r="{row_number}">{"".join(cells)}</row>')
        members[f"xl/worksheets/sheet{index}.xml"] = (
            f'{XML}<worksheet xmlns="{S}"><sheetData>{"".join(xml_rows)}</sheetData></worksheet>'
        )
    rels.append(("rIdS", f"{R}/sharedStrings", "sharedStrings.xml"))
    strings = "".join(f"<si><t>{escape(text)}</t></si>" for text in shared)
    members["xl/sharedStrings.xml"] = f'{XML}<sst xmlns="{S}">{strings}</sst>'
    members["xl/workbook.xml"] = (
        f'{XML}<workbook xmlns="{S}" xmlns:r="{R}"><sheets>{"".join(sheet_entries)}</sheets>'
        "</workbook>"
    )
    members["xl/_rels/workbook.xml.rels"] = _rels(rels)
    if comment is not None:
        members["xl/comments1.xml"] = (
            f'{XML}<comments xmlns="{S}"><commentList><comment ref="A1"><text><r><t>'
            f"{escape(comment)}</t></r></text></comment></commentList></comments>"
        )
    main = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"
    members["[Content_Types].xml"] = _content_types({"xl/workbook.xml": main})
    members["_rels/.rels"] = _rels([("rId1", REL_DOC, "xl/workbook.xml")])
    members["docProps/core.xml"] = _core(title)
    return zip_bytes(members)


def pptx(slides: Sequence[Sequence[str]], *, notes: Mapping[int, str] | None = None) -> bytes:
    members: dict[str, bytes | str] = {}
    ids, rels = [], []
    for number, texts in enumerate(slides, start=1):
        ids.append(f'<p:sldId id="{255 + number}" r:id="rId{number}"/>')
        rels.append((f"rId{number}", f"{R}/slide", f"slides/slide{number}.xml"))
        paragraphs = "".join(f"<a:p><a:r><a:t>{escape(text)}</a:t></a:r></a:p>" for text in texts)
        members[f"ppt/slides/slide{number}.xml"] = (
            f'{XML}<p:sld xmlns:p="{P}" xmlns:a="{A}"><p:cSld><p:spTree><p:sp><p:txBody>'
            f"{paragraphs}</p:txBody></p:sp></p:spTree></p:cSld></p:sld>"
        )
        note = (notes or {}).get(number)
        if note is not None:
            members[f"ppt/slides/_rels/slide{number}.xml.rels"] = _rels(
                [("rId9", f"{R}/notesSlide", f"../notesSlides/notesSlide{number}.xml")]
            )
            members[f"ppt/notesSlides/notesSlide{number}.xml"] = (
                f'{XML}<p:notes xmlns:p="{P}" xmlns:a="{A}"><p:cSld><p:spTree><p:sp><p:txBody>'
                f"<a:p><a:r><a:t>{escape(note)}</a:t></a:r></a:p></p:txBody></p:sp></p:spTree>"
                "</p:cSld></p:notes>"
            )
    members["ppt/presentation.xml"] = (
        f'{XML}<p:presentation xmlns:p="{P}" xmlns:r="{R}"><p:sldIdLst>{"".join(ids)}'
        "</p:sldIdLst></p:presentation>"
    )
    members["ppt/_rels/presentation.xml.rels"] = _rels(rels)
    main = "application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"
    members["[Content_Types].xml"] = _content_types({"ppt/presentation.xml": main})
    members["_rels/.rels"] = _rels([("rId1", REL_DOC, "ppt/presentation.xml")])
    members["ppt/slideLayouts/slideLayout1.xml"] = (
        f'{XML}<p:sldLayout xmlns:p="{P}" xmlns:a="{A}"><a:p><a:r><a:t>LAYOUT-NOISE</a:t></a:r>'
        "</a:p></p:sldLayout>"
    )
    return zip_bytes(members)


# ---- OpenDocument ----

_ODF_NS = (
    'xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" '
    'xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0" '
    'xmlns:table="urn:oasis:names:tc:opendocument:xmlns:table:1.0" '
    'xmlns:draw="urn:oasis:names:tc:opendocument:xmlns:drawing:1.0" '
    'xmlns:presentation="urn:oasis:names:tc:opendocument:xmlns:presentation:1.0" '
    'xmlns:style="urn:oasis:names:tc:opendocument:xmlns:style:1.0" '
    'xmlns:meta="urn:oasis:names:tc:opendocument:xmlns:meta:1.0" '
    'xmlns:dc="http://purl.org/dc/elements/1.1/"'
)


def _odf(kind: str, body: str, *, footer: str | None = None, encrypted: bool = False) -> bytes:
    styles = ""
    if footer is not None:
        styles = (
            "<office:master-styles><style:master-page><style:footer>"
            f"<text:p>{escape(footer)}</text:p></style:footer></style:master-page>"
            "</office:master-styles>"
        )
    manifest = (
        f'{XML}<manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:'
        'manifest:1.0"><manifest:file-entry manifest:full-path="content.xml">'
        + ("<manifest:encryption-data/>" if encrypted else "")
        + "</manifest:file-entry></manifest:manifest>"
    )
    return zip_bytes(
        {
            "mimetype": f"application/vnd.oasis.opendocument.{kind}",
            "content.xml": f"{XML}<office:document-content {_ODF_NS}><office:body>{body}"
            "</office:body></office:document-content>",
            "styles.xml": f"{XML}<office:document-styles {_ODF_NS}>{styles}"
            "</office:document-styles>",
            "meta.xml": f"{XML}<office:document-meta {_ODF_NS}><office:meta><dc:title>ODF-TITLE"
            "</dc:title></office:meta></office:document-meta>",
            "META-INF/manifest.xml": manifest,
        },
        stored=["mimetype"],
    )


def odt(paragraphs: Sequence[str], *, footer: str | None = None, encrypted: bool = False) -> bytes:
    body = "".join(
        f'<text:p>{escape(text)}<text:s text:c="2"/>tail<text:span>span</text:span></text:p>'
        for text in paragraphs
    )
    return _odf("text", f"<office:text>{body}</office:text>", footer=footer, encrypted=encrypted)


def ods(sheets: Mapping[str, Sequence[Sequence[str | int]]]) -> bytes:
    tables = []
    for name, rows in sheets.items():
        xml_rows = []
        for row in rows:
            cells = []
            for value in row:
                if isinstance(value, int):
                    cells.append(
                        f'<table:table-cell office:value-type="float" office:value="{value}">'
                        f"<text:p>{value:.2E}</text:p></table:table-cell>"
                    )
                elif value:
                    cells.append(
                        f"<table:table-cell><text:p>{escape(value)}</text:p></table:table-cell>"
                    )
                else:
                    cells.append('<table:table-cell table:number-columns-repeated="3"/>')
            xml_rows.append(f"<table:table-row>{''.join(cells)}</table:table-row>")
        xml_rows.append(
            '<table:table-row table:number-rows-repeated="1048000">'
            "<table:table-cell/></table:table-row>"
        )
        tables.append(f'<table:table table:name="{escape(name)}">{"".join(xml_rows)}</table:table>')
    return _odf("spreadsheet", f"<office:spreadsheet>{''.join(tables)}</office:spreadsheet>")


def odp(slides: Sequence[str], *, notes: str | None = None) -> bytes:
    pages = []
    for index, text in enumerate(slides):
        note = ""
        if notes is not None and index == 0:
            note = (
                "<presentation:notes><draw:frame><draw:text-box>"
                f"<text:p>{escape(notes)}</text:p>"
                "</draw:text-box></draw:frame></presentation:notes>"
            )
        pages.append(
            f'<draw:page draw:name="p{index}"><draw:frame><draw:text-box><text:p>{escape(text)}'
            f"</text:p></draw:text-box></draw:frame>{note}</draw:page>"
        )
    return _odf("presentation", f"<office:presentation>{''.join(pages)}</office:presentation>")


# ---- PDF ----


def _pdf_string(text: str) -> bytes:
    return (
        b"("
        + text.encode("latin-1").replace(b"\\", b"\\\\").replace(b"(", b"\\(").replace(b")", b"\\)")
        + b")"
    )


def pdf(pages: Sequence[str | None], *, image: bool = False, encrypted: bool = False) -> bytes:
    """A PDF with one page per entry: text in Helvetica, or None for a page without text.

    With `image`, a page without text shows a 1-by-1 image, as a scan does; without, it is blank.
    With `encrypted`, the document has a standard security handler whose user password isn't
    empty, so it can't be opened without one.
    """
    objects: list[bytes] = []

    def add(body: bytes) -> int:
        objects.append(body)
        return len(objects)

    catalog = add(b"")
    pages_obj = add(b"")
    font = add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    picture = add(
        b"<< /Type /XObject /Subtype /Image /Width 1 /Height 1 /ColorSpace /DeviceGray "
        b"/BitsPerComponent 8 /Length 1 >>\nstream\n\x80\nendstream"
    )
    kids = []
    for text in pages:
        if text is not None:
            stream = b"BT /F1 12 Tf 72 720 Td " + _pdf_string(text) + b" Tj ET"
        elif image:
            stream = b"q 100 0 0 100 72 600 cm /Im1 Do Q"
        else:
            stream = b""
        content = add(b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream")
        page = add(
            b"<< /Type /Page /Parent %d 0 R /MediaBox [0 0 612 792] /Contents %d 0 R "
            b"/Resources << /Font << /F1 %d 0 R >> /XObject << /Im1 %d 0 R >> >> >>"
            % (pages_obj, content, font, picture)
        )
        kids.append(b"%d 0 R" % page)
    objects[catalog - 1] = b"<< /Type /Catalog /Pages %d 0 R >>" % pages_obj
    objects[pages_obj - 1] = b"<< /Type /Pages /Kids [%s] /Count %d >>" % (
        b" ".join(kids),
        len(kids),
    )
    trailer_extra = b""
    if encrypted:
        o_entry, u_entry = os.urandom(32).hex().encode(), os.urandom(32).hex().encode()
        encrypt = add(
            b"<< /Filter /Standard /V 1 /R 2 /O <%s> /U <%s> /P -4 >>" % (o_entry, u_entry)
        )
        file_id = os.urandom(16).hex().encode()
        trailer_extra = b" /Encrypt %d 0 R /ID [<%s> <%s>]" % (encrypt, file_id, file_id)
    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for number, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % number + body + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objects) + 1)
    out += b"".join(b"%010d 00000 n \n" % offset for offset in offsets)
    out += b"trailer\n<< /Size %d /Root %d 0 R%s >>\nstartxref\n%d\n%%%%EOF\n" % (
        len(objects) + 1,
        catalog,
        trailer_extra,
        xref,
    )
    return bytes(out)


ENTITY_BOMB = (
    '<!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">'
    '<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">'
    '<!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">'
    '<!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">'
    '<!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">'
    '<!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">'
    '<!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">'
    '<!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">]>'
)
"""A billion-laughs DTD, for a part's prolog: expanded, it is 8^8 copies of "lol"."""
