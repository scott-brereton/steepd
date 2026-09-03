import zipfile

import pytest

from steepd.config import Settings
from steepd.epub import inspect_epub
from steepd.epubgen import build_epub
from steepd.newsletter import NewsletterResource


@pytest.fixture
def settings(tmp_path) -> Settings:
    return Settings(data_dir=tmp_path, public_base_url="http://localhost:8000")


def _write(tmp_path, payload: bytes):
    path = tmp_path / "out.epub"
    path.write_bytes(payload)
    return path


def test_mimetype_is_first_and_stored(tmp_path):
    payload = build_epub(
        title="Hello", author="Someone", language="en", identifier="urn:uuid:abc",
        body_html="<p>Body text</p>",
    )
    with zipfile.ZipFile(_write(tmp_path, payload)) as archive:
        first = archive.infolist()[0]
        assert first.filename == "mimetype"
        assert first.compress_type == zipfile.ZIP_STORED
        assert archive.read("mimetype") == b"application/epub+zip"


def test_round_trips_through_the_strict_inspector(tmp_path, settings):
    payload = build_epub(
        title="A newsletter", author="A publisher", language="en",
        identifier="urn:uuid:1234", body_html="<h1>Heading</h1><p>Paragraph</p>",
    )
    metadata = inspect_epub(_write(tmp_path, payload), settings, fallback_title="fallback")
    assert metadata.title == "A newsletter"
    assert metadata.author == "A publisher"
    assert metadata.language == "en"


def test_embeds_resources_and_survives_inspection(tmp_path, settings):
    png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64
    payload = build_epub(
        title="With image", author="", language="en", identifier="urn:uuid:5678",
        body_html='<p>See <img src="images/pic.png" alt="a picture"></p>',
        resources=[NewsletterResource(location="images/pic.png", content_type="image/png", content=png)],
    )
    path = _write(tmp_path, payload)
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        # Layout-agnostic: EbookLib writes under EPUB/, other writers use OEBPS/.
        # What matters is that the resource ships and the OPF manifests it.
        image_name = next(n for n in names if n.endswith("images/pic.png"))
        opf_name = next(n for n in names if n.endswith("content.opf"))
        assert archive.read(image_name) == png
        assert b"images/pic.png" in archive.read(opf_name)
    assert inspect_epub(path, settings, fallback_title="fallback").title == "With image"


def test_escapes_metadata_that_would_break_the_opf(tmp_path, settings):
    payload = build_epub(
        title="Tom & Jerry <script>", author='He said "hi"', language="en",
        identifier="urn:uuid:9999", body_html="<p>ok</p>",
    )
    metadata = inspect_epub(_write(tmp_path, payload), settings, fallback_title="fallback")
    assert metadata.title == "Tom & Jerry <script>"
