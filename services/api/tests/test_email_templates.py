"""Every email renders in English and Japanese, as text and HTML, with exactly its keys (FR-33)."""

import re
from collections.abc import Callable
from dataclasses import fields
from datetime import UTC, datetime, timedelta, timezone
from importlib import resources
from uuid import UUID

import jinja2
import pytest
from jinja2 import meta, nodes

from email_samples import (
    ADMIN,
    CODE,
    EXPIRES,
    LINK_TOKEN,
    ORIGIN,
    SAMPLES,
    SECRETS,
    SENDER,
    TENANT,
    VARIANTS,
)
from sft.service.email import EmailRenderer, RenderedEmail, template_environment
from sft.service.email.catalog import (
    EMAILS,
    DlpPolicyChanged,
    Email,
    EmailType,
    Links,
    Locale,
    MemberInvitation,
    PolicyChange,
    RecipientLocked,
    TransferLink,
    VerificationCode,
    format_time,
)

Logs = Callable[[], list[dict[str, object]]]

RENDERER = EmailRenderer(ORIGIN)
ENV = template_environment()
LAYOUT_ONLY = {"subject", "lang"}  # the renderer adds these for the HTML layout
JAPANESE = re.compile(r"[぀-ヿ一-鿿]")
URL = re.compile(r"https?://[^\s\"'<>]+")


def source_vars(name: str) -> set[str]:
    """The keys a template reads from its context, without the names it imports."""
    source = ENV.loader.get_source(ENV, name)[0]  # type: ignore[union-attr]
    tree = ENV.parse(source)
    imported = {
        alias if isinstance(alias, str) else alias[1]
        for node in tree.find_all(nodes.FromImport)
        for alias in node.names
    }
    return meta.find_undeclared_variables(tree) - imported


def every_rendering() -> list[tuple[Email, Locale, RenderedEmail]]:
    return [(e, loc, RENDERER.render(e, loc)) for e in VARIANTS for loc in Locale]


RENDERED = every_rendering()


def test_every_email_type_has_a_class_and_a_sample() -> None:
    assert set(EMAILS) == set(EmailType)
    assert set(SAMPLES) == set(EmailType)
    assert all(type(SAMPLES[t]) is EMAILS[t] for t in EmailType)


def test_every_email_has_both_parts_in_both_languages_and_nothing_else() -> None:
    root = resources.files("sft.service.email") / "templates"
    for locale in Locale:
        files = {p.name for p in (root / locale.value).iterdir() if not p.name.startswith("_")}
        assert files == {f"{t}.{part}" for t in EmailType for part in ("txt", "html")}, locale


@pytest.mark.parametrize("email_type", list(EmailType))
@pytest.mark.parametrize("locale", list(Locale))
@pytest.mark.parametrize("part", ["txt", "html"])
def test_each_template_uses_exactly_its_emails_keys(
    email_type: EmailType, locale: Locale, part: str
) -> None:
    # No missing key, which StrictUndefined would also catch at render time, and no key left
    # unused, which would mean one language says less than the other.
    keys = set(SAMPLES[email_type].context(Links(ORIGIN), locale))
    used = source_vars(f"{locale}/{email_type}.{part}") | source_vars(f"{locale}/_layout.{part}")
    assert used - LAYOUT_ONLY == keys


def test_every_variant_renders_in_both_languages() -> None:
    for email, locale, rendered in RENDERED:
        where = f"{email.TYPE} ({locale})"
        assert rendered.subject, where
        assert "\n" not in rendered.subject, where
        assert TENANT in rendered.text or email.TYPE is EmailType.FIRST_DOWNLOAD, where
        assert rendered.html.startswith("<!DOCTYPE html>"), where
        assert f'<html lang="{locale}">' in rendered.html, where
        for part in (rendered.subject, rendered.text, rendered.html):
            assert "None" not in part, where
            assert "{{" not in part, where
            assert "{%" not in part, where


def test_japanese_is_japanese_and_english_is_english() -> None:
    for email, locale, rendered in RENDERED:
        where = f"{email.TYPE} ({locale})"
        if locale is Locale.JA:
            assert JAPANESE.search(rendered.subject), where
            assert JAPANESE.search(rendered.text), where
        else:
            assert not JAPANESE.search(rendered.subject + rendered.text + rendered.html), where


def test_every_policy_change_has_a_label_in_both_languages() -> None:
    email = DlpPolicyChanged(tenant_name=TENANT, changes=tuple(PolicyChange))
    for locale in Locale:
        text = RENDERER.render(email, locale).text
        assert text.count("\n- ") == len(PolicyChange), locale


def test_a_missing_key_is_an_error() -> None:
    template = ENV.get_template("en/transfer_link.txt")
    with pytest.raises(jinja2.UndefinedError):
        template.render(tenant_name=TENANT)


# ---- links and secrets: only where the design allows (abuse 7.5, authn-authz 4.1 and 4.2) ----


def test_emails_link_only_to_the_web_app() -> None:
    for email, locale, rendered in RENDERED:
        for part in (rendered.text, rendered.html):
            for url in URL.findall(part):
                assert url.startswith(f"{ORIGIN}/"), f"{email.TYPE} ({locale}): {url}"
        for href in re.findall(r'href="([^"]*)"', rendered.html):
            assert href.startswith(f"{ORIGIN}/"), f"{email.TYPE} ({locale})"


def test_each_secret_appears_only_in_its_own_email_and_in_both_parts() -> None:
    for secret, owner in SECRETS.items():
        for locale in Locale:
            rendered = RENDERER.render(SAMPLES[owner], locale)
            assert secret in rendered.text, f"{owner} ({locale})"
            assert secret in rendered.html, f"{owner} ({locale})"
    for email, locale, rendered in RENDERED:
        for secret, owner in SECRETS.items():
            where = f"{secret} in {email.TYPE} ({locale})"
            assert secret not in rendered.subject, where
            if email.TYPE is not owner:
                assert secret not in rendered.text + rendered.html, where


def test_tokens_travel_only_in_the_fragment() -> None:
    for _, _, rendered in RENDERED:
        for url in URL.findall(rendered.text):
            assert "?" not in url
            if "#" in url:
                assert re.fullmatch(rf"{ORIGIN}/(t|u|invite)#[A-Za-z0-9_-]+", url)


def test_the_code_email_has_no_link() -> None:
    for locale in Locale:
        rendered = RENDERER.render(SAMPLES[EmailType.VERIFICATION_CODE], locale)
        assert not URL.search(rendered.text + rendered.html)


def test_the_upload_and_recipient_links_use_their_own_pages() -> None:
    text = RENDERER.render(SAMPLES[EmailType.TRANSFER_LINK], Locale.EN).text
    assert f"{ORIGIN}/t#{LINK_TOKEN}" in text
    text = RENDERER.render(SAMPLES[EmailType.UPLOAD_REQUEST], Locale.EN).text
    assert f"{ORIGIN}/u#" in text
    text = RENDERER.render(SAMPLES[EmailType.MEMBER_INVITATION_SSO], Locale.EN).text
    assert f"{ORIGIN}/invite#" in text


def test_recipient_locked_links_to_the_right_page() -> None:
    transfer = SAMPLES[EmailType.RECIPIENT_LOCKED]
    assert isinstance(transfer, RecipientLocked)
    assert f"{ORIGIN}/transfers/" in RENDERER.render(transfer, Locale.EN).text
    request = RecipientLocked(
        tenant_name=TENANT, subject_kind="upload_request", subject_id=UUID(int=1)
    )
    assert f"{ORIGIN}/upload-requests/" in RENDERER.render(request, Locale.JA).text


# ---- escaping ----


def test_html_escapes_every_value_and_text_keeps_it_plain() -> None:
    name = '<a href="https://evil.example">Acme</a> & "Co"'
    email = VerificationCode(tenant_name=name, code=CODE)
    for locale in Locale:
        rendered = RENDERER.render(email, locale)
        assert "evil.example" not in re.findall(r'href="([^"]*)"', rendered.html)
        assert '<a href="https://evil.example">' not in rendered.html
        assert "&lt;a href=&#34;https://evil.example&#34;&gt;" in rendered.html
        assert name in rendered.text


# ---- values ----


def test_times_are_shown_in_japan_time() -> None:
    assert format_time(EXPIRES, Locale.EN) == "20 November 2026, 12:00 Japan time (UTC+9)"
    assert format_time(EXPIRES, Locale.JA) == "2026年11月20日 12:00（日本時間）"  # noqa: RUF001 - Japanese brackets
    other_zone = EXPIRES.astimezone(timezone(timedelta(hours=-5)))
    assert format_time(other_zone, Locale.EN) == format_time(EXPIRES, Locale.EN)


@pytest.mark.parametrize(
    ("make", "name"),
    [
        (lambda: VerificationCode(tenant_name=TENANT, code="12a456"), "code"),
        (lambda: VerificationCode(tenant_name=TENANT, code="12345"), "code"),
        (lambda: VerificationCode(tenant_name="Bad\r\nBcc: x@y.example", code=CODE), "tenant_name"),
        (lambda: VerificationCode(tenant_name="", code=CODE), "tenant_name"),
        # A line or paragraph separator breaks a header as \n does; a bidi override hides text.
        (lambda: VerificationCode(tenant_name="Acme\u2028X", code=CODE), "tenant_name"),
        (lambda: VerificationCode(tenant_name="Acme\u2029X", code=CODE), "tenant_name"),
        (lambda: VerificationCode(tenant_name="Acme\u202eX", code=CODE), "tenant_name"),
        (lambda: VerificationCode(tenant_name=TENANT, code=CODE, valid_minutes=0), "valid_minutes"),
        (
            lambda: TransferLink(
                tenant_name=TENANT,
                sender_email=SENDER,
                token="short",  # noqa: S106 - a bad token
                expires_at=EXPIRES,
            ),
            "token",
        ),
        (
            lambda: TransferLink(
                tenant_name=TENANT,
                sender_email="not an address",
                token=LINK_TOKEN,
                expires_at=EXPIRES,
            ),
            "sender_email",
        ),
        (
            lambda: TransferLink(
                tenant_name=TENANT,
                sender_email=SENDER,
                token=LINK_TOKEN,
                expires_at=datetime(2026, 11, 20),  # the naive time under test
            ),
            "expires_at",
        ),
        (
            lambda: MemberInvitation(
                tenant_name=TENANT,
                temporary_password="has space",  # noqa: S106 - a bad password
                valid_days=7,
            ),
            "temporary_password",
        ),
        (
            lambda: RecipientLocked(
                tenant_name=TENANT,
                subject_kind="file",  # type: ignore[arg-type]
                subject_id=UUID(int=1),
            ),
            "subject_kind",
        ),
        (lambda: DlpPolicyChanged(tenant_name=TENANT, changes=()), "changes"),
        (lambda: DlpPolicyChanged(tenant_name=TENANT, changes=("rule_added",)), "changes"),  # type: ignore[arg-type]
    ],
)
def test_bad_values_are_refused_without_echoing_them(make: Callable[[], Email], name: str) -> None:
    with pytest.raises(ValueError, match=f"^{name} is not valid$"):
        make()


def test_a_decision_must_be_approved_or_rejected() -> None:
    from sft.service.email.catalog import DlpApprovalDecided

    with pytest.raises(ValueError, match=r"^decision is not valid$"):
        DlpApprovalDecided(tenant_name=TENANT, transfer_id=UUID(int=1), decision="maybe")  # type: ignore[arg-type]


def test_reprs_hold_no_secret_and_no_address() -> None:
    for email in VARIANTS:
        shown = repr(email)
        assert not any(secret in shown for secret in SECRETS), email.TYPE
        assert SENDER not in shown, email.TYPE
        assert ADMIN not in shown, email.TYPE
    for email, _, rendered in RENDERED:
        assert (
            repr(rendered)
            == f"RenderedEmail(email_type={email.TYPE!r}, locale={rendered.locale!r})"
        )


def test_secret_fields_are_declared() -> None:
    # A field the samples treat as a secret is listed in its class's SECRETS, and hidden.
    for email_type in set(SECRETS.values()):
        cls = EMAILS[email_type]
        assert cls.SECRETS
        hidden = {f.name for f in fields(cls) if not f.repr}
        assert set(cls.SECRETS) <= hidden, email_type


def test_the_base_class_has_no_context_of_its_own() -> None:
    with pytest.raises(NotImplementedError):
        Email(tenant_name=TENANT).context(Links(ORIGIN), Locale.EN)


def test_a_multi_line_subject_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    renderer = EmailRenderer(ORIGIN)
    env = jinja2.Environment(  # noqa: S701 - text only, nothing to escape
        loader=jinja2.DictLoader(
            {
                "en/transfer_held.txt": "{% block subject %}one\ntwo{% endblock %}",
                "en/transfer_held.html": "x",
            }
        ),
        undefined=jinja2.StrictUndefined,
    )
    monkeypatch.setattr(renderer, "_env", env)
    with pytest.raises(ValueError, match="must be one line"):
        renderer.render(SAMPLES[EmailType.TRANSFER_HELD], Locale.EN)


# ---- composing an email for a mailer ----


def test_compose_addresses_and_tags_the_email() -> None:
    tenant_id = UUID(int=7)
    out = RENDERER.compose(
        SAMPLES[EmailType.TRANSFER_LINK],
        Locale.JA,
        to="recipient@partner.example",
        tenant_id=tenant_id,
        tags={"recipient_id": str(UUID(int=9))},
    )
    assert out.reply_to == SENDER  # abuse 7.5: Reply-To is the sender
    assert out.email_type == "transfer_link"
    assert out.all_tags() == {
        "tenant_id": str(tenant_id),
        "email_type": "transfer_link",
        "recipient_id": str(UUID(int=9)),
    }
    assert LINK_TOKEN in out.text
    assert "recipient@partner.example" not in repr(out)
    assert LINK_TOKEN not in repr(out)


def test_only_emails_that_name_a_sender_have_a_reply_to() -> None:
    with_sender = {
        EmailType.TRANSFER_LINK,
        EmailType.UPLOAD_REQUEST,
        EmailType.FILES_BLOCKED_UPLOADER,
    }
    for email_type, email in SAMPLES.items():
        assert (email.reply_to == SENDER) is (email_type in with_sender), email_type
        if email_type not in with_sender:
            assert email.reply_to is None


def test_rendering_logs_nothing(json_logs: Logs) -> None:
    for email in VARIANTS:
        for locale in Locale:
            RENDERER.compose(email, locale, to="r@partner.example", tenant_id=UUID(int=1))
    assert json_logs() == []


def test_times_need_no_time_zone_database() -> None:
    # The image may have no tzdata; a fixed UTC+9 offset needs none (Japan has no DST).
    assert (
        format_time(datetime(2026, 7, 1, 15, 0, tzinfo=UTC), Locale.JA)
        == "2026年7月2日 00:00（日本時間）"  # noqa: RUF001 - Japanese brackets
    )
