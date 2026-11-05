"""Renders the service's emails in English and Japanese, as plain text and HTML (FR-33, #100).

Templates live in `templates/<locale>/<email type>.txt` and `.html`. The text file holds the
subject in its `subject` block. Both extend the locale's `_layout`, which adds the footer.

Why Jinja2: it autoescapes by file extension, so every value in an HTML part is escaped unless a
template says otherwise (none does), while the text part stays plain; `StrictUndefined` makes a
missing key an error instead of an empty string; `jinja2.meta` lists the keys a template uses, so a
test checks every template against its email's fields. It is the most used Python template engine,
maintained by Pallets, with MarkupSafe already in the lock. `string.Template` has no escaping, no
conditionals and no layouts; Mako and Chameleon add nothing we need and are less used.

Nothing here logs. A rendered email holds secrets (a link, a code, a temporary password) and an
address, so `RenderedEmail` and `OutgoingEmail` keep them out of their reprs (ADR-0009).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from uuid import UUID

import jinja2

from sft.data.mail import OutgoingEmail
from sft.service.email.catalog import EMAILS, Email, EmailType, Links, Locale, PolicyChange


@dataclass(frozen=True)
class RenderedEmail:
    email_type: EmailType
    locale: Locale
    subject: str = field(repr=False)
    text: str = field(repr=False)
    html: str = field(repr=False)


def template_environment() -> jinja2.Environment:
    """The one Jinja2 environment: templates from this package, escaping for `.html` only."""
    return jinja2.Environment(
        loader=jinja2.PackageLoader("sft.service.email", "templates"),
        autoescape=jinja2.select_autoescape(
            enabled_extensions=("html",), default_for_string=False, default=False
        ),
        undefined=jinja2.StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
        auto_reload=False,
    )


class EmailRenderer:
    def __init__(self, web_app_url: str) -> None:
        self._links = Links(web_app_url)
        self._env = template_environment()

    def render(self, email: Email, locale: Locale) -> RenderedEmail:
        context = email.context(self._links, locale)
        text_template = self._env.get_template(f"{locale}/{email.TYPE}.txt")
        subject = "".join(
            text_template.blocks["subject"](text_template.new_context(context))
        ).strip()
        if subject.splitlines() != [subject]:  # every line break, U+2028 included
            raise ValueError(f"the subject of {email.TYPE} ({locale}) must be one line")
        text = text_template.render(context)
        html = self._env.get_template(f"{locale}/{email.TYPE}.html").render(
            {**context, "subject": subject, "lang": locale.value}
        )
        return RenderedEmail(email.TYPE, locale, subject, text, html)

    def compose(
        self,
        email: Email,
        locale: Locale,
        *,
        to: str,
        tenant_id: UUID,
        tags: Mapping[str, str] | None = None,
    ) -> OutgoingEmail:
        """The rendered email, addressed and tagged, ready for a `Mailer`."""
        rendered = self.render(email, locale)
        return OutgoingEmail(
            tenant_id=tenant_id,
            email_type=email.TYPE.value,
            to=to,
            subject=rendered.subject,
            text=rendered.text,
            html=rendered.html,
            reply_to=email.reply_to,
            tags=dict(tags or {}),
        )


__all__ = [
    "EMAILS",
    "Email",
    "EmailRenderer",
    "EmailType",
    "Locale",
    "PolicyChange",
    "RenderedEmail",
    "template_environment",
]
