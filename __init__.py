"""Hermes Apple Passwords: secret source, operator CLI, skill and browser-vault backend."""

import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)


def register(ctx) -> None:
    from .cli import handle_cli, setup_cli
    from .source import ApplePasswordsSource

    ctx.register_secret_source(ApplePasswordsSource())
    ctx.register_cli_command(
        name="apple-passwords",
        help="Use Apple Passwords credentials through the local bridge",
        setup_fn=setup_cli,
        handler_fn=handle_cli,
        description=(
            "Configure startup secret mappings, pair the local bridge, list account metadata, "
            "and explicitly read, run, or inject Apple Passwords references."
        ),
    )
    ctx.register_skill(
        "apple-passwords",
        Path(__file__).parent / "skills" / "apple-passwords" / "SKILL.md",
        description="Use Apple Passwords credentials on macOS with local pairing and secret injection.",
    )
    # The browser-vault backend wraps the agent process's backend list, so it is only
    # meaningful in-process. Inside an isolated plugin host the agent never sees it.
    if os.environ.get("HERMES_PLUGIN_HOST_PROCESS") != "1":
        from . import vault

        if not vault.install():
            logger.debug("Apple Passwords browser-vault backend not installed")
