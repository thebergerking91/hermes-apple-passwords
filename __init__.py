"""Hermes Apple Passwords secret source and operator CLI."""

from pathlib import Path

def register(ctx) -> None:
    from .cli import handle_cli, setup_cli
    from .source import ApplePasswordsSource

    ctx.register_secret_source(ApplePasswordsSource())
    ctx.register_cli_command(
        name="apple-passwords",
        help="Access Apple Passwords through the local bridge",
        setup_fn=setup_cli,
        handler_fn=handle_cli,
        description="Check pairing, list account metadata, and explicitly use references.",
    )
    ctx.register_skill(
        "apple-passwords",
        Path(__file__).parent / "skills" / "apple-passwords" / "SKILL.md",
        description="Use Apple Passwords credentials on macOS with local pairing and secret injection.",
    )
