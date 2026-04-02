"""Prompt construction for LLM judges."""

from pathlib import Path
from typing import Literal

_PROMPT_DIR = Path(__file__).resolve().parent.parent.parent.parent / "data" / "llm_prompts"

_MAX_CONTENT_LENGTH = 50_000  # characters


def build_prompt(
    registry: Literal["npm", "pypi", "rubygems"],
    files: dict[str, str],
    deobfuscated_content: str | None = None,
) -> str:
    """Build a prompt for the LLM judge.

    Args:
        registry: Package registry type.
        files: Dict of {filename: content} to analyze.
        deobfuscated_content: Optional pre-processed content from deobfuscator.
    """
    template_file = _PROMPT_DIR / f"{registry}_analysis.txt"
    if not template_file.exists():
        template_file = _PROMPT_DIR / "npm_analysis.txt"

    template = template_file.read_text(encoding="utf-8")

    # Build file listing
    file_parts: list[str] = []
    total_len = 0

    for filename, content in files.items():
        if total_len + len(content) > _MAX_CONTENT_LENGTH:
            file_parts.append(f"\n### {filename} (truncated)\n```\n{content[:5000]}...\n```")
            break
        file_parts.append(f"\n### {filename}\n```\n{content}\n```")
        total_len += len(content)

    if deobfuscated_content:
        file_parts.append(f"\n### [Deobfuscated content]\n```\n{deobfuscated_content[:10000]}\n```")

    files_text = "\n".join(file_parts)
    return template.replace("{files}", files_text)
