"""
Prompt-injection / data-leak detection patterns.

This is the ONLY place pattern definitions live. To tune the guardrails
(add a phrase, relax a rule to cut false positives) edit the lists below —
no other file needs to change.

Each entry is ``(compiled_regex, category, reason)``:
* ``category`` is a short label used only for debug diagnostics.
* ``reason``   is the ``BlockReason`` returned to the caller.

Matching is case-insensitive and tolerant of extra whitespace. We keep the
patterns readable on purpose rather than maximally clever — this is a
lightweight, practical guard, not a complete adversarial-NLP system.
"""
import re
from typing import Optional

from services.guardrails.guardrail_types import BlockReason

_FLAGS = re.IGNORECASE | re.DOTALL

PatternEntry = tuple[re.Pattern, str, BlockReason]


def _c(pattern: str) -> re.Pattern:
    return re.compile(pattern, _FLAGS)


# ---------------------------------------------------------------------------
# 1. Attempts to override / ignore prior or system instructions
# ---------------------------------------------------------------------------
INSTRUCTION_OVERRIDE: list[PatternEntry] = [
    (_c(r"\b(ignore|disregard|forget|override|bypass)\b[^.\n]{0,40}\b(previous|prior|above|earlier|all|the|your|system|safety|these|any)\b[^.\n]{0,20}\b(instruction|instructions|rule|rules|prompt|prompts|message|messages|guideline|guidelines|direction|directions)\b"),
     "instruction_override", BlockReason.PROMPT_INJECTION_DETECTED),
    (_c(r"\bforget (the|everything|all) (above|before|previously|earlier)\b"),
     "instruction_override", BlockReason.PROMPT_INJECTION_DETECTED),
    (_c(r"\byou are no longer\b"),
     "instruction_override", BlockReason.PROMPT_INJECTION_DETECTED),
    (_c(r"\bdo not (summarize|answer|respond|reply)\b[^.\n]{0,30}\b(instead|rather)\b"),
     "instruction_override", BlockReason.HIDDEN_INSTRUCTIONS),
    (_c(r"\bdo not answer the user\b"),
     "instruction_override", BlockReason.HIDDEN_INSTRUCTIONS),
    (_c(r"\bfollow (these|the following)( new)? (instruction|instructions|rule|rules)\b"),
     "instruction_override", BlockReason.HIDDEN_INSTRUCTIONS),
    (_c(r"\bfollow these instructions instead\b"),
     "instruction_override", BlockReason.HIDDEN_INSTRUCTIONS),
    (_c(r"\bnew rules?\s*:"),
     "instruction_override", BlockReason.HIDDEN_INSTRUCTIONS),
    (_c(r"\binstead[, ]+(reveal|print|show|output|respond|say|return|leak)\b"),
     "instruction_override", BlockReason.HIDDEN_INSTRUCTIONS),
]

# ---------------------------------------------------------------------------
# 2. Role manipulation / jailbreak framing
# ---------------------------------------------------------------------------
ROLE_MANIPULATION: list[PatternEntry] = [
    (_c(r"\bdeveloper mode\b"), "role_manipulation", BlockReason.PROMPT_INJECTION_DETECTED),
    (_c(r"\bdev mode\b"), "role_manipulation", BlockReason.PROMPT_INJECTION_DETECTED),
    (_c(r"\bjailbreak\b"), "role_manipulation", BlockReason.PROMPT_INJECTION_DETECTED),
    (_c(r"\bact as (the )?system\b"), "role_manipulation", BlockReason.PROMPT_INJECTION_DETECTED),
    (_c(r"\byou are now (in )?(developer|dev|god|admin|root) mode\b"),
     "role_manipulation", BlockReason.PROMPT_INJECTION_DETECTED),
    (_c(r"\benable (developer|dev|god) mode\b"),
     "role_manipulation", BlockReason.PROMPT_INJECTION_DETECTED),
    (_c(r"\bpretend (you are|to be) (the )?(system|developer|admin)\b"),
     "role_manipulation", BlockReason.PROMPT_INJECTION_DETECTED),
]

# ---------------------------------------------------------------------------
# 3. Attempts to leak the system / developer / hidden prompt
# ---------------------------------------------------------------------------
SYSTEM_PROMPT_LEAK: list[PatternEntry] = [
    (_c(r"\b(reveal|show|print|expose|display|repeat|leak|dump|give me|tell me|output)\b[^.\n]{0,30}\b(your |the |you )?(system|developer|hidden|internal|initial|original)\b[^.\n]{0,12}\b(prompt|prompts|instruction|instructions|message|messages|rules)\b"),
     "system_prompt_leak", BlockReason.SYSTEM_PROMPT_LEAK),
    (_c(r"\bwhat (is|are) your (system|initial|original|hidden) (prompt|prompts|instruction|instructions)\b"),
     "system_prompt_leak", BlockReason.SYSTEM_PROMPT_LEAK),
    (_c(r"\brepeat the (words|text|instructions|prompt) above\b"),
     "system_prompt_leak", BlockReason.SYSTEM_PROMPT_LEAK),
    (_c(r"\breveal (developer|hidden) instructions\b"),
     "system_prompt_leak", BlockReason.SYSTEM_PROMPT_LEAK),
]

# ---------------------------------------------------------------------------
# 4. Attempts to leak secrets / environment variables
# ---------------------------------------------------------------------------
SECRET_LEAK_INTENT: list[PatternEntry] = [
    (_c(r"\b(show|print|reveal|expose|leak|dump|list|give me|tell me|output)\b[^.\n]{0,30}\b(api[\s_-]?keys?|secret|secrets|environment variables?|env vars?|credential|credentials|password|passwords|service key|access token|auth token)\b"),
     "secret_leak", BlockReason.SECRET_LEAK_ATTEMPT),
    (_c(r"\bprint environment variables\b"),
     "secret_leak", BlockReason.SECRET_LEAK_ATTEMPT),
    (_c(r"\b(OPENAI_API_KEY|LLM_API_KEY|EMBEDDING_API_KEY|SUPABASE_SERVICE_KEY|STORAGE_ACCOUNT_SECRET|DATABASE_URL|STORAGE_URL)\b"),
     "secret_leak", BlockReason.SECRET_LEAK_ATTEMPT),
]

# ---------------------------------------------------------------------------
# 5. Multi-turn context poisoning (delayed / distributed attacks)
# ---------------------------------------------------------------------------
CONTEXT_POISONING: list[PatternEntry] = [
    (_c(r"\bfor the rest of (this|the) (conversation|chat|session)\b"),
     "context_poisoning", BlockReason.CONTEXT_POISONING),
    (_c(r"\bfrom now on\b"),
     "context_poisoning", BlockReason.CONTEXT_POISONING),
    (_c(r"\bremember (this|the following)[^.\n]{0,40}\b(rule|instruction|for later)\b"),
     "context_poisoning", BlockReason.CONTEXT_POISONING),
    (_c(r"\bremember this rule for later\b"),
     "context_poisoning", BlockReason.CONTEXT_POISONING),
    (_c(r"\b(obey|follow) only (me|my|the user)\b"),
     "context_poisoning", BlockReason.CONTEXT_POISONING),
    (_c(r"\bwhenever i (ask|request|say)\b"),
     "context_poisoning", BlockReason.CONTEXT_POISONING),
    (_c(r"\bkeep this in mind for (later|all future)\b"),
     "context_poisoning", BlockReason.CONTEXT_POISONING),
    (_c(r"\bfor all (future|subsequent) (messages|responses|answers|replies)\b"),
     "context_poisoning", BlockReason.CONTEXT_POISONING),
]

# ---------------------------------------------------------------------------
# 6. Unsafe MODEL OUTPUT — leak phrases the model itself might emit
# ---------------------------------------------------------------------------
OUTPUT_LEAK_PHRASES: list[PatternEntry] = [
    (_c(r"\bhere (is|are) my (system|developer|hidden|internal) (prompt|prompts|instruction|instructions)\b"),
     "output_system_prompt", BlockReason.SYSTEM_PROMPT_LEAK),
    (_c(r"\bmy (system|developer) (prompt|instructions)\b[^.\n]{0,6}\b(is|are)\b"),
     "output_system_prompt", BlockReason.SYSTEM_PROMPT_LEAK),
    (_c(r"\b(system|developer) prompt\s*:"),
     "output_system_prompt", BlockReason.SYSTEM_PROMPT_LEAK),
    (_c(r"\bthe developer (instructed|told|asked|wants) me\b"),
     "output_developer_ref", BlockReason.SYSTEM_PROMPT_LEAK),
    (_c(r"\bi (ignored|disregarded|bypassed) the user('?s)?( request| question| instruction)?\b"),
     "output_ignored_user", BlockReason.HIDDEN_INSTRUCTIONS),
    (_c(r"\b(hidden|secret) instructions in the (pdf|document|book|file|text)\b"),
     "output_followed_pdf", BlockReason.HIDDEN_INSTRUCTIONS),
    (_c(r"\bi (followed|obeyed|am following|will follow) the (hidden|secret|embedded) instructions\b"),
     "output_followed_pdf", BlockReason.HIDDEN_INSTRUCTIONS),
    (_c(r"\bas (instructed|requested) (in|by) the (pdf|document|book)\b"),
     "output_followed_pdf", BlockReason.HIDDEN_INSTRUCTIONS),
]

# Actual secret VALUES that must never appear in a response.
SECRET_VALUE: list[PatternEntry] = [
    (_c(r"\bsk-or-v1-[A-Za-z0-9_-]{12,}"), "openrouter_key", BlockReason.SECRET_LEAK_ATTEMPT),
    (_c(r"\bsk-[A-Za-z0-9]{20,}"), "openai_key", BlockReason.SECRET_LEAK_ATTEMPT),
    (_c(r"\bAKIA[0-9A-Z]{16}\b"), "aws_key", BlockReason.SECRET_LEAK_ATTEMPT),
    (_c(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{6,}"), "jwt", BlockReason.SECRET_LEAK_ATTEMPT),
    (_c(r"\b(postgres|postgresql)://[^\s:]+:[^\s@]+@"), "db_dsn", BlockReason.SECRET_LEAK_ATTEMPT),
    (_c(r"\b(OPENAI_API_KEY|LLM_API_KEY|EMBEDDING_API_KEY|SUPABASE_SERVICE_KEY|STORAGE_ACCOUNT_SECRET|DATABASE_URL)\s*[=:]\s*\S"),
     "env_assignment", BlockReason.SECRET_LEAK_ATTEMPT),
]


# ---------------------------------------------------------------------------
# Grouped rule sets used by each guard
# ---------------------------------------------------------------------------

# User input: the full set (we want maximum recall on user-typed prompts).
INPUT_GROUPS: list[PatternEntry] = (
    INSTRUCTION_OVERRIDE
    + ROLE_MANIPULATION
    + SYSTEM_PROMPT_LEAK
    + SECRET_LEAK_INTENT
    + CONTEXT_POISONING
)

# PDF/book content: only the strong, unambiguous injection signals.
# Context-poisoning phrases ("from now on", "whenever I ask") are excluded
# because they legitimately appear in ordinary prose and would over-block.
DOCUMENT_GROUPS: list[PatternEntry] = (
    INSTRUCTION_OVERRIDE
    + ROLE_MANIPULATION
    + SYSTEM_PROMPT_LEAK
    + SECRET_LEAK_INTENT
)

# Model output: leak phrases + literal secret values.
OUTPUT_GROUPS: list[PatternEntry] = OUTPUT_LEAK_PHRASES + SECRET_VALUE


def _scan(text: Optional[str], groups: list[PatternEntry]) -> Optional[tuple[str, BlockReason]]:
    """Return ``(category, reason)`` for the first matching rule, else None."""
    if not text:
        return None
    for regex, category, reason in groups:
        if regex.search(text):
            return category, reason
    return None


def scan_input(text: Optional[str]) -> Optional[tuple[str, BlockReason]]:
    """Scan user-supplied text (prompts, conversation messages)."""
    return _scan(text, INPUT_GROUPS)


def scan_document(text: Optional[str]) -> Optional[tuple[str, BlockReason]]:
    """Scan untrusted document/PDF context destined for the LLM."""
    return _scan(text, DOCUMENT_GROUPS)


def scan_output(text: Optional[str]) -> Optional[tuple[str, BlockReason]]:
    """Scan model output before returning it to the client."""
    return _scan(text, OUTPUT_GROUPS)
