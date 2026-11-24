#!/usr/bin/env python3
"""Manual check: run the classifier against real release notes."""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import anthropic
from dotenv import load_dotenv

from rbd_update_bot import classifier, release_notes
from rbd_update_bot.release_notes import ReleaseSource

load_dotenv()

client = anthropic.Anthropic()
MODEL = "claude-sonnet-5"

CASES = [
    {
        "label": "Continuwuity -- known real breaking changes (should flag)",
        "service_name": "matrix",
        "image": "forgejo.ellis.link/continuwuation/continuwuity",
        "current_version": "v26.8.1",
        "new_version": "v26.9.0",
        "source": ReleaseSource(type="forgejo", host="https://forgejo.ellis.link",
                                 repo="continuwuation/continuwuity"),
    },
    {
        "label": "Joplin -- boring patch bump (should NOT flag)",
        "service_name": "joplin",
        "image": "joplin/server",
        "current_version": "v3.7.16",
        "new_version": "v3.7.18",
        "source": ReleaseSource(type="github", repo="laurent22/joplin"),
    },
]

for case in CASES:
    print(f"=== {case['label']} ===")
    print(f"{case['service_name']}: {case['current_version']} -> {case['new_version']}")

    notes, url = release_notes.fetch_release_notes(
        case["source"], case["current_version"], case["new_version"]
    )
    print(f"release notes: {len(notes)} chars, url={url}")

    assessment = classifier.classify(
        client=client,
        model=MODEL,
        service_name=case["service_name"],
        image=case["image"],
        current_version=case["current_version"],
        new_version=case["new_version"],
        release_notes=notes,
    )
    print(f"risk_level: {assessment.risk_level}")
    print(f"breaking_changes: {assessment.breaking_changes}")
    print(f"summary: {assessment.summary}")
    print(f"citations: {assessment.citations}")
    print()
