import json
import os

from fastapi import FastAPI, Query, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from groq import Groq

from tools_catalog import TOOLS

app = FastAPI(
    title="ARGUS Tool Search API",
    description="Search ARGUS security tools using natural language queries powered by AI.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

GROQ_API_KEY = os.environ.get("GROQ_API_KEY")


def _build_catalog_text() -> str:
    lines = []
    for t in TOOLS:
        lines.append(f"[{t['id']}] {t['name']} ({t['category']}): {t['description']}")
    return "\n".join(lines)


CATALOG_TEXT = _build_catalog_text()

SYSTEM_PROMPT = f"""You are an assistant that helps users find the right ARGUS security tool for their needs.

Below is the complete catalog of 81 ARGUS tools:

{CATALOG_TEXT}

When the user describes what they want to do, return the most relevant tools (max 3) ordered by relevance.

You MUST respond with ONLY valid JSON, no markdown, no explanation outside the JSON. Use this exact format:
[
  {{
    "id": <tool_id>,
    "name": "<tool_name>",
    "category": "<category>",
    "description": "<tool_description>",
    "relevance": "<brief explanation in the same language as the user query of why this tool is relevant>"
  }}
]

If no tool matches, return an empty array: []
"""


def _get_client() -> Groq:
    api_key = GROQ_API_KEY or os.environ.get("GROQ_API_KEY")
    if not api_key:
        raise HTTPException(status_code=500, detail="GROQ_API_KEY not configured")
    return Groq(api_key=api_key)


@app.get("/api/search")
@app.get("/search")
def search_tools(q: str = Query(..., min_length=1, description="Natural language query")):
    client = _get_client()

    chat_completion = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": q},
        ],
        temperature=0.2,
        max_tokens=1024,
    )

    raw = chat_completion.choices[0].message.content.strip()

    # Strip markdown code fences if present
    if raw.startswith("```"):
        raw = raw.split("\n", 1)[1] if "\n" in raw else raw[3:]
        if raw.endswith("```"):
            raw = raw[:-3].strip()

    try:
        results = json.loads(raw)
    except json.JSONDecodeError:
        raise HTTPException(status_code=502, detail=f"AI returned invalid JSON: {raw}")

    # Enrich with menu_number
    for r in results:
        r["menu_number"] = r.get("id")

    return {"query": q, "results": results}


@app.get("/api/tools")
@app.get("/tools")
def list_tools():
    return {"total": len(TOOLS), "tools": TOOLS}
