from __future__ import annotations
import fnmatch
import textwrap
import uuid
from pathlib import Path
from typing import List, Tuple

import yaml
import frontmatter
import chromadb
from chromadb.config import Settings
from markdown_it import MarkdownIt

# === local llm (ollama) ===
# make sure you have `ollama` installed and models pulled:
# ollama pull nomic-embed-text
# ollama pull llama3.1:8b
import ollama

MD = MarkdownIt()

# -----------------------
# config & utils
# -----------------------
def load_cfg(path: str = "config.yaml") -> dict:
    return yaml.safe_load(Path(path).read_text(encoding="utf-8"))

def match_any(p: Path, patterns: List[str]) -> bool:
    s = p.as_posix()
    return any(fnmatch.fnmatch(s, pat) for pat in patterns)

def iter_files(root: Path, inc: List[str], exc: List[str]):
    for p in root.rglob("*"):
        if p.is_file() and match_any(p, inc) and not match_any(p, exc):
            yield p

def split_markdown_sections(md_text: str):
    """
    split by headings and extract fenced code blocks as standalone chunks.
    returns list of tuples: (type, text, meta_dict)
    """
    tokens = MD.parse(md_text)
    chunks, cur_heading, buf = [], None, []

    def flush():
        nonlocal buf
        if buf and any(t.strip() for t in buf):
            chunks.append(("section", "\n".join(buf).strip(), {"heading": cur_heading}))
        buf = []

    i = 0
    while i < len(tokens):
        t = tokens[i]
        if t.type == "heading_open":
            flush()
            if i + 1 < len(tokens) and tokens[i + 1].type == "inline":
                cur_heading = tokens[i + 1].content.strip()
            while i < len(tokens) and tokens[i].type != "heading_close":
                i += 1
        elif t.type in ("fence", "code_block"):
            flush()
            lang = getattr(t, "info", "") or ""
            code = t.content
            chunks.append(("code", code, {"heading": cur_heading, "lang": lang.strip()}))
        elif t.type == "inline":
            if t.content:
                buf.append(t.content)
        i += 1
    flush()
    return chunks

def chunk_text(text: str, size: int, overlap: int):
    if len(text) <= size:
        yield text, 0, len(text)
        return
    start = 0
    while start < len(text):
        end = min(len(text), start + size)
        yield text[start:end], start, end
        if end == len(text):
            break
        start = max(0, end - overlap)

def embed_batch_ollama(model: str, texts: list[str]) -> list[list[float]]:
    """
    Ollama embeddings via nomic-embed-text.
    Supports both SDK signatures:
      - embeddings(model=..., prompt="...")
      - embeddings(model=..., input="...")  # newer
    """
    embs: list[list[float]] = []
    for t in texts:
        try:
            # older SDKs
            r = ollama.embeddings(model=model, prompt=t)
            embs.append(r["embedding"])
        except TypeError:
            # newer SDKs
            r = ollama.embeddings(model=model, input=t)
            embs.append(r["embedding"])
        except Exception as e:
            raise RuntimeError(f"ollama embeddings failed: {e}")
    return embs


# -----------------------
# index command (local path)
# -----------------------
def cmd_index():
    cfg = load_cfg()

    # use local repo path directly
    repo_path = Path(cfg.get("local_repo_path", ".")).resolve()
    if not repo_path.exists():
        raise SystemExit(f"local repository path not found: {repo_path}")

    inc = cfg.get("include_globs", ["_posts/**/*.md"])
    exc = cfg.get("exclude_globs", [])
    collection = cfg.get("collection", "cocomelonc_blog")
    embed_model = cfg.get("embed_model", "nomic-embed-text")
    size = int(cfg.get("chunk_chars", 1200))
    ovlp = int(cfg.get("chunk_overlap", 180))
    base_url = cfg.get("base_url", "")
    md_cfg = cfg.get(
        "md",
        {"split_by_headings": True, "code_as_separate_chunks": True, "include_front_matter": True},
    )

    # sanity: check Ollama daemon
    try:
        _ = ollama.list()
    except Exception as e:
        raise SystemExit(
            f"ollama is not running or not installed: {e}\n"
            f"install: https://ollama.com | start: `ollama serve`"
        )

    chroma = chromadb.Client(Settings(is_persistent=True, persist_directory=".chroma"))

    # recreate collection for a clean index
    if collection in [c.name for c in chroma.list_collections()]:
        chroma.delete_collection(collection)
    col = chroma.create_collection(collection)

    docs, ids, metas = [], [], []
    batch_size = 64

    for f in iter_files(repo_path, inc, exc):
        raw = f.read_text(encoding="utf-8", errors="ignore")
        post = frontmatter.loads(raw)
        fm = post.metadata or {}
        body = str(post.content)

        parts = split_markdown_sections(body) if md_cfg.get("split_by_headings", True) else [
            ("section", body, {})
        ]

        rel = f.relative_to(repo_path).as_posix()
        url = base_url + rel if base_url else rel

        for typ, content, meta in parts:
            if not content.strip():
                continue
            for chunk, s, e in chunk_text(content, size, ovlp):
                ids.append(str(uuid.uuid4()))
                docs.append(chunk)
                metas.append({
                    "path": rel,
                    "url": url,
                    "type": typ,
                    "heading": meta.get("heading"),
                    "lang": meta.get("lang"),
                    "start": s,
                    "end": e,
                    "title": fm.get("title"),
                    "date": str(fm.get("date") or ""),
                })
                if len(docs) >= batch_size:
                    embs = embed_batch_ollama(embed_model, docs)
                    col.add(documents=docs, metadatas=metas, embeddings=embs, ids=ids)
                    docs, metas, ids = [], [], []

    if docs:
        embs = embed_batch_ollama(embed_model, docs)
        col.add(documents=docs, metadatas=metas, embeddings=embs, ids=ids)

    print(f"indexed: {collection}")

# -----------------------
# ask command
# -----------------------
SYS_PROMPT = (
    "You are a malware research and threat intelligence assistant for posts from cocomelonc.github.io. "
    "Answer strictly based on the provided context. "
    "Cite sources as [title](URL) immediately after relevant statements. "
    "Focus on educational and practice-oriented explanations of code."
)

def retrieve(q: str, collection: str, k: int = 8) -> List[Tuple[str, dict]]:
    chroma = chromadb.Client(Settings(is_persistent=True, persist_directory=".chroma"))
    col = chroma.get_collection(collection_name=collection)
    res = col.query(query_texts=[q], n_results=k, include=["documents", "metadatas"])
    return list(zip(res["documents"][0], res["metadatas"][0]))

def build_messages(query: str, ctx: List[Tuple[str, dict]]):
    blocks: List[str] = []
    for i, (doc, m) in enumerate(ctx, 1):
        title = m.get("title") or m.get("heading") or m.get("path")
        url = m.get("url") or m.get("path")
        blocks.append(f"[{i}] {title} — {url}\n{doc}")
    ctx_text = "\n\n".join(blocks)

    user = f"""\
Question: {query}

Context:
{ctx_text}

Instructions:
1) Be concise and precise.
2) If context is insufficient, say so clearly and suggest where to look.
3) Cite sources as [title](URL) after each relevant statement.
"""
    messages = [
        {"role": "system", "content": SYS_PROMPT},
        {"role": "user", "content": textwrap.dedent(user)},
    ]
    return messages

def generate_answer(model: str, messages) -> str:
    try:
        resp = ollama.chat(model=model, messages=messages)
        return resp["message"]["content"]
    except Exception as e:
        raise RuntimeError(f"ollama chat failed: {e}")

def cmd_ask(question: str):
    cfg = load_cfg()
    # sanity: check ollama daemon
    try:
        _ = ollama.list()
    except Exception as e:
        raise SystemExit(f"ollama is not running or not installed: {e}")

    ctx = retrieve(question, cfg.get("collection", "cocomelonc_blog"), k=8)
    messages = build_messages(question, ctx)
    ans = generate_answer(cfg.get("gen_model", "llama3.1:8b"), messages)
    print(ans)

# -----------------------
# simple CLI entrypoint
# -----------------------
def main():
    import argparse

    parser = argparse.ArgumentParser(description="cocomelonc blog RAG (ollama cli, local repo path)")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("index", help="index/refresh embeddings from the local repository path")
    p_ask = sub.add_parser("ask", help='ask a question grounded in the indexed posts')
    p_ask.add_argument("question", help='your question, e.g. "Explain RC5 vs Speck"')

    args = parser.parse_args()
    if args.cmd == "index":
        cmd_index()
    elif args.cmd == "ask":
        cmd_ask(args.question)

if __name__ == "__main__":
    main()
