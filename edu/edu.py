from __future__ import annotations
import fnmatch
import textwrap
import uuid
from pathlib import Path
from typing import List, Tuple

import yaml
import chromadb
from chromadb.config import Settings
import ollama

# ---------- tiny utils ----------

def load_cfg() -> dict:
    return yaml.safe_load(Path("config.yaml").read_text(encoding="utf-8"))

def match_any(p: Path, patterns: List[str]) -> bool:
    s = p.as_posix()
    return any(fnmatch.fnmatch(s, pat) for pat in patterns)

def iter_files(root: Path, inc: List[str], exc: List[str]):
    for p in root.rglob("*"):
        if p.is_file() and match_any(p, inc) and not match_any(p, exc):
            yield p

def chunk_text(text: str, size: int, overlap: int):
    n = len(text)
    if n <= size:
        yield text, 0, n
        return
    start = 0
    while start < n:
        end = min(n, start + size)
        yield text[start:end], start, end
        if end >= n: break
        start = max(0, end - overlap)

def embed_batch_ollama(model: str, texts: List[str]) -> List[List[float]]:
    """ollama embeddings; support old/new SDK signatures."""
    embs: List[List[float]] = []
    for t in texts:
        try:
            r = ollama.embeddings(model=model, prompt=t)  # older SDK
        except TypeError:
            r = ollama.embeddings(model=model, input=t)   # newer SDK
        embs.append(r["embedding"])
    return embs

# ---------- chroma compat helpers ----------

def chroma_client() -> chromadb.Client:
    return chromadb.Client(Settings(is_persistent=True, persist_directory=".chroma"))

def create_collection_compat(client: chromadb.Client, name: str):
    """create or recreate a collection across chroma API variants."""
    # delete if exists
    try:
        # newer/most versions: list_collections() -> objects with .name
        existing = [c.name for c in client.list_collections()]
        if name in existing:
            client.delete_collection(name=name)
    except TypeError:
        # older signature: delete_collection(collection_name=...)
        client.delete_collection(collection_name=name)

    # create with name=
    try:
        return client.create_collection(name=name)
    except TypeError:
        # older signature: positional or collection_name=
        try:
            return client.create_collection(name)  # positional
        except TypeError:
            return client.create_collection(collection_name=name)

def get_collection_compat(client: chromadb.Client, name: str):
    """get a collection across chroma API variants."""
    try:
        return client.get_collection(name=name)
    except TypeError:
        return client.get_collection(collection_name=name)

# ---------- index ----------

def cmd_index():
    cfg = load_cfg()
    repo_path = Path(cfg.get("local_repo_path", ".")).resolve()
    if not repo_path.exists():
        raise SystemExit(f"local path not found: {repo_path}")

    include = cfg.get("include_globs", ["_posts/**/*.md"])
    exclude = cfg.get("exclude_globs", [])
    collection = cfg.get("collection", "cocomelonc_blog_poc")
    embed_model = cfg.get("embed_model", "nomic-embed-text")
    size = int(cfg.get("chunk_chars", 1200))
    ovlp = int(cfg.get("chunk_overlap", 200))
    base_url = cfg.get("base_url", "")

    # ensure ollama is up
    try:
        _ = ollama.list()
    except Exception as e:
        raise SystemExit(f"ollama not running/installed: {e}\nStart with: `ollama serve`")

    client = chroma_client()
    col = create_collection_compat(client, collection)

    docs, ids, metas = [], [], []
    BATCH = 64

    for f in iter_files(repo_path, include, exclude):
        txt = f.read_text(encoding="utf-8", errors="ignore")
        for chunk, s, e in chunk_text(txt, size, ovlp):
            ids.append(str(uuid.uuid4()))
            docs.append(chunk)
            # simple, non-null metadata
            rel = f.relative_to(repo_path).as_posix()
            metas.append({
                "path": rel,
                "start": int(s),
                "end": int(e),
                "url": (base_url + rel) if base_url else rel,
            })
            if len(docs) >= BATCH:
                embs = embed_batch_ollama(embed_model, docs)
                col.add(ids=ids, documents=docs, embeddings=embs, metadatas=metas)
                docs, ids, metas = [], [], []

    if docs:
        embs = embed_batch_ollama(embed_model, docs)
        col.add(ids=ids, documents=docs, embeddings=embs, metadatas=metas)

    print(f"indexed collection: {collection}")

# ---------- ask ----------

SYS_PROMPT = (
    "you are a malware research and threat intelligence assistant for posts from cocomelonc.github.io. "
    "answer strictly based on the provided context. "
    "cite sources as [title-or-path](URL) after the relevant statements. "
    "focus on educational and practice-oriented explanations of code."
)

def retrieve(q: str, collection: str, k: int = 6):
    client = chroma_client()
    col = get_collection_compat(client, collection)
    res = col.query(query_texts=[q], n_results=k, include=["documents", "metadatas"])
    docs = res["documents"][0]
    metas = res["metadatas"][0]
    return list(zip(docs, metas))

def build_messages(query: str, ctx: List[Tuple[str, dict]]):
    blocks = []
    for i, (doc, m) in enumerate(ctx, 1):
        path = m.get("path", "unknown")
        url = m.get("url", path)
        blocks.append(f"[{i}] {path} — {url}\n{doc}")
    ctx_text = "\n\n".join(blocks)
    user = f"""\
question: {query}

context:
{ctx_text}

instructions:
- be concise and precise.
- if context is insufficient, say so clearly.
- cite sources as [path](URL) right after the relevant statements.
"""
    return [
        {"role": "system", "content": SYS_PROMPT},
        {"role": "user", "content": textwrap.dedent(user)},
    ]

def generate_answer(model: str, messages) -> str:
    try:
        r = ollama.chat(model=model, messages=messages)
        return r["message"]["content"]
    except Exception as e:
        raise RuntimeError(f"ollama chat failed: {e}")

def cmd_ask(question: str):
    cfg = load_cfg()
    # ensure ollama is up
    try:
        _ = ollama.list()
    except Exception as e:
        raise SystemExit(f"ollama not running/installed: {e}")

    ctx = retrieve(question, cfg.get("collection", "cocomelonc_blog_poc"), k=6)
    msgs = build_messages(question, ctx)
    ans = generate_answer(cfg.get("gen_model", "llama3.1:8b"), msgs)
    print(ans)

# ---------- entry ----------

def main():
    import argparse
    p = argparse.ArgumentParser(description="tiny local RAG (ollama) - PoC")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("index", help="index local repo (plain text chunking)")
    a = sub.add_parser("ask", help="ask a question grounded in indexed chunks")
    a.add_argument("question")

    args = p.parse_args()
    if args.cmd == "index":
        cmd_index()
    elif args.cmd == "ask":
        cmd_ask(args.question)

if __name__ == "__main__":
    main()
