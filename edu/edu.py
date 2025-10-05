import os
import argparse
import yaml
import glob
from typing import List, Dict, Tuple
import chromadb
from chromadb.utils import embedding_functions
from chromadb.api.types import QueryResult
import re # for cleaning text
import sys # for exit
import ollama # new: for ollama interaction

# --- configuration loading ---
def load_config(config_path: str = "config.yaml") -> Dict:
    """loads the yaml configuration file."""
    if not os.path.exists(config_path):
        print(f"error: config file '{config_path}' not found.", file=sys.stderr)
        print("please create a config.yaml file with your repository path and other settings.", file=sys.stderr)
        sys.exit(1)
    with open(config_path, 'r') as f:
        return yaml.safe_load(f)

# --- ollama embedding function for chromadb ---
class OllamaEmbeddingFunction(embedding_functions.EmbeddingFunction):
    def __init__(self, model_name: str = "nomic-embed-text"):
        self.model_name = model_name
        # check if ollama server is running and model is available
        try:
            ollama.show(self.model_name)
            print(f"ollama embedding model '{self.model_name}' loaded successfully.")
        except Exception as e:
            print(f"error: ollama embedding model '{self.model_name}' not available or ollama server not running. {e}", file=sys.stderr)
            sys.exit(1)

    def __call__(self, input: embedding_functions.Documents) -> embedding_functions.Embeddings:
        embeddings = []
        for text_chunk in input:
            try:
                response = ollama.embeddings(model=self.model_name, prompt=text_chunk)
                embeddings.append(response['embedding'])
            except Exception as e:
                print(f"error generating ollama embedding for chunk: {text_chunk[:50]}... error: {e}", file=sys.stderr)
                embeddings.append([])
        return embeddings

# --- helper functions ---

def load_and_filter_files(repo_path: str, include_globs: List[str], exclude_globs: List[str]) -> List[str]:
    """
    loads file paths based on include/exclude globs.
    returns a list of absolute file paths.
    """
    all_files = set()
    for pattern in include_globs:
        full_pattern = os.path.join(repo_path, pattern)
        matched_files = glob.glob(full_pattern, recursive=True)
        for f in matched_files:
            all_files.add(os.path.abspath(f))

    excluded_files = set()
    for pattern in exclude_globs:
        full_pattern = os.path.join(repo_path, pattern)
        matched_files = glob.glob(full_pattern, recursive=True)
        for f in matched_files:
            excluded_files.add(os.path.abspath(f))

    filtered_files = sorted(list(all_files - excluded_files))
    print(f"found {len(filtered_files)} files after glob filtering.")
    return filtered_files

def split_text_into_chunks(text: str, chunk_size: int, chunk_overlap: int) -> List[str]:
    """
    splits text into chunks with a specified size and overlap.
    """
    chunks = []
    start = 0
    while start < len(text):
        end = start + chunk_size
        chunk = text[start:end]
        chunks.append(chunk)
        start += chunk_size - chunk_overlap
        if start < 0:
            start = 0 # ensure start doesn't go negative
    return chunks

def clean_text_for_embedding(text: str) -> str:
    """
    basic text cleaning to remove excessive whitespace or non-meaningful characters.
    """
    text = re.sub(r'\s+', ' ', text).strip() # replace multiple spaces/newlines with single space
    return text

# --- knowledge base class (using chromadb) ---

class KnowledgeBase:
    def __init__(self, collection_name: str, embedding_function: embedding_functions.EmbeddingFunction):
        self.client = chromadb.PersistentClient(path="./chroma_db_ollama") # stores db files in ./chroma_db_ollama
        self.collection_name = collection_name # store collection name
        self.embedding_function = embedding_function # store embedding function

        self.collection = self.client.get_or_create_collection(
            name=self.collection_name,
            embedding_function=self.embedding_function
        )
        print(f"chromadb collection '{self.collection_name}' initialized.")


    def index_repository(self, config: Dict):
        repo_path = config['local_repo_path']
        include_globs = config.get('include_globs', [])
        exclude_globs = config.get('exclude_globs', [])
        chunk_chars = config['chunk_chars']
        chunk_overlap = config['chunk_overlap']
        base_url = config.get('base_url', '')

        if not os.path.exists(repo_path):
            print(f"error: local repository path '{repo_path}' does not exist.", file=sys.stderr)
            sys.exit(1)

        print(f"indexing repository at: {repo_path}...")
        file_paths = load_and_filter_files(repo_path, include_globs, exclude_globs)
        
        if not file_paths:
            print("no files found to index after applying globs. please check your config.", file=sys.stderr)
            return

        # delete and re-create collection to ensure a clean slate
        print(f"deleting and re-creating collection '{self.collection_name}' for fresh indexing...")
        try:
            self.client.delete_collection(name=self.collection_name)
            self.collection = self.client.get_or_create_collection(
                name=self.collection_name,
                embedding_function=self.embedding_function
            )
        except Exception as e:
            # this might happen if the collection never existed, which is fine.
            print(f"warning: could not delete collection (might not exist yet): {e}", file=sys.stderr)
            self.collection = self.client.get_or_create_collection( # ensure it's created even if delete failed
                name=self.collection_name,
                embedding_function=self.embedding_function
            )
        
        documents_to_add = []
        metadatas_to_add = []
        ids_to_add = []
        
        doc_counter = 0

        for filepath in file_paths:
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    content = f.read()
                
                relative_filepath = os.path.relpath(filepath, repo_path)
                source_url = os.path.join(base_url, relative_filepath) if base_url else relative_filepath

                doc_chunks = split_text_into_chunks(content, chunk_chars, chunk_overlap)
                
                for i, chunk in enumerate(doc_chunks):
                    cleaned_chunk = clean_text_for_embedding(chunk)
                    if cleaned_chunk: # only add if chunk is not empty after cleaning
                        documents_to_add.append(cleaned_chunk)
                        metadatas_to_add.append({
                            "source": relative_filepath,
                            "url": source_url,
                            "chunk_index": i
                        })
                        ids_to_add.append(f"{relative_filepath}_{i}")
                        doc_counter += 1

            except Exception as e:
                print(f"warning: could not read or process {filepath}: {e}", file=sys.stderr)

        if documents_to_add:
            print(f"adding {len(documents_to_add)} chunks to chromadb...")
            self.collection.add(
                documents=documents_to_add,
                metadatas=metadatas_to_add,
                ids=ids_to_add
            )
            print(f"indexed {doc_counter} chunks into collection '{self.collection_name}'.")
        else:
            print("no documents to add after processing.", file=sys.stderr)

    def retrieve_relevant_chunks(self, query: str, top_k: int = 3) -> List[Tuple[str, str]]:
        """
        retrieves the most relevant document chunks from chromadb based on the query.
        returns a list of (chunk_content, source_url) tuples.
        """
        if self.collection.count() == 0:
            print("knowledge base is empty. please run 'index' command first.", file=sys.stderr)
            return []

        results: QueryResult = self.collection.query(
            query_texts=[query],
            n_results=top_k,
            include=['documents', 'metadatas']
        )
        
        relevant_info = []
        if results['documents'] and results['metadatas']:
            for i in range(len(results['documents'][0])):
                chunk_content = results['documents'][0][i]
                metadata = results['metadatas'][0][i]
                source_url = metadata.get('url', metadata.get('source', 'unknown source'))
                relevant_info.append((chunk_content, source_url))
        
        return relevant_info

# --- llm assistant ---

class LLMAssistant:
    def __init__(self, model_name: str):
        self.model_name = model_name
        try:
            ollama.show(self.model_name) # check if model exists
            print(f"ollama llm initialized with model: {model_name}")
        except Exception as e:
            print(f"error: ollama generative model '{self.model_name}' not available or ollama server not running. {e}", file=sys.stderr)
            sys.exit(1)


    def generate_response(self, prompt: str) -> str:
        """
        generates a response using the ollama model.
        """
        try:
            response = ollama.chat(model=self.model_name, messages=[{'role': 'user', 'content': prompt}])
            return response['message']['content']
        except Exception as e:
            return f"error generating response from llm: {e}"

# --- command handlers ---

def cmd_index(config_path: str):
    config = load_config(config_path)
    collection_name = config['collection']
    ollama_embed_model = config['ollama_embed_model']

    ollama_ef = OllamaEmbeddingFunction(model_name=ollama_embed_model)
    knowledge_base = KnowledgeBase(collection_name=collection_name, embedding_function=ollama_ef)
    knowledge_base.index_repository(config)
    print("indexing complete.")

def cmd_ask(question: str, config_path: str):
    config = load_config(config_path)
    collection_name = config['collection']
    ollama_gen_model = config['ollama_gen_model']
    ollama_embed_model = config['ollama_embed_model'] # need embed model to initialize knowledge_base

    ollama_ef = OllamaEmbeddingFunction(model_name=ollama_embed_model)
    knowledge_base = KnowledgeBase(collection_name=collection_name, embedding_function=ollama_ef)
    
    llm_assistant = LLMAssistant(model_name=ollama_gen_model)

    print(f"\nasking: '{question}'")

    # assuming top_k_retrieval is still 3, or add to config for `ask` command specifically
    relevant_chunks = knowledge_base.retrieve_relevant_chunks(question, top_k=3) 

    if not relevant_chunks:
        print("no relevant information found in the knowledge base for this question. please try indexing first if you haven't.", file=sys.stderr)
        return

    context_text = "\n\n".join([f"source: {source_url}\ncontent:\n{chunk}" for chunk, source_url in relevant_chunks])

    # updated rag prompt as requested
    rag_prompt = f"""
    you are an ai malware research and threat intelligence assistant that answers questions based on the provided context.
    if the answer is not available in the context, please state that you cannot answer from the given information.
    do not make up information.

    context:
    {context_text}

    question: {question}

    answer:
    """
    
    print("\nthinking... (this may take a moment)")
    response = llm_assistant.generate_response(rag_prompt)
    print("\n--- assistant's answer ---")
    print(response)
    print("------------------------\n")
    print("sources used:")
    for _, source_url in relevant_chunks:
        print(f"- {source_url}")

# --- main cli logic ---

def main():
    p = argparse.ArgumentParser(description="tiny local rag (ollama) - poc")
    p.add_argument("--config", default="config.yaml", help="path to the yaml configuration file (default: config.yaml)")

    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("index", help="index the local repository into the chromadb collection.")
    
    a = sub.add_parser("ask", help="ask a question grounded in the indexed chunks.")
    a.add_argument("question", help="the question you want to ask.")

    args = p.parse_args()

    if args.cmd == "index":
        cmd_index(args.config)
    elif args.cmd == "ask":
        cmd_ask(args.question, args.config)

if __name__ == "__main__":
    main()