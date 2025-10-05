import os
import argparse
import yaml
import glob
from typing import List, Dict, Tuple
import google.generativeai as genai
from dotenv import load_dotenv
import chromadb
from chromadb.utils import embedding_functions
from chromadb.api.types import QueryResult
import re # For cleaning text

# Load environment variables from .env file
load_dotenv()

# --- Configuration Loading ---
def load_config(config_path: str) -> Dict:
    """Loads the YAML configuration file."""
    with open(config_path, 'r') as f:
        return yaml.safe_load(f)

# --- Configure Google Gemini API ---
API_KEY = os.getenv("GOOGLE_API_KEY")
if not API_KEY:
    raise ValueError("GOOGLE_API_KEY not found in environment variables. Please set it.")
genai.configure(api_key=API_KEY)

# Use Gemini's embedding function for ChromaDB
class GeminiEmbeddingFunction(embedding_functions.EmbeddingFunction):
    def __call__(self, input: embedding_functions.Documents) -> embedding_functions.Embeddings:
        model = "models/embedding-001"
        embeddings = []
        # The Gemini API might have rate limits or batch size limits,
        # so process in smaller batches if needed, or handle errors.
        for text_chunk in input:
            try:
                response = genai.embed_content(model=model, content=text_chunk)
                embeddings.append(response['embedding'])
            except Exception as e:
                print(f"Error generating embedding for chunk: {text_chunk[:50]}... Error: {e}")
                embeddings.append([]) # Append an empty list or handle as appropriate
        return embeddings

# Initialize the Gemini Embedding Function for ChromaDB
gemini_ef = GeminiEmbeddingFunction()

# --- Helper Functions ---

def load_and_filter_files(repo_path: str, include_globs: List[str], exclude_globs: List[str]) -> List[str]:
    """
    Loads file paths based on include/exclude globs.
    Returns a list of absolute file paths.
    """
    all_files = set()
    for pattern in include_globs:
        # Use os.path.join to correctly handle paths on different OS
        full_pattern = os.path.join(repo_path, pattern)
        # glob.glob returns files relative to cwd if repo_path isn't absolute,
        # so we ensure absolute paths.
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
    print(f"Found {len(filtered_files)} files after glob filtering.")
    return filtered_files

def split_text_into_chunks(text: str, chunk_size: int, chunk_overlap: int) -> List[str]:
    """
    Splits text into chunks with a specified size and overlap.
    A basic markdown-aware split could be implemented here if needed.
    For now, a character-based split.
    """
    chunks = []
    start = 0
    while start < len(text):
        end = start + chunk_size
        chunk = text[start:end]
        chunks.append(chunk)
        start += chunk_size - chunk_overlap
        if start < 0: # Ensure start doesn't go negative if chunk_overlap > chunk_size
            start = 0
    return chunks

def clean_text_for_embedding(text: str) -> str:
    """
    Basic text cleaning to remove excessive whitespace or non-meaningful characters
    that might interfere with embeddings, but keep context.
    """
    text = re.sub(r'\s+', ' ', text).strip() # Replace multiple spaces/newlines with single space
    # Consider removing markdown specific characters if they don't contribute to meaning
    # e.g., text = re.sub(r'[`*_{}[\]()#+\-.!]', '', text) - but this might remove too much context for code/structured data
    return text

# --- Knowledge Base Class (using ChromaDB) ---

class KnowledgeBase:
    def __init__(self, collection_name: str, embedding_function: embedding_functions.EmbeddingFunction):
        self.client = chromadb.PersistentClient(path="./chroma_db") # Stores db files in ./chroma_db
        self.collection = self.client.get_or_create_collection(
            name=collection_name,
            embedding_function=embedding_function # Pass the initialized embedding function
        )
        print(f"ChromaDB collection '{collection_name}' initialized.")

    def index_repository(self, config: Dict):
        repo_path = config['local_repo_path']
        include_globs = config.get('include_globs', [])
        exclude_globs = config.get('exclude_globs', [])
        chunk_chars = config['chunk_chars']
        chunk_overlap = config['chunk_overlap']
        base_url = config.get('base_url', '')

        print(f"Indexing repository at: {repo_path}...")
        file_paths = load_and_filter_files(repo_path, include_globs, exclude_globs)
        
        # Clear existing data in collection to re-index
        # self.collection.clear() # Use with caution if you want to update incrementally
        
        documents_to_add = []
        metadatas_to_add = []
        ids_to_add = []
        
        doc_counter = 0

        for filepath in file_paths:
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    content = f.read()
                
                # Generate a relative path for metadata and potential URL
                relative_filepath = os.path.relpath(filepath, repo_path)
                source_url = os.path.join(base_url, relative_filepath) if base_url else relative_filepath

                doc_chunks = split_text_into_chunks(content, chunk_chars, chunk_overlap)
                
                for i, chunk in enumerate(doc_chunks):
                    cleaned_chunk = clean_text_for_embedding(chunk)
                    if cleaned_chunk: # Only add if chunk is not empty after cleaning
                        documents_to_add.append(cleaned_chunk)
                        metadatas_to_add.append({
                            "source": relative_filepath,
                            "url": source_url,
                            "chunk_index": i
                        })
                        ids_to_add.append(f"{relative_filepath}_{i}")
                        doc_counter += 1

            except Exception as e:
                print(f"Warning: Could not read or process {filepath}: {e}")

        if documents_to_add:
            # ChromaDB handles embedding generation internally when add is called
            # and an embedding function is provided to the collection.
            print(f"Adding {len(documents_to_add)} chunks to ChromaDB...")
            self.collection.add(
                documents=documents_to_add,
                metadatas=metadatas_to_add,
                ids=ids_to_add
            )
            print(f"Indexed {doc_counter} chunks into collection '{self.collection.name}'.")
        else:
            print("No documents to add after processing.")

    def retrieve_relevant_chunks(self, query: str, top_k: int = 3) -> List[Tuple[str, str]]:
        """
        Retrieves the most relevant document chunks from ChromaDB based on the query.
        Returns a list of (chunk_content, source_url) tuples.
        """
        # ChromaDB query automatically uses the configured embedding function
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
                source_url = metadata.get('url', metadata.get('source', 'Unknown Source'))
                relevant_info.append((chunk_content, source_url))
        
        return relevant_info

# --- LLM Assistant ---

class LLMAssistant:
    def __init__(self, model_name: str):
        self.model = genai.GenerativeModel(model_name)
        print(f"Gemini LLM initialized with model: {model_name}")

    def generate_response(self, prompt: str) -> str:
        """
        Generates a response using the Gemini model.
        """
        try:
            response = self.model.generate_content(prompt)
            # Access response.text for the generated content
            # response.candidates[0].content.parts[0].text is another way for older versions or specific needs
            return response.text
        except genai.types.BlockedPromptException as e:
            return f"Error: Prompt blocked due to safety concerns. {e}"
        except Exception as e:
            return f"Error generating response from LLM: {e}"

# --- Main CLI Logic ---

def main():
    parser = argparse.ArgumentParser(description="A RAG LLM assistant for local Markdown repositories.")
    parser.add_argument("--config", default="config.yaml", help="Path to the YAML configuration file.")
    args = parser.parse_args()

    config = load_config(args.config)
    
    # Use config values
    collection_name = config['collection']
    gen_model = config['gen_model']
    chunk_chars = config['chunk_chars'] # These are now in config but also used in chunking logic
    chunk_overlap = config['chunk_overlap']

    knowledge_base = KnowledgeBase(collection_name=collection_name, embedding_function=gemini_ef)
    
    # Check if the collection is empty. If so, index the repository.
    # This prevents re-indexing every time the script runs if the data is already there.
    if knowledge_base.collection.count() == 0:
        print(f"Collection '{collection_name}' is empty or does not exist. Indexing repository...")
        knowledge_base.index_repository(config)
    else:
        print(f"Collection '{collection_name}' already contains {knowledge_base.collection.count()} items. Skipping re-indexing.")
        # If you want to force re-indexing, you could add a CLI flag or clear the collection manually.
        # e.g., knowledge_base.collection.clear()
        #       knowledge_base.index_repository(config)

    llm_assistant = LLMAssistant(model_name=gen_model)

    print("\nLocal RAG LLM Assistant ready! Type 'exit' to quit.")
    
    while True:
        query = input("\nYour question: ")
        if query.lower() == 'exit':
            break

        # Assuming TOP_K_RETRIEVAL is still 3 for now, or add to config
        relevant_chunks = knowledge_base.retrieve_relevant_chunks(query, top_k=3) 

        if not relevant_chunks:
            print("No relevant information found in the knowledge base. Please try a different query.")
            continue

        context_text = "\n\n".join([f"Source: {source_url}\nContent:\n{chunk}" for chunk, source_url in relevant_chunks])

        # Construct the RAG prompt
        rag_prompt = f"""
        You are an AI assistant that answers questions based on the provided context.
        If the answer is not available in the context, please state that you cannot answer from the given information.
        Do not make up information.

        Context:
        {context_text}

        Question: {query}

        Answer:
        """
        
        print("\nThinking... (This may take a moment)")
        response = llm_assistant.generate_response(rag_prompt)
        print("\n--- Assistant's Answer ---")
        print(response)
        print("------------------------\n")
        print("Sources used:")
        for _, source_url in relevant_chunks:
            print(f"- {source_url}")

if __name__ == "__main__":
    main()