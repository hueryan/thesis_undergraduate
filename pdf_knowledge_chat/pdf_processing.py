import time
from embedding_model import embedding_model
from milvus_manager import MilvusManager
from config import MODEL_NAME


def process_and_store_pdf(pdf_path):
    start_time = time.time()
    milvus = MilvusManager()

    from pdf_processor import split_pdf_to_chunks
    chunks = split_pdf_to_chunks(pdf_path)
    texts = [chunk.page_content for chunk in chunks]

    # Batch processing
    batch_size = 8 if "large" in MODEL_NAME else 2048
    embeddings = []
    for i in range(0, len(texts), batch_size):
        batch = texts[i:i + batch_size]
        embeddings.extend(embedding_model.embed_documents(batch))

    milvus.insert_data(texts, embeddings)
    print(f"Stored {len(texts)} chunks with {len(embeddings)} embeddings")
    print(f"Time cost: {time.time() - start_time:.2f}s")