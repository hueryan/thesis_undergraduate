from langchain_community.document_loaders import PyPDFLoader
from langchain.text_splitter import CharacterTextSplitter
import chardet
import codecs

def split_pdf_to_chunks(pdf_path, chunk_size=1000, chunk_overlap=200):
    loader = PyPDFLoader(pdf_path)
    documents = loader.load()

    for doc in documents:
        raw_content = doc.page_content
        detected = chardet.detect(raw_content.encode())
        encoding = detected['encoding'] or 'utf-8'
        try:
            codecs.lookup(encoding)
        except LookupError:
            encoding = 'utf-8'
        doc.page_content = raw_content.encode(encoding, errors='replace').decode(encoding, errors='replace')

    text_splitter = CharacterTextSplitter(
        chunk_size=chunk_size,
        chunk_overlap=chunk_overlap
    )
    return text_splitter.split_documents(documents)