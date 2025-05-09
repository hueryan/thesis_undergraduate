from langchain_community.embeddings import HuggingFaceBgeEmbeddings
from config import MODEL_NAME

MODEL_DIM_MAPPING = {
    "BAAI/bge-small-zh-v1.5": 512,
    "BAAI/bge-base-zh-v1.5": 768,
    "BAAI/bge-large-zh-v1.5": 1024
}

model_kwargs = {'device': 'cuda'}
encode_kwargs = {'normalize_embeddings': True}

embedding_model = HuggingFaceBgeEmbeddings(
    model_name=MODEL_NAME,
    model_kwargs=model_kwargs,
    encode_kwargs=encode_kwargs,
    query_instruction="为以下问题生成表示以检索相关数据结构学习资料：",
)

model_dim = MODEL_DIM_MAPPING.get(MODEL_NAME)