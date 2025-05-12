from langchain_community.embeddings import HuggingFaceBgeEmbeddings
from config_milvus import MODEL_NAME
import os
# 获取当前脚本所在目录（即 configs 目录）
current_dir = os.path.dirname(os.path.abspath(__file__))
LOCAL_MODEL_PATH = f"{current_dir}/{MODEL_NAME}"


MODEL_DIM_MAPPING = {
    "BAAI/bge-small-zh-v1.5": 512,
    "BAAI/bge-base-zh-v1.5": 768,
    "BAAI/bge-large-zh-v1.5": 1024
}

model_kwargs = {'device': 'cuda'}
encode_kwargs = {'normalize_embeddings': True}

embedding_model = HuggingFaceBgeEmbeddings(
    model_name=LOCAL_MODEL_PATH,
    model_kwargs=model_kwargs,
    encode_kwargs=encode_kwargs,
    query_instruction="为以下问题生成表示以检索相关数据结构学习资料：",
)

model_dim = MODEL_DIM_MAPPING.get(MODEL_NAME)