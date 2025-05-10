from dotenv import dotenv_values
import os

# 获取当前脚本所在目录（即 configs 目录）
current_dir = os.path.dirname(os.path.abspath(__file__))
env_path = os.path.join(current_dir, "milvus_config.env")
configs = dotenv_values(env_path)

DEEPSEEK_API_KEY = configs['DEEPSEEK_API_KEY']
MODEL_NAME = configs['MODEL_NAME']
DB_NAME = configs['DB_NAME']
MILVUS_COLLECTION_NAME = configs['MILVUS_COLLECTION_NAME']
