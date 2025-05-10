from dotenv import dotenv_values

configs = dotenv_values("milvus_config.env")
DEEPSEEK_API_KEY = configs['DEEPSEEK_API_KEY']
MODEL_NAME = configs['MODEL_NAME']
DB_NAME = configs['DB_NAME']
MILVUS_COLLECTION_NAME = configs['MILVUS_COLLECTION_NAME']
