from pymilvus import MilvusClient
from config import DB_NAME as db_name

client = MilvusClient()

def create_milvus_db():
    if db_name in client.list_databases():
        print(f'{db_name} 已经存在！')
    else:
        client.create_database(db_name)
        print(f'{db_name} 创建成功！！！')
    client.use_database(db_name=db_name)