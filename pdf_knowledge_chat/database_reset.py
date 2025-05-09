from pymilvus import connections, utility
from config import MILVUS_COLLECTION_NAME
from config import DB_NAME as db_name

def reset_milvus_collection():
    try:
        connections.connect(host='localhost', port='19530', db_name=db_name)
        if utility.has_collection(MILVUS_COLLECTION_NAME):
            utility.drop_collection(MILVUS_COLLECTION_NAME)
            print(f"Collection {MILVUS_COLLECTION_NAME} reset successfully")
        else:
            print(f"Collection {MILVUS_COLLECTION_NAME} does not exist")
    except Exception as e:
        print(f"Reset failed: {str(e)}")
    finally:
        connections.disconnect("default")