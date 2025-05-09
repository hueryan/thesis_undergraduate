from pymilvus import connections, FieldSchema, CollectionSchema, DataType, Collection, utility, MilvusClient
from config import MILVUS_COLLECTION_NAME, MODEL_NAME
from embedding_model import model_dim
from config import DB_NAME as db_name

class MilvusManager:
    def __init__(self):
        self.collection_name = MILVUS_COLLECTION_NAME
        self.dim = model_dim
        self._connect()
        self._prepare_collection()

    def _connect(self):
        connections.connect(host="localhost", port="19530", db_name=db_name)



    def _prepare_collection(self):
        if not utility.has_collection(self.collection_name):
            self._create_collection()
        self.collection = Collection(self.collection_name)
        self.collection.load()

    def _create_collection(self):
        fields = [
            FieldSchema(name="id", dtype=DataType.INT64, is_primary=True, auto_id=True),
            FieldSchema(name="text", dtype=DataType.VARCHAR, max_length=5000),
            FieldSchema(name="embedding", dtype=DataType.FLOAT_VECTOR, dim=self.dim)
        ]
        schema = CollectionSchema(fields, description="数据结构知识库")
        self.collection = Collection(self.collection_name, schema)
        self._create_index()

    # def _create_index(self):
    #     # if self.dim == 512:
    #     #     index_params = {"M": 16, "efConstruction": 200}
    #     # elif self.dim == 1024:
    #     #     index_params = {"M": 24, "efConstruction": 300}
    #     index_params = {
    #         "index_type": "HNSW",
    #         "metric_type": "L2",
    #         "params": {"M": 16, "efConstruction": 200}
    #     }
    #     self.collection.create_index("embedding", index_params)



    def _create_index(self):
        index_params = {
            "index_type": "HNSW",
            "metric_type": "L2",
            "params": {},
            # 若选择性开启一下则注释
            # "params": {"M": 16, "efConstruction": 200}
        }


        # 根据向量维度调整参数
        if self.dim == 512:
            # 512维（低维度）：平衡精度与资源消耗
            index_params["params"] = {"M": 16, "efConstruction": 200}
        elif self.dim == 768:
            # 768维（中维度）：适度提升参数以保持搜索质量
            index_params["params"] = {"M": 20, "efConstruction": 250}
        elif self.dim == 1024:
            # 1024维（高维度）：降低参数以避免显存溢出
            index_params["params"] = {"M": 24, "efConstruction": 300}

        # 显式创建HNSW索引
        self.collection.create_index(
            field_name="embedding",
            index_params=index_params
        )

    def insert_data(self, texts, embeddings):
        entities = [texts, embeddings]
        self.collection.insert(entities)
        self.collection.flush()

    def search(self, query_embedding, top_k=3):
        search_params = {"metric_type": "L2", "params": {"nprobe": 10}}
        results = self.collection.search(
            data=[query_embedding],
            anns_field="embedding",
            param=search_params,
            limit=top_k,
            output_fields=["text"]
        )
        return [hit.entity.get("text") for hit in results[0]]