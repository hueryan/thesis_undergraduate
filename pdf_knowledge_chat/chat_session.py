# chat_session.py
import time
from embedding_model import embedding_model
from milvus_manager import MilvusManager
from config_milvus import DEEPSEEK_API_KEY
from langchain_openai import ChatOpenAI


class ChatSession:
    def __init__(self):
        self.history = []
        self.milvus = MilvusManager()
        self.llm = ChatOpenAI(
            openai_api_base="https://api.deepseek.com/v1",
            openai_api_key=DEEPSEEK_API_KEY,
            model_name="deepseek-chat"
        )

    def generate_answer(self, question):
        # Retrieve context
        query_embedding = embedding_model.embed_query(question)
        context = self.milvus.search(query_embedding)

        # # Build prompt
        prompt = f"""你是一个熟练掌握数据结构的教授助理，基于知识库内容和对话历史，严格按以下格式要求回答问题：

        知识库上下文：
        {''.join(context)}

        对话历史：
        {self._format_history()}
        
        要求：
        1. 如果用户询问了不是关于数据结构或者资料库没有的时候，你可以通过标注一下内容为deepseek生成，给出他/她提问所对应的解释（通过本来的模型功能），最后回答完他的问题可以通过柏拉图式提问，将他的问题与数据结构相结合抛出问题
        2. 如果用户提问的是数据库内容，拆分知识点，给出定义，看情况给出其他的内容，包括但不限于举例子。最后也通过苏格拉德式提问抛出与之提出相关相关问题
        3. 当涉及到代码时，使用完整的 C 语言编写
        
        

        格式要求：
        1. 每个独立问题使用 # 问题 作为一级标题
        2. 答案内容使用 ## 答案 作为二级标题
        3. 不同轮次的问答用---分隔
        4. 答案中需要包含代码示例时使用```包裹
        5. 使用规范的Markdown语法

        当前问题：{question}
        答案："""

        # Generate answer
        response = self.llm.invoke(prompt)
        self._update_history(question, response.content)
        return response.content


    def _format_history(self):
        return "\n\n---\n".join([
            f"# 问题\n{content}\n\n## 回答\n{answer}"
            for (_, content), (_, answer) in zip(self.history[::2], self.history[1::2])
        ])

    def _update_history(self, question, answer):
        self.history.extend([("user", question), ("assistant", answer)])