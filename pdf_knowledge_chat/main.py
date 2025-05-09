import os
import time
from chat_session import ChatSession
from database_reset import reset_milvus_collection
from pdf_processing import process_and_store_pdf
from create_milvus_db import create_milvus_db



if __name__ == "__main__":
    # 1. Reset collection
    # reset_milvus_collection()

    # 2. Create database
    # create_milvus_db()

    """
    # 单文件处理：
    PDF_PATH = "../../data/pdf/数据结构 C语言版 第2版 (严蔚敏).pdf"
    if os.path.exists(PDF_PATH):
        process_and_store_pdf(PDF_PATH)
    else:
        raise "文件不存在"
    """

    # 3. pdf_load
    # PDF_DIR = "../../data/pdf"
    # pdf_files = [f for f in os.listdir(PDF_DIR) if f.endswith('.pdf')]

    # if not pdf_files:
    #     raise Exception("没有找到PDF文件")
    #
    # # Sort with pdf_name
    # for pdf_file in sorted(pdf_files):
    #     pdf_path = os.path.join(PDF_DIR, pdf_file)
    #     print(f"正在处理: {pdf_file}")
    #     process_and_store_pdf(pdf_path)


    # 4. Start chat session
    session = ChatSession()
    while True:
        question = input("\n用户提问（输入exit退出）: ")
        if question.lower() == "exit":
            break
        start_time = time.time()
        answer = session.generate_answer(question)
        print(f"\n{answer}\n\n（耗时{time.time() - start_time:.1f}s）")