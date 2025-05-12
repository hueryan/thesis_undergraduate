import pymysql
from datetime import datetime
from configs.database_config import MYSQL_HOST, MYSQL_PORT, MYSQL_USER, MYSQL_PW, MYSQL_DB, MYSQL_PDF_TABLE

def insert_pdf_info(pdf_name, pdf_path):
    try:
        # 建立数据库连接
        connection = pymysql.connect(
            host=MYSQL_HOST,
            port=int(MYSQL_PORT),
            user=MYSQL_USER,
            password=MYSQL_PW,
            database=MYSQL_DB,
            charset='utf8mb4',
            cursorclass=pymysql.cursors.DictCursor
        )

        with connection.cursor() as cursor:
            # 插入 PDF 信息的 SQL 语句
            sql = f"INSERT INTO {MYSQL_PDF_TABLE} (pdf_name, pdf_path) VALUES (%s, %s)"
            cursor.execute(sql, (pdf_name, pdf_path))


        # 提交事务
        connection.commit()
        print(f"PDF {pdf_name} 信息插入成功")
    except Exception as e:
        print(f"插入失败: {str(e)}")
        # 回滚事务
        connection.rollback()
    finally:
        # 关闭数据库连接
        connection.close()

# 调用函数插入 PDF 信息
pdf_name = "数据结构(C语言版第2版).pdf"
pdf_path = "./data/pdf/数据结构(C语言版第2版).pdf"
insert_pdf_info(pdf_name, pdf_path)