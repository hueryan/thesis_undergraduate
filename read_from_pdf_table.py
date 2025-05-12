import pymysql
from configs.database_config import *


# 数据库连接函数
def get_mysql_connection():
    return pymysql.connect(
        host=MYSQL_HOST,
        port=int(MYSQL_PORT),
        user=MYSQL_USER,
        password=MYSQL_PW,
        database=MYSQL_DB
    )

# 获取所有 PDF 信息
def get_all_pdfs():
    conn = get_mysql_connection()
    try:
        with conn.cursor(pymysql.cursors.DictCursor) as cursor:
            sql = f"SELECT * FROM {MYSQL_PDF_TABLE}"
            cursor.execute(sql)
            return cursor.fetchall()
    finally:
        conn.close()

# 示例调用
pdfs = get_all_pdfs()
for pdf in pdfs:
    print(pdf)