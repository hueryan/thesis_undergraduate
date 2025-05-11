import os
import re
from datetime import datetime
import pymysql
from configs.database_config import *


def process_md_files(folder_path):
    # 调试信息
    print(f"\n=== 扫描文件夹：{folder_path} ===")
    print(f"初始文件列表：{os.listdir(folder_path)}\n")

    # 建立数据库连接
    try:
        connection = pymysql.connect(
            host=MYSQL_HOST,
            port=int(MYSQL_PORT),
            user=MYSQL_USER,
            password=MYSQL_PW,
            database=MYSQL_DB,
            charset='utf8mb4',
            cursorclass=pymysql.cursors.DictCursor
        )
        connection.ping(reconnect=True)
        print("✅ 数据库连接成功")
    except Exception as e:
        print(f"❌ 数据库连接失败：{str(e)}")
        return

    # 文件收集与排序逻辑
    file_entries = []
    duplicate_counter = {}  # 跟踪重复序号

    for filename in os.listdir(folder_path):
        # 增强正则表达式：允许文件名包含额外字符（如" - 副本"）
        match = re.match(r'^(\d+)\.\s*([\w\s-]+?)\.md$', filename)
        if not match:
            print(f"⚠️ 跳过无效文件：{filename}")
            continue

        num = int(match.group(1))
        name = match.group(2).strip()

        # 处理重复序号
        if num in duplicate_counter:
            print(f"⚠️ 发现重复序号 {num}：{filename}（已存在 {duplicate_counter[num]} 个文件）")
            duplicate_counter[num] += 1
        else:
            duplicate_counter[num] = 1

        file_entries.append((num, filename, name))

    # 按自然顺序排序（优先数字，其次文件名）
    file_entries.sort(key=lambda x: (x[0], x[1]))

    print("\n=== 排序后文件列表 ===")
    for entry in file_entries:
        print(f"序号 {entry[0]:>2}：{entry[1]}")

    # 处理文件
    for num, filename, name in file_entries:
        print(f"\n▶ 正在处理：{filename}（序号 {num}）")
        file_path = os.path.join(folder_path, filename)

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                code = f.read()
            print(f"内容长度：{len(code)}字节")
        except Exception as e:
            print(f"❌ 读取失败：{str(e)}")
            continue

        # 数据库操作
        try:
            with connection.cursor() as cursor:
                sql = f"""INSERT INTO {MYSQL_ALGORITHM_TEMPLATES_TABLE} 
                        (name, code, created_by, created_at)
                        VALUES (%s, %s, %s, %s)"""
                cursor.execute(sql, (name, code, MYSQL_ALGORITHM_TEMPLATES_TABLE_CREATE_BY, datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
            connection.commit()
            print(f"✅ 已插入：{name}")
        except pymysql.err.IntegrityError as e:
            connection.rollback()
            print(f"⚠️ 数据重复（可能原因：同名记录已存在）")
        except Exception as e:
            connection.rollback()
            print(f"❌ 插入失败：{str(e)}")

    connection.close()


if __name__ == "__main__":
    md_folder = "./算法模板/常用代码模板1"
    if not os.path.exists(md_folder):
        print(f"❌ 文件夹不存在：{md_folder}")
        exit(1)

    process_md_files(md_folder)