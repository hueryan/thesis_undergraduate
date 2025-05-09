import pymysql
import uuid
from datetime import datetime, timedelta
from database_config import MYSQL_HOST, MYSQL_PORT, MYSQL_USER, MYSQL_PW, MYSQL_DB, MYSQL_INVITATION_CODES_TABLE

# 连接到 MySQL 数据库
mydb = pymysql.connect(
    host=MYSQL_HOST,
    port=int(MYSQL_PORT),
    user=MYSQL_USER,
    password=MYSQL_PW,
    database=MYSQL_DB
)

mycursor = mydb.cursor()

def create_invitation_code(expiration_days, max_uses):
    # 生成唯一的邀请码
    code = str(uuid.uuid4())
    # 计算过期日期
    expiration_date = datetime.now() + timedelta(days=expiration_days)
    # 插入邀请码信息到数据库
    sql = f"INSERT INTO {MYSQL_INVITATION_CODES_TABLE} (code, expiration_date, max_uses) VALUES (%s, %s, %s)"
    val = (code, expiration_date, max_uses)
    mycursor.execute(sql, val)
    mydb.commit()
    print(f"邀请码 {code} 已创建，有效期至 {expiration_date}，最大使用次数为 {max_uses}。")

# 示例：创建一个有效期为 7 天，最大使用次数为 10 的邀请码
create_invitation_code(7, 10)

mycursor.close()
mydb.close()