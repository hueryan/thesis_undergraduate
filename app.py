from flask import Flask, render_template, request, redirect, url_for, flash, session
from configs.database_config import MYSQL_HOST, MYSQL_PORT, MYSQL_USER, MYSQL_PW, MYSQL_DB, MYSQL_USER_TABLE
from data_structure_kg_workspace.config_neo4j import NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD
import pymysql
import re
import os
from dotenv import load_dotenv
from neo4j import GraphDatabase
import secrets
from datetime import datetime
import hashlib  # 用于密码哈希

load_dotenv()

app = Flask(__name__)
# 优先从环境变量获取，不存在则生成临时密钥
app.secret_key = os.environ.get('FLASK_SECRET_KEY') or secrets.token_hex(24)

# 验证密钥是否有效
if not app.secret_key:
    raise ValueError("Secret key must be configured")

driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))


# 辅助函数：检查用户是否已登录
def is_user_logged_in():
    return 'user_id' in session


# 数据库连接函数
def get_mysql_connection():
    return pymysql.connect(
        host=MYSQL_HOST,
        port=int(MYSQL_PORT),
        user=MYSQL_USER,
        password=MYSQL_PW,
        database=MYSQL_DB,
        cursorclass=pymysql.cursors.DictCursor
    )


# 密码哈希函数
def hash_password(password):
    return hashlib.sha256(password.encode('utf-8')).hexdigest()


# 首页路由
@app.route('/')
def index():
    return render_template('index.html')


# 登录路由 - 处理GET和POST请求
# 登录路由 - 处理GET和POST请求
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # 对输入的密码进行哈希处理
        hashed_password = hash_password(password)

        try:
            connection = pymysql.connect(
                host=MYSQL_HOST,
                port=int(MYSQL_PORT),
                user=MYSQL_USER,
                password=MYSQL_PW,
                database=MYSQL_DB
            )
            with connection.cursor() as cursor:
                # 使用哈希后的密码进行查询
                select_sql = f"SELECT * FROM {MYSQL_USER_TABLE} WHERE username = %s AND password = %s AND status = 200"
                cursor.execute(select_sql, (username, hashed_password))
                user = cursor.fetchone()
                if user:
                    # 修正：设置session['user_id']
                    session['user_id'] = user[0]  # 假设user[0]是用户ID
                    session['user'] = username
                    role = user[4]
                    session['role'] = role
                    if role == -1:
                        flash('欢迎管理员登录系统', 'success')
                    elif role == 0:
                        flash('欢迎用户登录系统', 'success')
                    return redirect(url_for('main'))
                else:
                    check_user_sql = f"SELECT * FROM {MYSQL_USER_TABLE} WHERE username = %s"
                    cursor.execute(check_user_sql, (username,))
                    existing_user = cursor.fetchone()
                    if existing_user:
                        flash('该用户已被禁用，请联系管理员', 'error')
                    else:
                        flash('用户名或密码错误', 'error')
                    return render_template('login.html', username=username, password=password)
        except pymysql.Error as e:
            flash(f'登录失败，错误信息: {str(e)}', 'error')
            return render_template('login.html', username=username, password=password)
        finally:
            if 'connection' in locals() and connection:
                connection.close()
    return render_template('login.html')

# 邀请码表操作
def validate_invitation_code(code):
    with get_mysql_connection() as conn:
        with conn.cursor() as cursor:
            sql = "SELECT * FROM invitation_codes WHERE code = %s AND expiration_date > NOW() AND used_count < max_uses"
            cursor.execute(sql, (code,))
            return cursor.fetchone()

def increment_invitation_usage(code):
    with get_mysql_connection() as conn:
        with conn.cursor() as cursor:
            sql = "UPDATE invitation_codes SET used_count = used_count + 1 WHERE code = %s"
            cursor.execute(sql, (code,))
            conn.commit()

# 注册路由 - 处理GET和POST请求
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        invitation_code = request.form.get('invitation_code', '')

        # 表单验证
        errors = {}

        # 用户名验证 (8-16位，必须包含字母和数字)
        if not re.match(r'^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,16}$', username):
            errors['username'] = '用户名必须包含字母和数字，长度为8-16位'

        # 邮箱验证
        if not re.match(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$', email):
            errors['email'] = '请输入有效的邮箱地址'

        # 密码验证 (至少8位，至少包含两项：字母、数字、特殊字符)
        if len(password) < 8:
            errors['password'] = '密码长度至少8位'
        elif not (
                (any(c.isalpha() for c in password) and any(c.isdigit() for c in password)) or
                (any(c.isalpha() for c in password) and any(not c.isalnum() for c in password)) or
                (any(c.isdigit() for c in password) and any(not c.isalnum() for c in password))
        ):
            errors['password'] = '密码必须包含字母、数字、特殊字符中的至少两项'

        # 检查用户名和邮箱是否已存在
        with get_mysql_connection() as conn:
            with conn.cursor() as cursor:
                sql = f"SELECT username, email FROM {MYSQL_USER_TABLE} WHERE username = %s OR email = %s"
                cursor.execute(sql, (username, email))
                existing_user = cursor.fetchone()
                if existing_user:
                    if existing_user.get('username') == username:
                        errors['username'] = '用户名已存在'
                    if existing_user.get('email') == email:
                        errors['email'] = '邮箱已被注册'

        # 验证邀请码 (如果提供)
        if invitation_code:
            code_data = validate_invitation_code(invitation_code)
            if not code_data:
                errors['invitation_code'] = '无效的邀请码或已过期'

        if errors:
            for field, msg in errors.items():
                flash(msg, field)
            return redirect(url_for('register'))

        # 设置用户角色
        role = -1 if invitation_code else 0

        # 创建新用户
        with get_mysql_connection() as conn:
            with conn.cursor() as cursor:
                sql = f"INSERT INTO {MYSQL_USER_TABLE} (username, email, password, role, invitation_code, registration_time) VALUES (%s, %s, %s, %s, %s, %s)"
                cursor.execute(sql, (username, email, hash_password(password), role, invitation_code, datetime.now()))
                user_id = cursor.lastrowid
                conn.commit()

        # 如果使用了邀请码，增加使用次数
        if invitation_code:
            increment_invitation_usage(invitation_code)

        flash('注册成功，请登录')
        return redirect(url_for('login'))

    return render_template('register.html')


# 注销路由

@app.route('/logout')
def logout():
    # 清除所有session变量
    session.clear()
    flash('已成功注销')
    return redirect(url_for('index'))


# 主页面路由
@app.route('/main')
def main():
    # 确保用户已登录
    if not is_user_logged_in():
        flash('请先登录')
        return redirect(url_for('login'))
    
    # 渲染主页面模板
    return render_template('main.html')


# 从Neo4j获取随机节点的路由
@app.route('/main/knowledge-graph')
def knowledge_graph():
    # 确保用户已登录
    if not is_user_logged_in():
        flash('请先登录')
        return redirect(url_for('login'))

    try:
        # 连接到Neo4j数据库
        with driver.session() as session:
            # Cypher查询：获取末端节点（没有出边的节点）及其完整路径
            query = """
            MATCH path=(root)-[*0..]->(endNode)
            WHERE NOT (endNode)-->()  // 只选择没有出边的节点
            WITH endNode, collect(path) as paths, rand() as random
            ORDER BY random
            LIMIT 9  // 随机选择9个末端节点
            UNWIND paths as path
            WITH endNode, nodes(path) as pathNodes, relationships(path) as rels
            RETURN 
                endNode,
                [node in pathNodes | node.name] as pathNames,  // 节点名称列表
                [rel in rels | type(rel)] as relTypes  // 关系类型列表
            """

            # 执行查询
            results = session.run(query)

            # 处理结果
            leaf_nodes = []
            for record in results:
                node = record['endNode']
                path_names = record['pathNames']
                rel_types = record['relTypes']

                # 获取节点的基本信息
                node_id = node.id
                node_name = node.get('name', '未知名称')
                node_type = list(node.labels)[0] if node.labels else '未知类型'
                node_description = node.get('description', '无描述')

                # 构建路径信息，使用→连接节点名称
                path_info = "→".join(path_names) if path_names else "根节点"

                # 添加到节点列表
                leaf_nodes.append({
                    'id': node_id,
                    'name': node_name,
                    'type': node_type,
                    'description': node_description,
                    'path_info': path_info
                })

            # 渲染知识图谱页面，传递节点数据
            return render_template('node_show.html', leaf_nodes=leaf_nodes)

    except Exception as e:
        flash(f'获取知识图谱数据失败: {str(e)}', 'error')
        return redirect(url_for('main'))



# 运行应用
if __name__ == '__main__':
    app.run(debug=True)