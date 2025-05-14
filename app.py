from json import JSONDecodeError
import sys
import os
import asyncio
import json
import logging
# 获取当前脚本所在目录
current_dir = os.path.dirname(os.path.abspath(__file__))
# 构建 milvus_manager.py等 所在目录的路径
pdf_knowledge_chat_dir = os.path.join(current_dir, 'pdf_knowledge_chat')
# 将该目录添加到 Python 路径中
sys.path.append(pdf_knowledge_chat_dir)

import urllib
from configs.database_config import MYSQL_HOST, MYSQL_PORT, MYSQL_USER, MYSQL_PW, MYSQL_DB, MYSQL_USER_TABLE, MYSQL_INVITATION_CODES_TABLE, MYSQL_ALGORITHM_TEMPLATES_TABLE, DEEPSEEK_API_KEY, MYSQL_PDF_TABLE, MYSQL_USER_KNOWLEDGE_SCORES
from data_structure_kg_workspace.config_neo4j import NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_from_directory
from pdf_knowledge_chat.chat_session import ChatSession
from dotenv import load_dotenv
from datetime import datetime
from neo4j import GraphDatabase
from langchain_openai import ChatOpenAI
import pymysql
import hashlib  # 用于密码哈希
import secrets
import re
import os
from flask import send_file
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

# 无限缓存装饰器
def unlimited_cache(func):
    cache = {}
    async def wrapper(*args, **kwargs):
        key = (args, tuple(sorted(kwargs.items())))
        if key not in cache:
            cache[key] = await func(*args, **kwargs)
        return cache[key]
    return wrapper

# 密码哈希函数
def hash_password(password):
    return hashlib.sha256(password.encode('utf-8')).hexdigest()


# 首页路由
@app.route('/')
def index():
    return render_template('index.html')


# 登录路由 - 处理 GET 和 POST 请求
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # 对输入的密码进行哈希处理
        hashed_password = hash_password(password)

        try:
            # 使用 get_mysql_connection 函数获取连接，确保使用字典游标
            connection = get_mysql_connection()
            with connection.cursor() as cursor:
                # 查询用户信息
                check_user_sql = f"SELECT * FROM {MYSQL_USER_TABLE} WHERE username = %s"
                cursor.execute(check_user_sql, (username,))
                user = cursor.fetchone()

                if user:
                    # 用户存在，检查密码和状态
                    # 通过字段名访问密码，而不是索引位置
                    if user['password'] == hashed_password:  # 密码匹配
                        if user['status'] == 200:  # 状态为 200
                            session['user_id'] = user['id']
                            session['user'] = username
                            role = user['role']
                            session['role'] = role
                            if role == -1:
                                flash('欢迎管理员登录系统', 'success')
                            elif role == 0:
                                flash('欢迎用户登录系统', 'success')
                            return redirect(url_for('main') + '?login_success=true')
                        else:  # 状态非 200
                            flash('该用户已被禁用，请联系管理员', 'error')
                    else:  # 密码不匹配
                        flash('密码错误', 'error')
                else:  # 用户不存在
                    flash('用户不存在，请注册', 'error')

                return render_template('login.html', username=username)
        except pymysql.Error as e:
            flash(f'登录失败，错误信息: {str(e)}', 'error')
            return render_template('login.html', username=username)
        finally:
            if 'connection' in locals() and connection:
                connection.close()
    return render_template('login.html')


# 邀请码表操作
def validate_invitation_code(code):
    with get_mysql_connection() as conn:
        with conn.cursor() as cursor:
            sql = f"SELECT * FROM {MYSQL_INVITATION_CODES_TABLE} WHERE code = %s AND expiration_date > NOW() AND used_count < max_uses"
            cursor.execute(sql, (code,))
            return cursor.fetchone()


def increment_invitation_usage(code):
    with get_mysql_connection() as conn:
        with conn.cursor() as cursor:
            sql = f"UPDATE {MYSQL_INVITATION_CODES_TABLE} SET used_count = used_count + 1 WHERE code = %s"
            cursor.execute(sql, (code,))
            conn.commit()


# 注册路由 - 处理 GET 和 POST 请求
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        invitation_code = request.form.get('invitation_code', '')

        # 表单验证
        errors = {}

        # 用户名验证 (8-16 位，必须包含字母和数字)
        if not re.match(r'^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,16}$', username):
            errors['username'] = '用户名必须包含字母和数字，长度为 8-16 位'

        # 邮箱验证
        if not re.match(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$', email):
            errors['email'] = '请输入有效的邮箱地址'

        # 密码验证 (至少 8 位，至少包含两项：字母、数字、特殊字符)
        if len(password) < 8:
            errors['password'] = '密码长度至少 8 位'
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
                    if existing_user.get('username') == username and existing_user.get('email') != email:
                        errors['username'] = '用户名已存在'
                    elif existing_user.get('email') == email and existing_user.get('username') != username:
                        errors['email'] = '邮箱已被注册'
                    elif existing_user.get('email') == email and existing_user.get('username') == username:
                        errors['user_email'] = '用户名已存在，邮箱已被注册'

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
    # 清除所有 session 变量
    session.clear()
    flash('已成功注销')
    return redirect(url_for('login'))


# 主页面路由
@app.route('/main')
def main():
    # 确保用户已登录
    if not is_user_logged_in():
        flash('请先登录')
        return redirect(url_for('login'))

    # 渲染主页面模板
    return render_template('main.html')


# 重置密码路由 - 处理 GET 和 POST 请求
@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    # 确保用户已登录
    if not is_user_logged_in():
        flash('请先登录')
        return redirect(url_for('login'))

    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        errors = {}

        # 验证当前密码
        user_id = session.get('user_id')
        with get_mysql_connection() as conn:
            with conn.cursor() as cursor:
                sql = f"SELECT password FROM {MYSQL_USER_TABLE} WHERE id = %s"
                cursor.execute(sql, (user_id,))
                result = cursor.fetchone()

                if not result or result['password'] != hash_password(current_password):
                    errors['current_password'] = '当前密码不正确'

        # 验证新密码
        if len(new_password) < 8:
            errors['new_password'] = '新密码长度至少 8 位'
        elif not (
                (any(c.isalpha() for c in new_password) and any(c.isdigit() for c in new_password)) or
                (any(c.isalpha() for c in new_password) and any(not c.isalnum() for c in new_password)) or
                (any(c.isdigit() for c in new_password) and any(not c.isalnum() for c in new_password))
        ):
            errors['new_password'] = '新密码必须包含字母、数字、特殊字符中的至少两项'

        # 验证确认密码
        if new_password != confirm_password:
            errors['confirm_password'] = '两次输入的密码不一致'

        if errors:
            for field, msg in errors.items():
                flash(msg, field)
            return redirect(url_for('change_password'))

        # 更新密码
        with get_mysql_connection() as conn:
            with conn.cursor() as cursor:
                sql = f"UPDATE {MYSQL_USER_TABLE} SET password = %s WHERE id = %s"
                cursor.execute(sql, (hash_password(new_password), user_id))
                conn.commit()

        flash('密码更新成功，请使用新密码登录', 'success')
        return redirect(url_for('logout'))

    # 移除对 AJAX 请求的特殊处理，直接返回完整页面
    return render_template('change_password.html')


@app.route('/main/knowledge-graph')
def knowledge_graph():
    # 确保用户已登录
    if not is_user_logged_in():
        flash('请先登录')
        return redirect(url_for('login'))

    try:
        # 连接到 Neo4j 数据库
        with driver.session() as session:
            # Cypher 查询：获取末端节点（没有出边的节点）及其完整路径
            query = """
            MATCH path=(root)-[*0..]->(endNode)
            WHERE NOT (endNode)-->()  // 只选择没有出边的节点
            WITH endNode, collect(path) as paths, rand() as random
            ORDER BY random
            LIMIT 9  // 随机选择 9 个末端节点
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
                node_id = node.element_id
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

            # 判断是否是 AJAX 请求
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                # 只返回内容片段
                return render_template('node_show.html', leaf_nodes=leaf_nodes)
            else:
                # 返回完整页面
                return render_template('main.html', leaf_nodes=leaf_nodes)

    except Exception as e:
        flash(f'获取知识图谱数据失败: {str(e)}', 'error')
        return redirect(url_for('main'))


@app.route('/main/algorithm-templates')
def algorithm_templates():
    # 确保用户已登录
    if not is_user_logged_in():
        flash('请先登录')
        return redirect(url_for('login'))

    try:
        # 获取排序参数，默认为按 created_at 降序
        sort = request.args.get('sort', 'desc')

        # 获取搜索关键字
        search_query = request.args.get('search', '').strip()

        # 获取页码，默认为第 1 页
        page = int(request.args.get('page', 1))
        per_page = 6

        # 从数据库获取算法模板数据
        with get_mysql_connection() as conn:
            with conn.cursor() as cursor:
                # 构建基础 SQL 查询
                base_sql = f"FROM {MYSQL_ALGORITHM_TEMPLATES_TABLE}"

                # 添加搜索条件
                if search_query:
                    base_sql += " WHERE name LIKE %s"
                    search_param = f"%{search_query}%"
                    params = (search_param,)
                else:
                    params = ()

                # 查询总记录数
                sql_count = f"SELECT COUNT(*) as total {base_sql}"
                cursor.execute(sql_count, params)
                total = cursor.fetchone()['total']

                # 计算总页数
                total_pages = (total + per_page - 1) // per_page

                # 验证页码
                if page < 1:
                    page = 1
                elif page > total_pages:
                    page = total_pages
                    # 重定向到更新后的 URL
                    return redirect(url_for('algorithm_templates', sort=sort, search=search_query, page=page))

                offset = (page - 1) * per_page

                # 根据排序参数构建 SQL 查询
                if sort == 'asc':
                    order_by = 'ORDER BY id ASC'
                elif sort == 'desc':
                    order_by = 'ORDER BY id DESC'
                else:
                    order_by = 'ORDER BY created_at DESC'

                # 查询当前页的数据
                sql = f"SELECT * {base_sql} {order_by} LIMIT {offset}, {per_page}"
                cursor.execute(sql, params)
                algorithm_templates = cursor.fetchall()
                # 动态提取语言名称
                for template in algorithm_templates:
                    code = template['code']
                    # 使用正则匹配代码块开头的语言声明
                    match = re.search(r'^```([^\s`]+)', code, re.MULTILINE)  # 允许非空白和非反引号字符
                    if match:
                        lang = match.group(1).lower()
                        # 特殊处理常见语言
                        if lang in ['c++', 'cpp']:
                            template['language'] = 'C++'
                        elif lang == 'csharp':
                            template['language'] = 'C#'
                        else:
                            # 首字母大写，保留其他字符
                            template['language'] = lang.capitalize()
                    else:
                        # 备用匹配：注释中的语言声明
                        alt_match = re.search(r'#\s*language:\s*([^\s#]+)', code, re.IGNORECASE)
                        if alt_match:
                            lang = alt_match.group(1).lower()
                            if lang in ['c++', 'cpp']:
                                template['language'] = 'C++'
                            elif lang == 'csharp':
                                template['language'] = 'C#'
                            else:
                                template['language'] = lang.capitalize()
                        else:
                            template['language'] = 'Unknown'

        # 计算分页信息
        has_prev = page > 1
        has_next = page < total_pages
        prev_num = page - 1 if has_prev else None
        next_num = page + 1 if has_next else None

        pagination = {
            'page': page,
            'per_page': per_page,
            'total': total,
            'pages': total_pages,
            'has_prev': has_prev,
            'has_next': has_next,
            'prev_num': prev_num,
            'next_num': next_num,
            'offset': offset  # 添加offset用于显示
        }

        # 判断是否是AJAX请求或者请求部分内容
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.args.get('partial'):
            # 只返回内容片段
            return render_template('algorithm_templates_list.html',
                                   algorithm_templates=algorithm_templates,
                                   pagination=pagination,
                                   sort=sort,
                                   search_query=search_query)
        else:
            # 返回完整页面
            return render_template('main.html',
                                   algorithm_templates=algorithm_templates,
                                   pagination=pagination,
                                   sort=sort,
                                   search_query=search_query)

    except Exception as e:
        flash(f'获取算法模板数据失败: {str(e)}', 'error')
        return redirect(url_for('main'))


@app.route('/main/algorithm-templates/<int:template_id>')
def view_algorithm_template(template_id):
    # 验证普通用户权限
    if not is_user_logged_in():
        flash('请先登录', 'error')
        return redirect(url_for('login'))

    # 获取模板数据
    template = get_algorithm_template(template_id)
    if not template:
        flash('模板不存在', 'error')
        return redirect(url_for('algorithm_templates'))

    # 动态识别代码语言
    code = template['code']
    match = re.search(r'^```([^\s`]+)', code, re.MULTILINE)
    if match:
        lang = match.group(1).lower()
        # 统一语言标识
        if lang in ['c++', 'cpp']:
            lang = 'cpp'
        elif lang == 'csharp':
            lang = 'csharp'
        template['language'] = lang
    else:
        template['language'] = 'plaintext'

    return render_template('algorithm_template_view.html', template=template)

@app.route('/main/algorithm-templates/random')
def random_algorithm_templates():
    # 确保用户已登录
    if not is_user_logged_in():
        flash('请先登录')
        return redirect(url_for('login'))

    try:
        per_page = 6
        page = int(request.args.get('page', 1))

        # 获取或生成随机ID列表
        if 'random_ids' not in session or request.args.get('new') == 'true':
            with get_mysql_connection() as conn:
                with conn.cursor() as cursor:
                    cursor.execute(f"SELECT id FROM {MYSQL_ALGORITHM_TEMPLATES_TABLE} ORDER BY RAND()")
                    all_ids = [row['id'] for row in cursor.fetchall()]
                    session['random_ids'] = all_ids
                    session.modified = True
        else:
            all_ids = session.get('random_ids', [])

        # 计算总页数
        total = len(all_ids)
        total_pages = (total + per_page - 1) // per_page

        # 验证页码
        if page < 1:
            page = 1
            # 重定向到更新后的 URL
            return redirect(url_for('random_algorithm_templates', page=page, new=request.args.get('new')))
        elif page > total_pages:
            page = total_pages
            # 重定向到更新后的 URL
            return redirect(url_for('random_algorithm_templates', page=page, new=request.args.get('new')))

        offset = (page - 1) * per_page

        # 获取当前页的ID子集
        current_ids = all_ids[offset: offset + per_page]

        # 从数据库获取所有算法模板数据
        with get_mysql_connection() as conn:
            with conn.cursor() as cursor:
                placeholders = ', '.join(['%s'] * len(current_ids))
                # 随机选择数据
                sql = f"SELECT * FROM {MYSQL_ALGORITHM_TEMPLATES_TABLE} WHERE id IN ({placeholders}) ORDER BY FIELD(id, {placeholders})"
                cursor.execute(sql, current_ids + current_ids)
                algorithm_templates = cursor.fetchall()

                # 动态提取语言名称
                for template in algorithm_templates:
                    code = template['code']
                    # 使用正则匹配代码块开头的语言声明
                    match = re.search(r'^```([^\s`]+)', code, re.MULTILINE)  # 允许非空白和非反引号字符
                    if match:
                        lang = match.group(1).lower()
                        # 特殊处理常见语言
                        if lang in ['c++', 'cpp']:
                            template['language'] = 'C++'
                        elif lang == 'csharp':
                            template['language'] = 'C#'
                        else:
                            # 首字母大写，保留其他字符
                            template['language'] = lang.capitalize()
                    else:
                        # 备用匹配：注释中的语言声明
                        alt_match = re.search(r'#\s*language:\s*([^\s#]+)', code, re.IGNORECASE)
                        if alt_match:
                            lang = alt_match.group(1).lower()
                            if lang in ['c++', 'cpp']:
                                template['language'] = 'C++'
                            elif lang == 'csharp':
                                template['language'] = 'C#'
                            else:
                                template['language'] = lang.capitalize()
                        else:
                            template['language'] = 'Unknown'

        # 计算分页信息
        pagination = {
            'page': page,
            'per_page': per_page,
            'total': total,
            'pages': total_pages,
            'has_prev': page > 1,
            'has_next': page < total_pages,
            'prev_num': page - 1 if page > 1 else None,
            'next_num': page + 1 if page < total_pages else None,
            'offset': offset
        }

        # 判断是否是AJAX请求或者请求部分内容
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.args.get('partial'):
            # 只返回内容片段
            return render_template('algorithm_templates_list.html',
                                   algorithm_templates=algorithm_templates,
                                   pagination=pagination,
                                   sort=None,
                                   is_random=True)  # 添加is_random参数
        else:
            # 返回完整页面
            return render_template('main.html',
                                   algorithm_templates=algorithm_templates,
                                   pagination=pagination,
                                   sort=None,
                                   is_random=True)

    except Exception as e:
        flash(f'获取随机算法模板数据失败: {str(e)}', 'error')
        return redirect(url_for('main'))


def create_algorithm_template(name, code, created_by):
    """创建新的算法模板"""
    with get_mysql_connection() as conn:
        with conn.cursor() as cursor:
            sql = f"INSERT INTO {MYSQL_ALGORITHM_TEMPLATES_TABLE} (name, code, created_by, created_at) VALUES (%s, %s, %s, %s)"
            cursor.execute(sql, (name, code, created_by, datetime.now()))
            conn.commit()
            return cursor.lastrowid


def get_algorithm_template(template_id):
    """获取单个算法模板"""
    with get_mysql_connection() as conn:
        with conn.cursor() as cursor:
            sql = f"SELECT * FROM {MYSQL_ALGORITHM_TEMPLATES_TABLE} WHERE id = %s"
            cursor.execute(sql, (template_id,))
            return cursor.fetchone()


def get_all_algorithm_templates():
    """获取所有算法模板"""
    with get_mysql_connection() as conn:
        with conn.cursor() as cursor:
            sql = f"SELECT * FROM {MYSQL_ALGORITHM_TEMPLATES_TABLE} ORDER BY created_at DESC"
            cursor.execute(sql)
            return cursor.fetchall()



@app.route('/admin/algorithm-templates', methods=['GET'])
def admin_algorithm_templates():
    """管理员查看所有算法模板"""
    if not is_user_logged_in() or session.get('role') != -1:
        flash('权限不足', 'error')
        return redirect(url_for('main'))

    # 获取搜索参数
    search_query = request.args.get('search', '').strip()

    # 获取排序参数，默认为按 ID 降序
    sort = request.args.get('sort', 'desc')

    # 获取页码，默认为第 1 页
    page = int(request.args.get('page', 1))
    per_page = 8

    with get_mysql_connection() as conn:
        with conn.cursor() as cursor:
            # 构建基础 SQL 查询
            base_sql = f"FROM {MYSQL_ALGORITHM_TEMPLATES_TABLE}"

            # 添加搜索条件
            if search_query:
                base_sql += " WHERE name LIKE %s"
                search_param = f"%{search_query}%"
                params = (search_param,)
            else:
                params = ()

            # 查询总记录数
            sql_count = f"SELECT COUNT(*) as total {base_sql}"
            cursor.execute(sql_count, params)
            total = cursor.fetchone()['total']

            # 计算总页数
            total_pages = (total + per_page - 1) // per_page

            # 验证页码
            if page < 1:
                page = 1
            elif page > total_pages:
                page = total_pages

            offset = (page - 1) * per_page

            # 根据排序参数构建 SQL 查询
            if sort == 'asc':
                order_by = 'ORDER BY id ASC'
            else:
                order_by = 'ORDER BY id DESC'

            # 查询当前页的数据
            sql = f"SELECT * {base_sql} {order_by} LIMIT {offset}, {per_page}"
            cursor.execute(sql, params)
            templates = cursor.fetchall()

    # 计算分页信息
    has_prev = page > 1
    has_next = page < total_pages
    prev_num = page - 1 if has_prev else None
    next_num = page + 1 if has_next else None

    pagination = {
        'page': page,
        'per_page': per_page,
        'total': total,
        'pages': total_pages,
        'has_prev': has_prev,
        'has_next': has_next,
        'prev_num': prev_num,
        'next_num': next_num
    }

    return render_template('admin/algorithm_templates_list.html',
                           templates=templates,
                           pagination=pagination,
                           sort=sort,
                           search_query=search_query)


@app.route('/admin/algorithm-templates/new', methods=['GET', 'POST'])
def admin_create_algorithm_template():
    """管理员创建新算法模板"""
    if not is_user_logged_in() or session.get('role') != -1:
        flash('权限不足', 'error')
        return redirect(url_for('main'))

    if request.method == 'POST':
        name = request.form.get('name')
        code = request.form.get('code')
        created_by = session.get('user')

        if not name or not code:
            flash('名称和代码不能为空', 'error')
            return redirect(request.url)

        create_algorithm_template(name, code, created_by)
        flash('算法模板创建成功', 'success')
        return redirect(url_for('admin_algorithm_templates'))

    return render_template('admin/algorithm_template_form.html')


@app.route('/admin')
def admin_index():
    # 确保用户已登录且为管理员
    if not is_user_logged_in() or session.get('role') != -1:
        flash('权限不足', 'error')
        return redirect(url_for('main'))
    return render_template('admin/admin_index.html')


@app.route('/admin/algorithm-templates/<int:template_id>', methods=['GET'])
def admin_view_algorithm_template(template_id):
    """管理员查看算法模板详情"""
    if not is_user_logged_in() or session.get('role') != -1:
        flash('权限不足', 'error')
        return redirect(url_for('main'))

    template = get_algorithm_template(template_id)
    if not template:
        flash('模板不存在', 'error')
        return redirect(url_for('admin_algorithm_templates'))
    # template.code 已经包含了从数据库中获取的内容

    return render_template('admin/algorithm_template_view.html', template=template)


def update_algorithm_template(template_id, name, code):
    """更新算法模板"""
    with get_mysql_connection() as conn:
        with conn.cursor() as cursor:
            sql = f"UPDATE {MYSQL_ALGORITHM_TEMPLATES_TABLE} SET name = %s, code = %s WHERE id = %s"
            cursor.execute(sql, (name, code, template_id))
            conn.commit()


@app.route('/admin/algorithm-templates/<int:template_id>/edit', methods=['GET', 'POST'])
def admin_edit_algorithm_template(template_id):
    """管理员编辑算法模板"""
    if not is_user_logged_in() or session.get('role') != -1:
        flash('权限不足', 'error')
        return redirect(url_for('main'))

    template = get_algorithm_template(template_id)
    if not template:
        flash('模板不存在', 'error')
        return redirect(url_for('admin_algorithm_templates'))

    # 检查当前用户是否为创建者
    if template['created_by'] != session.get('user'):
        flash('你不是该模板的创建者，无权修改', 'error')
        return redirect(url_for('admin_algorithm_templates'))

    if request.method == 'POST':
        name = request.form.get('name')
        code = request.form.get('code')

        if not name or not code:
            flash('名称和代码不能为空', 'error')
            return redirect(request.url)

        update_algorithm_template(template_id, name, code)
        flash('算法模板更新成功', 'success')
        return redirect(url_for('admin_algorithm_templates'))

    return render_template('admin/algorithm_template_edit.html', template=template)


# 管理员查看用户知识掌握程度打分
@app.route('/admin/user-knowledge-scores', methods=['GET'])
def admin_user_knowledge_scores():
    if not is_user_logged_in() or session.get('role') != -1:
        flash('权限不足', 'error')
        return redirect(url_for('main'))

    search_query = request.args.get('search', '').strip()
    page = int(request.args.get('page', 1))
    per_page = 8

    with get_mysql_connection() as conn:
        with conn.cursor() as cursor:
            base_sql = f"FROM {MYSQL_USER_KNOWLEDGE_SCORES} JOIN {MYSQL_USER_TABLE} ON {MYSQL_USER_KNOWLEDGE_SCORES}.user_id = {MYSQL_USER_TABLE}.id"

            if search_query:
                base_sql += f" WHERE {MYSQL_USER_TABLE}.username LIKE %s"
                search_param = f"%{search_query}%"
                params = (search_param,)
            else:
                params = ()

            sql_count = f"SELECT COUNT(*) as total {base_sql}"
            cursor.execute(sql_count, params)
            total = cursor.fetchone()['total']

            total_pages = (total + per_page - 1) // per_page

            if page < 1:
                page = 1
            elif page > total_pages:
                page = total_pages

            offset = (page - 1) * per_page
            # 确保 offset 不会为负数
            offset = max(0, offset)

            sql = f"SELECT {MYSQL_USER_KNOWLEDGE_SCORES}.*, {MYSQL_USER_TABLE}.username {base_sql} ORDER BY {MYSQL_USER_KNOWLEDGE_SCORES}.id DESC LIMIT {offset}, {per_page}"
            cursor.execute(sql, params)
            scores = cursor.fetchall()

    has_prev = page > 1
    has_next = page < total_pages
    prev_num = page - 1 if has_prev else None
    next_num = page + 1 if has_next else None

    pagination = {
        'page': page,
        'per_page': per_page,
        'total': total,
        'pages': total_pages,
        'has_prev': has_prev,
        'has_next': has_next,
        'prev_num': prev_num,
        'next_num': next_num
    }

    return render_template('admin/user_knowledge_scores_list.html',
                           scores=scores,
                           pagination=pagination,
                           search_query=search_query)

# 新增函数：调用大模型进行知识评分
async def async_call_large_model_to_score_knowledge(question):
    llm = ChatOpenAI(
        openai_api_base="https://api.deepseek.com/v1",
        openai_api_key=DEEPSEEK_API_KEY,
        model_name="deepseek-chat"
    )
    prompt = f"""
    请根据以下用户提问，对用户的数据结构知识进行打分。要求：
    1. 仅对提问涉及的知识点评分
    2. 输出严格JSON格式如 {{"树":85}}
    3. 有效模块：链表、树、图、栈、队列、哈希表、堆
    4. 根据问题客观的给出分数，必须客观的打分，我要用这个去记录学生对知识的掌握程度，方便学生后续学习

    用户提问：{question}
    """
    try:
        response = await asyncio.to_thread(llm.invoke, prompt)
        json_str = re.search(r'\{.*?\}', response.content, re.DOTALL).group()
        scores = json.loads(json_str)
        valid_modules = {"链表", "树", "图", "栈", "队列", "哈希表", "堆"}
        return {k: min(max(int(v), 0), 100) for k, v in scores.items() if k in valid_modules}  # 分数限制在0-100
    except Exception as e:
        logging.error(f"评分失败: {str(e)}")
        return {}


@app.route('/main/chat', methods=['POST'])
async def chat():
    data = request.get_json()
    question = data.get('question')
    if not question:
        return jsonify({"error": "问题不能为空"}), 400

    # 获取当前评分（仅本次提问涉及的模块）
    new_scores = await async_call_large_model_to_score_knowledge(question)
    # if not new_scores:
    #     return jsonify({"error": "无法生成评分"}), 500

    user_id = session.get('user_id')
    if not user_id:
        return jsonify({"error": "未登录"}), 401

    all_scores = {}
    if new_scores:
        try:
            connection = get_mysql_connection()
            with connection.cursor() as cursor:
                connection.begin()

                # 检查用户记录是否存在
                cursor.execute(f"SELECT * FROM user_knowledge_scores WHERE user_id = %s", (user_id,))
                user_record = cursor.fetchone()

                if user_record:
                    # 更新现有记录
                    update_fields = []
                    values = []
                    for module, score in new_scores.items():
                        if module == '链表':
                            update_fields.append('linked_list = %s')
                        elif module == '树':
                            update_fields.append('tree = %s')
                        elif module == '图':
                            update_fields.append('graph = %s')
                        elif module == '栈':
                            update_fields.append('stack = %s')
                        elif module == '队列':
                            update_fields.append('queue = %s')
                        elif module == '哈希表':
                            update_fields.append('hash_table = %s')
                        elif module == '堆':
                            update_fields.append('heap = %s')
                        values.append(score)
                    values.append(user_id)

                    if update_fields:
                        update_sql = f"UPDATE user_knowledge_scores SET {', '.join(update_fields)} WHERE user_id = %s"
                        cursor.execute(update_sql, values)
                else:
                    # 插入新记录
                    columns = []
                    values = []
                    for module, score in new_scores.items():
                        if module == '链表':
                            columns.append('linked_list')
                        elif module == '树':
                            columns.append('tree')
                        elif module == '图':
                            columns.append('graph')
                        elif module == '栈':
                            columns.append('stack')
                        elif module == '队列':
                            columns.append('queue')
                        elif module == '哈希表':
                            columns.append('hash_table')
                        elif module == '堆':
                            columns.append('heap')
                        values.append(score)
                    columns.extend(['user_id'])
                    values.extend([user_id])

                    insert_sql = f"INSERT INTO user_knowledge_scores ({', '.join(columns)}) VALUES ({', '.join(['%s'] * len(values))})"
                    cursor.execute(insert_sql, values)

                connection.commit()

            # 获取更新后的全部分数
            with connection.cursor() as cursor:
                cursor.execute(
                    f"SELECT linked_list, tree, graph, stack, queue, hash_table, heap FROM user_knowledge_scores WHERE user_id = %s",
                    (user_id,)
                )
                all_scores = cursor.fetchone()
                if all_scores:
                    all_scores = {
                        '链表': all_scores['linked_list'],
                        '树': all_scores['tree'],
                        '图': all_scores['graph'],
                        '栈': all_scores['stack'],
                        '队列': all_scores['queue'],
                        '哈希表': all_scores['hash_table'],
                        '堆': all_scores['heap']
                    }
                else:
                    all_scores = {}

        except pymysql.Error as e:
            connection.rollback()
            logging.error(f"数据库错误: {str(e)}")
            return jsonify({"error": f"存储失败: {str(e)}"}), 500
        except Exception as e:
            logging.error(f"系统错误: {str(e)}")
            return jsonify({"error": "服务器内部错误"}), 500
        finally:
            connection.close()

    # 后续聊天逻辑
    chat_session = ChatSession()
    answer = chat_session.generate_answer(question)
    return jsonify({
        "answer": answer.replace('\n', '  \n'),
        "scores": all_scores
    })


@app.route('/main/chat-page')
def chat_page():
    if not is_user_logged_in():
        flash('请先登录')
        return redirect(url_for('login'))
    pdfId = 2
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return render_template('chat_rag_content.html', pdfId=pdfId)  # 创建内容片段模板
    return render_template('chat_rag.html', pdfId=pdfId)


@app.route('/get_pdf_path/<int:pdf_id>', methods=['GET'])
def get_pdf_path(pdf_id):
    if not is_user_logged_in():
        flash('请先登录')
        return redirect(url_for('login'))

    with get_mysql_connection() as conn:
        with conn.cursor() as cursor:
            sql = f"SELECT pdf_path FROM {MYSQL_PDF_TABLE} WHERE id = %s"
            cursor.execute(sql, (pdf_id,))
            result = cursor.fetchone()
            if result:
                pdf_path = result['pdf_path']
                full_path = os.path.join('data/pdf', os.path.basename(pdf_path))
                if os.path.exists(full_path):
                    return send_file(full_path, mimetype='application/pdf')
                else:
                    return jsonify({"error": "PDF 文件不存在"}), 404
            else:
                return jsonify({"error": "未找到对应的 PDF 文件"}), 404

@app.route('/public/<path:filename>')
def get_pdf(filename):
    return send_from_directory('public', filename)

# 获取算法模板通过ID
def get_algorithm_template_by_id(template_id):
    return get_algorithm_template(template_id)



# 调用大模型生成代码解释
@unlimited_cache
async def async_call_large_model_to_explain_code(code):
    # 初始化 DeepSeek 模型
    llm = ChatOpenAI(
        openai_api_base="https://api.deepseek.com/v1",
        openai_api_key=DEEPSEEK_API_KEY,
        model_name="deepseek-chat"
    )
    # 构建提示信息
    prompt = f"请解释以下代码：\n{code}"
    # 调用模型生成解释
    response = await asyncio.to_thread(llm.invoke, prompt)
    return response.content

# 分析算法复杂度
@unlimited_cache
async def async_call_large_model_toanalyze_algorithm_complexity(code):
    # 初始化 DeepSeek 模型
    llm = ChatOpenAI(
        openai_api_base="https://api.deepseek.com/v1",
        openai_api_key=DEEPSEEK_API_KEY,
        model_name="deepseek-chat"
    )
    # 构建提示信息
    prompt = f"请分析以下代码的时间复杂度和空间复杂度：\n{code}"
    # 调用模型生成复杂度分析
    response = await asyncio.to_thread(llm.invoke, prompt)
    return response.content

# 获取算法代码解释
async def async_get_algorithm_code_explanation(template_id):
    template = get_algorithm_template_by_id(template_id)
    if template:
        code = template['code']
        return await async_call_large_model_to_explain_code(code)
    return None

# 分析算法复杂度
async def async_analyze_algorithm_complexity(template_id):
    template = get_algorithm_template(template_id)
    if template:
        code = template['code']
        return await async_call_large_model_toanalyze_algorithm_complexity(code)
    return None



# 同时获取代码注释和复杂度分析
@app.route('/main/algorithm-templates/<int:template_id>/explanation-and-complexity', methods=['GET'])
async def get_algorithm_explanation_and_complexity(template_id):
    # 确保用户已登录
    if not is_user_logged_in():
        flash('请先登录')
        return redirect(url_for('login'))

    explanation_task = async_get_algorithm_code_explanation(template_id)
    complexity_task = async_analyze_algorithm_complexity(template_id)

    explanation, complexity = await asyncio.gather(explanation_task, complexity_task)

    if explanation and complexity:
        combined_md = f"### 代码注释\n{explanation}\n\n### 复杂度分析\n{complexity}"
        return jsonify({"explanation_and_complexity": combined_md})
    return jsonify({"error": "无法获取代码注释或复杂度分析"}), 404

# 调用大模型生成可执行例子
@unlimited_cache
async def async_call_large_model_to_generate_executable_example(code):
    # 初始化 DeepSeek 模型
    llm = ChatOpenAI(
        openai_api_base="https://api.deepseek.com/v1",
        openai_api_key=DEEPSEEK_API_KEY,
        model_name="deepseek-chat"
    )
    # 构建提示信息
    prompt = f"请根据以下算法代码给出一个可以直接执行的例子只生成可运行的代码，无需任何注释，注解：\n{code}"
    # 调用模型生成可执行例子
    response = await asyncio.to_thread(llm.invoke, prompt)
    return response.content

@unlimited_cache
async def async_call_large_model_to_generate_executable_example_explain(code):
    # 初始化 DeepSeek 模型
    llm = ChatOpenAI(
        openai_api_base="https://api.deepseek.com/v1",
        openai_api_key=DEEPSEEK_API_KEY,
        model_name="deepseek-chat"
    )
    # 构建提示信息
    prompt = f"请根据以下例子代码，直接代码中生成注释注解：\n{code}"
    # 调用模型生成可执行例子
    response = await asyncio.to_thread(llm.invoke, prompt)
    return response.content

# 获取算法可执行例子
async def async_get_algorithm_executable_example(template_id):
    template = get_algorithm_template_by_id(template_id)
    if template:
        code = template['code']
        return await async_call_large_model_to_generate_executable_example(code)
    return None

# 获取算法可执行例子和代码可视化
@app.route('/main/algorithm-templates/<int:template_id>/executable-example', methods=['GET'])
async def get_algorithm_executable_example(template_id):
    # 确保用户已登录
    if not is_user_logged_in():
        flash('请先登录')
        return redirect(url_for('login'))

    executable_example = await async_get_algorithm_executable_example(template_id)

    if executable_example:
        # 提取代码块的语言和内容
        code_match = re.search(
            r'```\s*?(\w+)?\s*?\n(.*?)```',  # 允许语言标识可选、前后空格
            executable_example,
            re.DOTALL | re.IGNORECASE  # 支持多行匹配且忽略大小写
        )
        if not code_match:
            # 尝试匹配无语言标识的代码块
            code_match = re.search(
                r'```\s*?\n(.*?)```',
                executable_example,
                re.DOTALL
            )
            if code_match:
                lang = 'plaintext'
                code_content = code_match.group(1).strip()
            else:
                return jsonify({"error": f"代码格式解析失败，原始内容：{executable_example[:100]}..."}), 400
        else:
            lang = (code_match.group(1) or 'plaintext').lower()
            code_content = code_match.group(2).strip()  # 去除首尾空格

        # 映射语言到Python Tutor环境
        lang_mapping = {
            'python': '3',
            'javascript': 'js',
            'java': 'java',
            'c': 'c',
            'cpp': 'cpp',
            'csharp': 'csharp'
        }
        tutor_lang = lang_mapping.get(lang, '3')  # 默认Python

        # 构建Python Tutor URL
        encoded_code = urllib.parse.quote_plus(code_content)

        tutor_url = f'https://pythontutor.com/iframe-embed.html#code={encoded_code}&codeDivHeight=800&codeDivWidth=600&cumulative=false&curInstr=3&heapPrimitives=nevernest&origin=opt-frontend.js&py={tutor_lang}&rawInputLstJSON=%5B%5D&textReferences=false'
        # tutor_url = f'https://pythontutor.com/iframe-embed.html#code={encoded_code}&cumulative=false&curInstr=3&heapPrimitives=nevernest&origin=opt-frontend.js&py={tutor_lang}&rawInputLstJSON=%5B%5D&textReferences=false'


        executable_example_explain = await async_call_large_model_to_generate_executable_example_explain(code_content)
        if executable_example_explain:
            # 提取代码块的语言和内容
            code_explain_match = re.search(
                r'```\s*?(\w+)?\s*?\n(.*?)```',  # 允许语言标识可选、前后空格
                executable_example_explain,
                re.DOTALL | re.IGNORECASE  # 支持多行匹配且忽略大小写
            )
            if not code_explain_match:
                # 尝试匹配无语言标识的代码块
                code_explain_match = re.search(
                    r'```\s*?\n(.*?)```',
                    executable_example_explain,
                    re.DOTALL
                )
                if code_explain_match:
                    lang = 'plaintext'
                    code_explain_content = code_explain_match.group(1).strip()
                else:
                    return jsonify({"error": f"代码格式解析失败，原始内容：{executable_example_explain[:100]}..."}), 400
            else:
                lang = (code_explain_match.group(1) or 'plaintext').lower()
                code_explain_content = code_explain_match.group(2).strip()  # 去除首尾空格

        return jsonify({
            "executable_example": code_explain_content,
            "tutor_url": tutor_url,
            "language": lang
        })

    return jsonify({"error": "无法获取可执行例子"}), 404

if __name__ == '__main__':
    app.run(debug=True)