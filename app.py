from configs.database_config import MYSQL_HOST, MYSQL_PORT, MYSQL_USER, MYSQL_PW, MYSQL_DB, MYSQL_USER_TABLE, MYSQL_INVITATION_CODES_TABLE, MYSQL_ALGORITHM_TEMPLATES_TABLE
from data_structure_kg_workspace.config_neo4j import NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD
from flask import Flask, render_template, request, redirect, url_for, flash, session
from dotenv import load_dotenv
from datetime import datetime
from neo4j import GraphDatabase
import pymysql
import hashlib  # 用于密码哈希
import secrets
import re
import os
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
        # 获取页码，默认为第 1 页
        page = int(request.args.get('page', 1))
        per_page = 6
        offset = (page - 1) * per_page

        # 从数据库获取算法模板数据
        with get_mysql_connection() as conn:
            with conn.cursor() as cursor:
                # 查询总记录数
                sql_count = f"SELECT COUNT(*) as total FROM {MYSQL_ALGORITHM_TEMPLATES_TABLE}"
                cursor.execute(sql_count)
                total = cursor.fetchone()['total']

                # 查询当前页的数据
                sql = f"SELECT * FROM {MYSQL_ALGORITHM_TEMPLATES_TABLE} ORDER BY created_at DESC LIMIT {offset}, {per_page}"
                cursor.execute(sql)
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
        total_pages = (total + per_page - 1) // per_page
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
                                   pagination=pagination)
        else:
            # 返回完整页面
            return render_template('main.html',
                                   algorithm_templates=algorithm_templates,
                                   pagination=pagination)

    except Exception as e:
        flash(f'获取算法模板数据失败: {str(e)}', 'error')
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
    offset = (page - 1) * per_page

    # 根据排序参数构建 SQL 查询
    if sort == 'asc':
        order_by = 'ORDER BY id ASC'
    else:
        order_by = 'ORDER BY id DESC'

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

            # 查询当前页的数据
            sql = f"SELECT * {base_sql} {order_by} LIMIT {offset}, {per_page}"
            cursor.execute(sql, params)
            templates = cursor.fetchall()

    # 计算分页信息
    total_pages = (total + per_page - 1) // per_page
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

if __name__ == '__main__':
    app.run(debug=True)