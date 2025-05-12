# 安装 pypi 环境
```bash
pip install mysql pymysql flask
```
```sql
CREATE TABLE IF NOT EXISTS invitation_codes (
    id INT AUTO_INCREMENT PRIMARY KEY,
    code VARCHAR(255) NOT NULL UNIQUE,
    expiration_date DATETIME NOT NULL,
    max_uses INT NOT NULL,
    used_count INT DEFAULT 0
);
```

```sql
CREATE TABLE IF NOT EXISTS user_tb (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    email VARCHAR(100) UNIQUE,
    password VARCHAR(255) NOT NULL,
    role INT NOT NULL DEFAULT 0 COMMENT '用户角色：0-普通用户，-1-管理员',
    status INT NOT NULL DEFAULT 200 COMMENT '用户状态：200-正常，其他值可自定义（如400-禁用）',
    registration_time DATETIME DEFAULT CURRENT_TIMESTAMP,
    invitation_code VARCHAR(255) DEFAULT NULL
);
```

```sql
-- 修改用户status
UPDATE user_tb 
SET status = 3 
WHERE id = 1;
```

```sql
CREATE TABLE IF NOT EXISTS algorithm_templates (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    code TEXT NOT NULL,
    created_by VARCHAR(255) NOT NULL,
    created_at DATETIME NOT NULL
);
```

UPDATE invitation_codes 
SET used_count = 10 
WHERE id = 2;

```sql
-- 创建 ds_pdf 表
CREATE TABLE ds_pdf (
    -- 唯一标识，自增主键
    id INT AUTO_INCREMENT PRIMARY KEY,
    -- PDF 名称，不允许为空
    pdf_name VARCHAR(255) NOT NULL,
    -- PDF 路径，不允许为空
    pdf_path VARCHAR(255) NOT NULL,
    -- 上传时间，默认值为当前时间
    upload_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```