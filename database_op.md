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
SET expiration_date = "2025-05-10 02:10:24" 
WHERE id = 2;