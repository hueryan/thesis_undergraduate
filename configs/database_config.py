from dotenv import dotenv_values
import os

# 获取当前脚本所在目录（即 configs 目录）
current_dir = os.path.dirname(os.path.abspath(__file__))
env_path = os.path.join(current_dir, "database_config.env")
mysql_configs = dotenv_values(env_path)


MYSQL_HOST = mysql_configs['MYSQL_HOST']
MYSQL_PORT = mysql_configs['MYSQL_PORT']
MYSQL_USER = mysql_configs['MYSQL_USER']
MYSQL_PW = mysql_configs['MYSQL_PW']
MYSQL_DB = mysql_configs['MYSQL_DB']
MYSQL_USER_TABLE = mysql_configs['MYSQL_USER_TABLE']
# 算法模板表
MYSQL_ALGORITHM_TEMPLATES_TABLE = mysql_configs['MYSQL_ALGORITHM_TEMPLATES_TABLE']
# 算法模板创建人
MYSQL_ALGORITHM_TEMPLATES_TABLE_CREATE_BY = mysql_configs['MYSQL_ALGORITHM_TEMPLATES_TABLE_CREATE_BY']
# 邀请码表
MYSQL_INVITATION_CODES_TABLE = mysql_configs['MYSQL_INVITATION_CODES_TABLE']
# 存储 pdf 表
MYSQL_PDF_TABLE = mysql_configs['MYSQL_PDF_TABLE']

DEEPSEEK_API_KEY = mysql_configs['DEEPSEEK_API_KEY']