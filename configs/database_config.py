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
MYSQL_ALGORITHM_TEMPLATES_TABLE = mysql_configs['MYSQL_ALGORITHM_TEMPLATES_TABLE']
MYSQL_INVITATION_CODES_TABLE = mysql_configs['MYSQL_INVITATION_CODES_TABLE']