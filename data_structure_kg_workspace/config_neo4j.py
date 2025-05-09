from dotenv import dotenv_values
import os

# 获取当前脚本所在目录（即 configs 目录）
current_dir = os.path.dirname(os.path.abspath(__file__))
env_path = os.path.join(current_dir, "neo4j.env")  # 指向 configs/database_config.env
configs = dotenv_values(env_path)

# 获取环境变量
NEO4J_URI = configs['NEO4J_URI']
NEO4J_USER = configs['NEO4J_USER']
NEO4J_PASSWORD = configs['NEO4J_PASSWORD']
NEO4J_LABEL = configs['NEO4J_LABEL']
IMAGE_PATH = configs['IMAGE_PATH']
DOUBAO_API_KEY = configs['DOUBAO_API_KEY']

# print(IMAGE_PATH.split('/')[-1].split('.png')[0])

# print(f"txt/{IMAGE_PATH.split('/')[-1].split('.png')[0]}.txt")
