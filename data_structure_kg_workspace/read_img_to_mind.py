import os
import base64
from openai import OpenAI
from config_neo4j import DOUBAO_API_KEY, IMAGE_PATH  # 从配置文件读取

client = OpenAI(
    base_url="https://ark.cn-beijing.volces.com/api/v3",
    api_key=DOUBAO_API_KEY,
)

def image_to_base64(image_path):
    """将本地图片转为Base64编码"""
    with open(image_path, "rb") as image_file:
        return base64.b64encode(image_file.read()).decode("utf-8")

def get_image_url(image_path):
    """示例：上传本地图片到临时存储并获取URL（需替换为实际存储服务）"""
    # 实际需使用OSS/COS等存储服务，此处仅演示Base64方式（豆包支持data URI）
    return f"data:image/png;base64,{image_to_base64(image_path)}"

def process_mindmap_with_doubao(image_path):
    try:
        # 生成有效图片输入（使用Base64 Data URI，避免URL依赖）
        image_data = get_image_url(image_path)

        response = client.chat.completions.create(
            model="doubao-1.5-vision-pro-250328",
            messages=[
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "image_url",
                            "image_url": {
                                "url": image_data  # 使用Base64数据或有效URL
                            }
                        },
                        {
                            "type": "text",
                            "text": "解析这张数据结构与算法的思维导图的节点关系，输出格式为：主节点→子节点→孙节点，每行一个关系。同时审查思维导图中的名词是否为数据结构学术用语，若存在非学术用语或错字，请指出并给出正确的术语。直接替换成正确的属于，无需标注出来。也不用最后的注释,但是你要看清楚了"

                        }
                    ]
                }
            ]
        )
        return response.choices[0].message.content
    except Exception as e:
        print(f"豆包模型调用错误: {e}")
        return None

if __name__ == "__main__":
    # 检查图片路径有效性
    if not os.path.exists(IMAGE_PATH):
        print(f"错误：图片文件不存在 - {IMAGE_PATH}")
    else:
        print("解析结果：")
        result = process_mindmap_with_doubao(IMAGE_PATH)
        if result:
            print(result)
            # FILE_NAME = f"{IMAGE_PATH.split('/')[-1].split('.png')[0]}"
            # with open(f"txt/{FILE_NAME}.txt", "w", encoding='utf-8') as f:
            #     f.write(result)
            # print(f"{FILE_NAME}保存成功")
        else:
            print("解析失败，请检查API密钥或图片内容。")
