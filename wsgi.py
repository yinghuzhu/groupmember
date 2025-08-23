import os
import sys

# 将app目录添加到Python路径中
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'app'))

from app.main import create_app

app = create_app()

if __name__ == "__main__":
    app.run()