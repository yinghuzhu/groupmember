import os
import sys

# 将 app 目录添加到 Python 路径中
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'app'))

from app.main import create_app

app = create_app()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))