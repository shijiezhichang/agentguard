FROM python:3.12-slim

WORKDIR /app

# 安装系统依赖
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# 复制依赖文件并安装
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 复制应用代码
COPY scan.py .
COPY web.py .

# 暴露端口
EXPOSE 8000

# 启动命令
CMD ["uvicorn", "web:app", "--host", "0.0.0.0", "--port", "8000"]
