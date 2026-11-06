FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 HOME=/home/app TZ=Asia/Vladivostok
RUN apt-get update && apt-get install -y --no-install-recommends openssh-client ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
RUN groupadd -g 10001 app && useradd -u 10001 -g app -M app
COPY app ./app
COPY recovery_app.py ./
USER 10001:10001
CMD ["uvicorn","recovery_app:app","--host","127.0.0.1","--port","8003","--workers","1","--no-proxy-headers"]
