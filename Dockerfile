FROM python:3.12-slim
WORKDIR /scanner_praser
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . ./scanner_praser/
EXPOSE 5000
CMD ["python", "scanner_praser.py"]