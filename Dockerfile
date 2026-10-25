FROM node:20-alpine
WORKDIR /scanner_praser
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . ./scanner_praser/
EXPOSE 5000
CMD ["python", "scanner_praser.py"]