FROM python:3.12.12-slim

WORKDIR /app

COPY ./src/ /app

COPY requirements.txt ./

RUN pip install -r requirements.txt

RUN groupadd -r cystack && useradd -r -g cystack -s /sbin/nologin -c "CyStack user" cystack

USER cystack

CMD ["python", "manage.py"]
