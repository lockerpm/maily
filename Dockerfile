FROM python:3.10-slim

WORKDIR /app

COPY ./src/ /app

COPY requirements.txt /app

RUN pip install -r requirements.txt

RUN groupadd -r cystack && useradd -r -g cystack -s /sbin/nologin -c "CyStack user" cystack

USER cystack

CMD ["python", "manage.py"]
