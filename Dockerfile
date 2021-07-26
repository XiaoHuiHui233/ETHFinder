FROM python:3.8

RUN mkdir -p /app

WORKDIR /app

ADD requirements.txt /app/

RUN pip install -r requirements.txt

ADD dpt /app/

ADD rlpx /app/

ADD __init__.py /app/

ADD config.py /app/

ADD controller.py /app/

ADD main.py /app/

ENV PYTHONUNBUFFERED 0

ENTRYPOINT ["python", "-u", "main.py"]