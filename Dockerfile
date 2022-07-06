FROM python:3.10
COPY ./requirements.txt /app/
WORKDIR /app
RUN pip install -r requirements.txt
COPY ./ /app
ENV PYTHONUNBUFFERED 0
ENTRYPOINT ["python", "-u", "main.py"]