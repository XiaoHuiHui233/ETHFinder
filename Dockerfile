FROM python:3.9
COPY ./requirements.txt /app/
WORKDIR /app
RUN pip install -r requirements.txt
COPY ./ /app
EXPOSE 30303
ENV PYTHONUNBUFFERED 0
ENTRYPOINT ["python", "-u", "tests/nodedisc_v4_test.py"]