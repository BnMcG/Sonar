FROM python:3
ENV PYTHONUNBUFFERED 1
RUN mkdir /sonar
WORKDIR /sonar
COPY requirements.txt /sonar/
RUN pip install -r requirements.txt
COPY . /sonar/
CMD python3 -m sonar.listener
