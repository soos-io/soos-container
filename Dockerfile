FROM aquasec/trivy:0.34.0 as BASE

COPY ./src ./
COPY ./VERSION.txt ./requirements.txt ./

ENV PYTHONUNBUFFERED=1
RUN apk add --update --no-cache python3 && ln -sf python3 /usr/bin/python
RUN python3 -m ensurepip
RUN pip3 install --no-cache --upgrade pip setuptools
RUN pip3 install -r requirements.txt



ENTRYPOINT ["python3", "main.py"]