FROM python:3-alpine

WORKDIR CMSeeK

RUN apk add --no-cache git py3-pip && git clone https://github.com/Tuhinshubhra/CMSeeK

RUN pip install -r CMSeeK/requirements.txt

COPY ./server.py .
ENTRYPOINT [ "python", "server.py" ]
