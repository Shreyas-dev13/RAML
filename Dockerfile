FROM python:3.13-slim

RUN apt-get update -y && apt-get upgrade -y

RUN apt-get install -y wget openjdk-21-jre-headless

RUN pip install uv

WORKDIR /app

COPY uv.lock .

COPY pyproject.toml .

RUN uv sync

COPY scripts scripts

RUN chmod +x ./scripts/install_apktool.sh

RUN chmod +x ./scripts/start.sh

RUN ./scripts/install_apktool.sh

COPY src src

ENTRYPOINT [ "./scripts/start.sh" ]
