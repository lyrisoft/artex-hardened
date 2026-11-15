FROM python:3.12-alpine
WORKDIR /srv
COPY security/llm-broker/broker.py /srv/broker.py
USER 65532:65532
EXPOSE 8899
CMD ["python3","-u","/srv/broker.py"]
