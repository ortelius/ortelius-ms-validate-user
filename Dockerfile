FROM quay.io/ortelius/ms-python-base:flask-1.0

ENV DB_HOST localhost
ENV DB_NAME postgres
ENV DB_USER postgres
ENV DB_PASS postgres
ENV DB_POST 5432

WORKDIR /app

COPY main.py /app
COPY requirements.txt /app
RUN pip install -r requirements.txt; \
python -m pip uninstall -y pip;

#Run example:
# docker run -it -e DB_HOST=192.168.10.96 -e DB_PORT=6543 -p 6161:80 a0f1439236fb
