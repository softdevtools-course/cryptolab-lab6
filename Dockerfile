FROM python:3.12-slim@sha256:aa943ce411423c7582288f18707ff66eddcbaeb510502d747a72aeb34f30d159
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 CRYPTOLAB_DATA_DIR=/var/lib/cryptolab
WORKDIR /app
COPY pyproject.toml requirements-runtime.lock ./
COPY app ./app
COPY web ./web
COPY examples ./examples
RUN pip install --no-cache-dir -c requirements-runtime.lock . && useradd --uid 10001 --create-home cryptolab
USER 10001:10001
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1", "--no-proxy-headers"]
