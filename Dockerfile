FROM python:3.11-slim

WORKDIR /app

COPY . .

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    build-essential \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN apt update && apt install ca-certificates -y
# posredni certyfikat keycloak
COPY security/keycloak_cert/26ddd22b46c9c44d5a694d39807e72ad.pem /usr/local/share/ca-certificates/certum_intermediate.crt
COPY security/keycloak_cert/444c0.pem /usr/local/share/ca-certificates/certum_root.crt
RUN update-ca-certificates

ENV REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt \
    SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt

RUN python -m pip install --upgrade pip

RUN pip install --no-cache-dir -r app/requirements.txt

# Create required directories for certificates and keys
RUN mkdir -p /etc/eudiw/pid-issuer-dev/cert/ \
    /etc/eudiw/pid-issuer-dev/privKey/ 
    
ENV FLASK_APP=app\
    FLASK_RUN_PORT=6000\
    FLASK_RUN_HOST=0.0.0.0\
    SERVICE_URL="https://eudiw-issuer.duckdns.org:5000/" \
    EIDAS_NODE_URL="https://preprod.issuer.eudiw.dev/EidasNode/"\
    DYNAMIC_PRESENTATION_URL="https://dev.verifier-backend.eudiw.dev/ui/presentations/"

EXPOSE 6000

CMD ["flask", "run", "--host=0.0.0.0"]