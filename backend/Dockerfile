FROM python:3.13-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf2.0-0 libffi-dev \
    shared-mime-info build-essential curl git unzip \
    nmap \
    firefox-esr xvfb \
    python3-dev python3-pip libxml2-dev libxslt1-dev \
    && rm -rf /var/lib/apt/lists/*

# geckodriver (required by EyeWitness/Selenium)
ARG GECKODRIVER_VERSION=0.35.0
RUN curl -sL https://github.com/mozilla/geckodriver/releases/download/v${GECKODRIVER_VERSION}/geckodriver-v${GECKODRIVER_VERSION}-linux64.tar.gz -o /tmp/geckodriver.tar.gz \
    && tar -xzf /tmp/geckodriver.tar.gz -C /usr/local/bin \
    && rm /tmp/geckodriver.tar.gz \
    && chmod +x /usr/local/bin/geckodriver

# ProjectDiscovery tools: Nuclei, Subfinder, HTTPX (prebuilt binaries)
ARG NUCLEI_VERSION=3.3.7
ARG SUBFINDER_VERSION=2.6.6
ARG HTTPX_VERSION=1.6.8
RUN curl -sL https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip -o /tmp/nuclei.zip \
    && unzip -o /tmp/nuclei.zip -d /usr/local/bin nuclei && rm /tmp/nuclei.zip \
    && curl -sL https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION}_linux_amd64.zip -o /tmp/subfinder.zip \
    && unzip -o /tmp/subfinder.zip -d /usr/local/bin subfinder && rm /tmp/subfinder.zip \
    && curl -sL https://github.com/projectdiscovery/httpx/releases/download/v${HTTPX_VERSION}/httpx_${HTTPX_VERSION}_linux_amd64.zip -o /tmp/httpx.zip \
    && unzip -o /tmp/httpx.zip -d /usr/local/bin httpx && rm /tmp/httpx.zip \
    && chmod +x /usr/local/bin/nuclei /usr/local/bin/subfinder /usr/local/bin/httpx

RUN nuclei -update-templates -silent || true

# Amass (Go binary release)
ARG AMASS_VERSION=4.2.0
RUN curl -sL https://github.com/owasp-amass/amass/releases/download/v${AMASS_VERSION}/amass_Linux_amd64.zip -o /tmp/amass.zip \
    && unzip -o /tmp/amass.zip -d /tmp \
    && mv /tmp/amass_Linux_amd64/amass /usr/local/bin/amass \
    && chmod +x /usr/local/bin/amass \
    && rm -rf /tmp/amass.zip /tmp/amass_Linux_amd64

# EyeWitness (FortyNorthSecurity, matches Kali's apt-packaged version)
RUN git clone --depth 1 https://github.com/FortyNorthSecurity/EyeWitness.git /opt/EyeWitness \
    && cd /opt/EyeWitness/Python/setup \
    && ./setup.sh || pip install --no-cache-dir -r /opt/EyeWitness/Python/requirements.txt \
    && ln -s /opt/EyeWitness/Python/EyeWitness.py /usr/local/bin/eyewitness \
    && chmod +x /opt/EyeWitness/Python/EyeWitness.py

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ ./backend/

ENV DISPLAY=:99

EXPOSE 8000

CMD Xvfb :99 -screen 0 1280x1024x24 & \
    python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000
