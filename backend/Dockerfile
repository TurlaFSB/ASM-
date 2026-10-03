# Stages: `base` (all tools) -> `prod` (non-root, for docker-compose.prod.yml) -> `dev` (root; the default target,
# used by docker-compose.yml with the source bind-mounted).
FROM python:3.13-slim AS base

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf-xlib-2.0-0 libffi-dev \
    shared-mime-info build-essential curl git unzip \
    nmap whatweb \
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
    && chmod +x /usr/local/bin/nuclei /usr/local/bin/subfinder /usr/local/bin/httpx \
    && ln -sf /usr/local/bin/httpx /usr/local/bin/httpx-toolkit

# Fail the build loudly if templates did not download (a silent failure makes nuclei scan nothing)
RUN nuclei -update-templates \
    && test "$(find /root/nuclei-templates -name '*.yaml' | wc -l)" -gt 1000

# Amass (Go binary release)
ARG AMASS_VERSION=4.2.0
RUN curl -sL https://github.com/owasp-amass/amass/releases/download/v${AMASS_VERSION}/amass_Linux_amd64.zip -o /tmp/amass.zip \
    && unzip -o /tmp/amass.zip -d /tmp \
    && mv /tmp/amass_Linux_amd64/amass /usr/local/bin/amass \
    && chmod +x /usr/local/bin/amass \
    && rm -rf /tmp/amass.zip /tmp/amass_Linux_amd64

# feroxbuster (directory/content discovery, prebuilt binary release)
ARG FEROXBUSTER_VERSION=2.11.0
RUN curl -fsSL https://github.com/epi052/feroxbuster/releases/download/v${FEROXBUSTER_VERSION}/x86_64-linux-feroxbuster.zip -o /tmp/ferox.zip \
    && unzip -o /tmp/ferox.zip -d /usr/local/bin feroxbuster && rm /tmp/ferox.zip \
    && chmod +x /usr/local/bin/feroxbuster

# SecLists wordlists for feroxbuster ("small" = quickhits, "medium" = common.txt). The curated
# "core" list ships in the repo (backend/wordlists/asm-core.txt).
RUN mkdir -p /opt/wordlists \
    && curl -fsSL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt \
       -o /opt/wordlists/common.txt \
    && curl -fsSL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/quickhits.txt \
       -o /opt/wordlists/quickhits.txt
# Fail the build if a download silently produced an error page / empty list (a 404 body would
# otherwise be used as a "wordlist" and every scan would find nothing)
RUN test "$(wc -l < /opt/wordlists/quickhits.txt)" -gt 1000 \
    && test "$(wc -l < /opt/wordlists/common.txt)" -gt 1000 \
    && feroxbuster --version

# EyeWitness (FortyNorthSecurity, matches Kali's apt-packaged version)
RUN git clone --depth 1 https://github.com/FortyNorthSecurity/EyeWitness.git /opt/EyeWitness \
    && cd /opt/EyeWitness/setup \
    && ./setup.sh || pip install --no-cache-dir -r /opt/EyeWitness/setup/requirements.txt \
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

# ── Production image: runs as an unprivileged user, owns nothing it does not need ──
FROM base AS prod
RUN apt-get update && apt-get install -y --no-install-recommends libcap2-bin \
    && rm -rf /var/lib/apt/lists/* \
    # Raw sockets for SYN scans WITHOUT root: only CAP_NET_RAW, only on the nmap binary. The container must
    # also grant it (cap_add: NET_RAW); without it scans fall back to a TCP connect scan automatically.
    && setcap cap_net_raw+eip "$(readlink -f /usr/bin/nmap)" \
    && groupadd -g 10001 asm \
    && useradd -u 10001 -g 10001 -m -d /home/asm -s /usr/sbin/nologin asm \
    # nuclei looks for templates under $HOME, which is /root in the base image and unreadable here
    && cp -a /root/nuclei-templates /home/asm/nuclei-templates \
    && mkdir -p /app/screenshots /app/scan_output /tmp/.X11-unix \
    && chmod 1777 /tmp/.X11-unix \
    && chown -R asm:asm /home/asm /app/screenshots /app/scan_output
ENV HOME=/home/asm \
    NMAP_PRIVILEGED=1 \
    MOZ_DISABLE_CONTENT_SANDBOX=1
USER asm

# ── Development image (default target) ──
FROM base AS dev
