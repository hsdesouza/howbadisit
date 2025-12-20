# Web HowBadIsIt? - Docker Image
# Base: Python 3.11 (versão estável, compatível com todas as dependências originais)

FROM python:3.11-slim-bookworm

# Metadados
LABEL maintainer="Red Team Security"
LABEL description="Web HowBadIsIt? - MSSP Professional Tool"
LABEL version="1.0.0"

# Variáveis de ambiente
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Instalar dependências do sistema
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    dnsutils \
    libxml2-dev \
    libxslt1-dev \
    gcc \
    g++ \
    make \
    && rm -rf /var/lib/apt/lists/*

# Criar diretório de trabalho
WORKDIR /app

# Copiar requirements.txt ORIGINAL (versão que você já tinha)
COPY requirements_docker.txt /app/requirements.txt

# Instalar dependências Python
RUN pip install --upgrade pip setuptools wheel && \
    pip install -r requirements.txt

# Copiar o scanner e HTML generator
COPY howbadisit.py /app/
COPY html_report_generator.py /app/
COPY templates/ /app/templates/

# Criar diretório para relatórios
RUN mkdir -p /app/reports

# Usuário não-root para segurança
RUN useradd -m -u 1000 scanner && \
    chown -R scanner:scanner /app
USER scanner

# Volume para relatórios
VOLUME ["/app/reports"]

# Ponto de entrada
ENTRYPOINT ["python3", "howbadisit.py"]

# Comando padrão (help)
CMD ["--help"]
