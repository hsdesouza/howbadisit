# HowBadIsIt? v2.1 - MSSP Professional Tool

![Version](https://img.shields.io/badge/version-2.0.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.11-green.svg)
![Docker](https://img.shields.io/badge/docker-required-blue.svg)
![License](https://img.shields.io/badge/license-Proprietary-red.svg)

Ferramenta profissional de pentest automatizado para websites, desenvolvida especificamente para MSSPs (Managed Security Service Providers).

## 🚀 **Novidades da Versão 2.0**

- ✅ **Instalação 100% Automatizada** via Git + Docker
- ✅ **Zero Configuração Manual** - um único comando
- ✅ **Compatibilidade Total** - Ubuntu/Debian/Kali (WSL/VM/Hardware)
- ✅ **Detecção Automática** de ambiente e distro
- ✅ **Aliases Inteligentes** para uso rápido
- ✅ **Validação Automática** pós-instalação

---

## 📦 **Instalação Rápida (Recomendada)**

### **Método 1: Instalação Direta (Um Comando)**

```bash
curl -fsSL https://raw.githubusercontent.com/hsdesouza/howbadisit/main/setup.sh | bash
```

**Isso irá:**
1. Detectar seu sistema (Ubuntu/Debian/Kali, WSL/VM/Hardware)
2. Instalar Git (se necessário)
3. Instalar Docker (se necessário)
4. Clonar o repositório para `/opt/howbadisit`
5. Fazer build da imagem Docker
6. Configurar aliases
7. Validar instalação

**Tempo: ~5-10 minutos**

---

### **Método 2: Clone Manual + Setup**

```bash
# Clone o repositório
git clone git@github.com:hsdesouza/howbadisit.git
cd pentest

# Execute o setup
chmod +x setup.sh
./setup.sh
```

---

### **Método 3: HTTPS (se não tiver SSH configurado)**

```bash
git clone https://github.com/hsdesouza/howbadisit.git
cd pentest
chmod +x setup.sh
./setup.sh
```

---

## 🎯 **Uso Rápido**

Após a instalação:

```bash
# Navegar até o diretório
cd /opt/howbadisit

# Scan interativo (mais fácil)
./howbadisit.sh scan

# Scan direto
./howbadisit.sh run -t example.com

# Com relatório JSON
./howbadisit.sh run -t example.com -o json -f /app/reports/report.json

# Listar relatórios
./howbadisit.sh list

# Ajuda
./howbadisit.sh help
```

---

## 🔧 **Aliases Automáticos**

Após recarregar o shell (`source ~/.bashrc`):

```bash
# De qualquer lugar do sistema:
pentest -t example.com                  # Scan direto
pentest-scan                             # Scan interativo
pentest-list                             # Listar relatórios
pentest-shell                            # Shell no container
pentest-update                           # Atualizar do Git + rebuild
```

---

## 📋 **Pré-requisitos**

- **Sistema Operacional**: Ubuntu 20.04+, Debian 11+, Kali Linux 2020+
- **Ambiente**: WSL2, VM ou Hardware (bare metal)
- **Usuário**: Não-root com privilégios sudo
- **Internet**: Conexão para download de dependências

**O script de instalação cuida de tudo automaticamente!**

---

## 🎯 **10 Testes Implementados**

Ordenados por relevância e impacto comercial:

### 1. ⭐⭐⭐⭐⭐ Detecção de Tecnologias e Versões Vulneráveis
- Identifica servidores web, frameworks, CMS
- Detecta versões específicas de software
- Correlaciona com CVEs conhecidos
- **Valor**: ROI imediato com exploits públicos

### 2. ⭐⭐⭐⭐⭐ Enumeração de Subdomínios e Detecção de Subdomain Takeover
- Enumera subdomínios ativos
- Detecta possibilidade de takeover (GitHub Pages, Heroku, AWS S3, etc.)
- Identifica ativos esquecidos
- **Valor**: Previne comprometimento de reputação e phishing

### 3. ⭐⭐⭐⭐⭐ Análise de Informações Expostas
- Busca arquivos sensíveis (.git, .env, backups SQL)
- Verifica configurações expostas
- Identifica comentários com credenciais
- **Valor**: Acesso não autorizado imediato

### 4. ⭐⭐⭐⭐ Detecção de Portas e Serviços Expostos
- Scan de portas comuns
- Identificação de serviços e versões
- Mapeia superfície de ataque
- **Valor**: Base para qualquer pentest profissional

### 5. ⭐⭐⭐⭐ Verificação de Configurações SSL/TLS
- Testa protocolos fracos
- Verifica validade de certificados
- Detecta cifras inseguras
- **Valor**: Compliance (LGPD, PCI-DSS, ISO 27001)

### 6. ⭐⭐⭐⭐ Análise de Headers de Segurança HTTP
- Verifica HSTS, CSP, X-Frame-Options
- Identifica headers faltantes
- **Valor**: Quick wins, melhora score em auditorias

### 7. ⭐⭐⭐ Análise de Formulários e Injeções Básicas
- Testa CSRF protection
- Detecção passiva de SQL Injection
- Análise de sanitização de inputs
- **Valor**: OWASP Top 10 - alta visibilidade

### 8. ⭐⭐⭐ Verificação de CORS Misconfiguration
- Detecta políticas CORS permissivas
- Testa origens arbitrárias
- **Valor**: Relevante para arquiteturas SPA/API modernas

### 9. ⭐⭐ Teste de Métodos HTTP Inseguros
- Verifica métodos perigosos (PUT, DELETE, TRACE)
- Testa HTTP Verb Tampering
- **Valor**: Impacto moderado quando presente

### 10. ⭐⭐ Detecção de WAF/CDN
- Identifica presença de WAF (Cloudflare, AWS WAF, Akamai)
- Mapeia infraestrutura de proteção
- **Valor**: Informativo para contextualizar outros achados

---

## 📊 **Formatos de Saída**

### JSON (Recomendado para Automação)
```bash
./howbadisit.sh run -t example.com -o json -f /app/reports/report.json

# Analisar com jq
cat reports/report.json | jq '.summary'
```

### Texto (Recomendado para Leitura)
```bash
./howbadisit.sh run -t example.com -o text -f /app/reports/report.txt

# Ver no terminal
cat reports/report.txt
```

---

## 🔐 **Considerações de Segurança**

### ⚠️ **IMPORTANTE - Uso Legal**

Este scanner deve ser usado **APENAS** com permissão explícita do proprietário do alvo.

**Uso não autorizado pode:**
- Violar leis de crimes cibernéticos (Lei Carolina Dieckmann - 12.737/2012)
- Resultar em processo civil e criminal
- Violar termos de serviço de provedores

### **Boas Práticas**

1. ✅ Obtenha autorização por escrito antes de qualquer teste
2. ✅ Informe o cliente sobre possíveis interrupções
3. ✅ Use em ambiente de teste primeiro
4. ✅ Documente todas as atividades
5. ✅ Respeite rate limits e políticas de robots.txt

---

## 📁 **Estrutura de Arquivos**

```
/opt/howbadisit/
├── setup.sh                       # Script de instalação automatizada ⭐ NOVO
├── howbadisit.py         # Script principal de pentest
├── Dockerfile                     # Definição da imagem Docker
├── docker-compose.yml             # Orquestração Docker
├── howbadisit.sh               # Helper para facilitar uso
├── requirements_docker.txt        # Dependências Python (versão original)
├── .dockerignore                  # Otimização do build
├── README.md                      # Esta documentação
├── DOCKER_GUIDE.md                # Guia completo Docker
├── DOCKER_README.md               # Referência rápida Docker
├── QUICKSTART.md                  # Guia início rápido
├── QUICK_START.txt                # Guia pós-instalação ⭐ NOVO
├── CHANGELOG.md                   # Histórico de versões
├── LICENSE                        # Licença
└── reports/                       # Relatórios gerados
```

---

## 🛠️ **Troubleshooting**

### **Docker não inicia (WSL)**
```bash
sudo dockerd > /dev/null 2>&1 &
sleep 5
docker ps
```

### **Permission denied**
```bash
# Adicionar ao grupo docker
sudo usermod -aG docker $USER

# Recarregar grupo
newgrp docker

# OU fazer logout/login
```

### **Reinstalar/Atualizar**
```bash
cd /opt/howbadisit
git pull
docker build -t howbadisit .

# OU usar alias
pentest-update
```

### **Limpar tudo e recomeçar**
```bash
# Remover instalação
sudo rm -rf /opt/howbadisit

# Remover imagem Docker
docker rmi howbadisit

# Reinstalar
curl -fsSL https://raw.githubusercontent.com/hsdesouza/howbadisit/main/setup.sh | bash
```

---

## 💼 **Valor Comercial para MSSP**

### **Por que estes testes?**

1. **ROI Imediato**: Resultados tangíveis em minutos
2. **Fácil Demonstração**: Clientes entendem os riscos
3. **Compliance**: Atende requisitos regulatórios (LGPD, PCI-DSS)
4. **Baixos Falsos Positivos**: Credibilidade técnica
5. **Correções Mensuráveis**: Permite acompanhamento
6. **Escalável**: Automação para múltiplos clientes

### **Casos de Uso**

- **Assessment Inicial**: First contact com potenciais clientes
- **Relatórios Executivos**: Demonstração de valor
- **Monitoramento Contínuo**: Verificação periódica
- **Pós-Remediação**: Validação de correções
- **Compliance Reports**: Evidências para auditorias

---

## 📈 **Exemplos Práticos**

### **Scan de Múltiplos Clientes**

```bash
#!/bin/bash
# scan-clientes.sh

CLIENTES=(
    "cliente1.com.br:cliente1"
    "cliente2.com.br:cliente2"
    "cliente3.com.br:cliente3"
)

cd /opt/howbadisit

for item in "${CLIENTES[@]}"; do
    DOMAIN="${item%%:*}"
    NAME="${item##*:}"
    
    echo "Scanning: $DOMAIN ($NAME)"
    
    ./howbadisit.sh run \
        -t "$DOMAIN" \
        -o json \
        -f "/app/reports/${NAME}_$(date +%Y%m%d_%H%M%S).json"
    
    sleep 10
done
```

### **Agendamento com Cron**

```bash
# Editar crontab
crontab -e

# Adicionar scan diário às 2h
0 2 * * * cd /opt/howbadisit && ./howbadisit.sh run -t cliente.com -o json -f /app/reports/daily_$(date +\%Y\%m\%d).json

# Scan semanal aos domingos
0 3 * * 0 cd /opt/howbadisit && ./howbadisit.sh run -t cliente.com -o json -f /app/reports/weekly_$(date +\%Y\%m\%d).json
```

---

## 🔄 **Atualização**

### **Atualizar do Git**

```bash
cd /opt/howbadisit
git pull origin main

# Rebuild da imagem
docker build -t howbadisit .

# OU usar alias
pentest-update
```

### **Changelog**

Ver `CHANGELOG.md` para histórico completo de alterações.

---

## 📞 **Suporte**

### **Documentação**
- `README.md` - Documentação completa (este arquivo)
- `DOCKER_GUIDE.md` - Guia detalhado Docker
- `QUICKSTART.md` - Início rápido
- `QUICK_START.txt` - Guia pós-instalação

### **Logs**
```bash
# Logs do scanner
cat /opt/howbadisit/pentest_scanner.log

# Logs do Docker (WSL)
cat /tmp/dockerd.log
```

### **Comunidade**
- Issues: https://github.com/hsdesouza/howbadisit/issues
- Contribuições: Pull requests são bem-vindos

---

## ⚖️ **Licença**

Proprietary - Uso restrito para MSSP autorizada

Ver `LICENSE` para termos completos.

---

## 🙏 **Créditos**

Desenvolvido seguindo melhores práticas de:
- OWASP Testing Guide
- PTES (Penetration Testing Execution Standard)
- NIST Cybersecurity Framework
- Docker Best Practices
- DevOps Automation Standards

---

## 📊 **Especificações Técnicas**

### **Plataforma**
- Ubuntu 20.04+ LTS
- Debian 11+
- Kali Linux 2020+
- Compatível com WSL2, VM e Hardware

### **Arquitetura**
- Docker containerizado (100% isolado)
- Python 3.11 (estável e testado)
- Modular e extensível
- Thread-safe
- Concurrent execution

### **Dependências**
- Docker 20.10+
- Git 2.25+
- 2GB RAM mínimo
- 5GB espaço em disco

### **Performance**
- Timeout configurável (padrão: 10s)
- Threads configuráveis (padrão: 5)
- Execução típica: 2-5 minutos
- Rate limiting friendly

---

## ✅ **Checklist Pós-Instalação**

- [ ] Setup executado com sucesso
- [ ] Docker acessível (`docker ps`)
- [ ] Imagem criada (`docker images | grep pentest`)
- [ ] Teste básico OK (`./howbadisit.sh help`)
- [ ] Primeiro scan completo
- [ ] Aliases configurados (`source ~/.bashrc`)
- [ ] Relatórios salvos corretamente

---

**Disclaimer**: Esta ferramenta é fornecida "como está" para fins educacionais e de segurança legítimos. Os autores não são responsáveis por uso inadequado ou ilegal.

---

**Version**: 2.0.0  
**Release Date**: 2024-12-19  
**Python**: 3.11  
**Platform**: Ubuntu/Debian/Kali (WSL/VM/Hardware)  
**Repository**: https://github.com/hsdesouza/howbadisit

---

## 🚀 **Quick Start Summary**

```bash
# 1. Instalação (um comando)
curl -fsSL https://raw.githubusercontent.com/hsdesouza/howbadisit/main/setup.sh | bash

# 2. Primeiro scan
cd /opt/howbadisit
./howbadisit.sh scan

# 3. Pronto! 🎉
```

Para documentação detalhada, veja os outros arquivos `.md` no repositório.
