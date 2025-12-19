#!/bin/bash

################################################################################
# HowBadIsIt? - Automated Setup v2.1.0
# 
# Automated installation for Ubuntu/Debian/Kali Linux
# Funciona em: WSL, VM, Hardware
# 
# Uso: curl -fsSL https://raw.githubusercontent.com/hsdesouza/howbadisit/main/setup.sh | bash
#      OU
#      git clone git@github.com:hsdesouza/howbadisit.git && cd howbadisit && ./setup.sh
#
################################################################################

set -e

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Variáveis globais
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE_NAME="howbadisit"
IMAGE_TAG="2.1.0"
REPO_URL="git@github.com:hsdesouza/howbadisit.git"
INSTALL_DIR="/opt/howbadisit"

################################################################################
# Funções de Output
################################################################################

print_banner() {
    clear
    echo -e "${CYAN}"
    cat << 'EOF'
╔═══════════════════════════════════════════════════════════════════════╗
║                                                                       ║
║           HowBadIsIt? - AUTOMATED SETUP v2.1.0                 ║
║                                                                       ║
║                    🐳 Docker + Git Automation                         ║
║                                                                       ║
╚═══════════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

error() {
    echo -e "${RED}[✗]${NC} $1"
}

step() {
    echo -e "\n${MAGENTA}[STEP $1/$2]${NC} $3"
    echo -e "${CYAN}──────────────────────────────────────────────────────────────${NC}"
}

################################################################################
# Funções de Detecção
################################################################################

detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO=$ID
        VERSION=$VERSION_ID
        PRETTY_NAME="$PRETTY_NAME"
    else
        DISTRO="unknown"
        VERSION="unknown"
        PRETTY_NAME="Unknown Linux"
    fi
    
    info "Detected: $PRETTY_NAME"
}

detect_environment() {
    if grep -qi microsoft /proc/version 2>/dev/null; then
        ENV="WSL"
        info "Environment: Windows Subsystem for Linux (WSL)"
    elif systemd-detect-virt &>/dev/null; then
        VIRT=$(systemd-detect-virt)
        if [ "$VIRT" != "none" ]; then
            ENV="VM"
            info "Environment: Virtual Machine ($VIRT)"
        else
            ENV="Hardware"
            info "Environment: Physical Hardware"
        fi
    else
        ENV="Unknown"
        info "Environment: Unknown"
    fi
}

check_root() {
    if [ "$EUID" -eq 0 ]; then
        error "Do not run as root! Run as normal user with sudo privileges."
        exit 1
    fi
    
    if ! sudo -n true 2>/dev/null; then
        warning "You need sudo privileges. You may be prompted for password."
    fi
}

################################################################################
# Installation de Dependências
################################################################################

install_git() {
    if command -v git &> /dev/null; then
        success "Git already installed ($(git --version))"
        return 0
    fi
    
    info "Installing Git..."
    
    case "$DISTRO" in
        ubuntu|debian|kali)
            sudo apt-get update -qq
            sudo apt-get install -y -qq git
            ;;
        *)
            error "Unsupported distribution for automatic Git installation"
            exit 1
            ;;
    esac
    
    if command -v git &> /dev/null; then
        success "Git installed successfully"
    else
        error "Git installation failed"
        exit 1
    fi
}

install_docker() {
    if command -v docker &> /dev/null; then
        success "Docker already installed ($(docker --version))"
        
        # Verificar se pode executar sem sudo
        if docker ps &> /dev/null; then
            success "Docker running and accessible"
            return 0
        else
            warning "Docker installed but not accessible. Fixing permissions..."
        fi
    else
        info "Installing Docker..."
        
        case "$DISTRO" in
            ubuntu|debian|kali)
                # Remover versões antigas
                sudo apt-get remove -y docker docker-engine docker.io containerd runc 2>/dev/null || true
                
                # Instalar dependências
                sudo apt-get update -qq
                sudo apt-get install -y -qq \
                    apt-transport-https \
                    ca-certificates \
                    curl \
                    gnupg \
                    lsb-release
                
                # Adicionar chave GPG oficial do Docker
                sudo mkdir -p /etc/apt/keyrings
                curl -fsSL https://download.docker.com/linux/$DISTRO/gpg | \
                    sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg 2>/dev/null || \
                    sudo apt-get install -y -qq docker.io docker-compose
                
                # Adicionar repositório (se oficial disponível)
                if [ -f /etc/apt/keyrings/docker.gpg ]; then
                    echo \
                        "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
                        https://download.docker.com/linux/$DISTRO \
                        $(lsb_release -cs) stable" | \
                        sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
                    
                    sudo apt-get update -qq
                    sudo apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-compose-plugin
                fi
                ;;
            *)
                error "Unsupported distribution for automatic Docker installation"
                exit 1
                ;;
        esac
    fi
    
    # Adicionar usuário ao grupo docker
    info "Adding user to docker group..."
    sudo usermod -aG docker $USER
    
    # Iniciar Docker (funciona diferente no WSL)
    if [ "$ENV" = "WSL" ]; then
        info "Starting Docker daemon (WSL mode)..."
        if ! docker ps &> /dev/null; then
            sudo dockerd > /tmp/dockerd.log 2>&1 &
            sleep 5
        fi
    else
        info "Enabling and starting Docker service..."
        sudo systemctl enable docker 2>/dev/null || true
        sudo systemctl start docker 2>/dev/null || true
    fi
    
    # Verificar se Docker está funcionando
    ATTEMPTS=0
    MAX_ATTEMPTS=10
    
    while [ $ATTEMPTS -lt $MAX_ATTEMPTS ]; do
        if docker ps &> /dev/null 2>&1; then
            success "Docker is running!"
            return 0
        fi
        
        ATTEMPTS=$((ATTEMPTS + 1))
        info "Waiting for Docker to start... (attempt $ATTEMPTS/$MAX_ATTEMPTS)"
        sleep 2
    done
    
    warning "Docker may not be running properly"
    warning "You may need to:"
    echo "  1. Logout and login again (for group changes)"
    echo "  2. Run: newgrp docker"
    echo "  3. On WSL: sudo dockerd &"
    
    read -p "Continue anyway? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
}

################################################################################
# Clone do Repositório
################################################################################

clone_repository() {
    if [ -d "$INSTALL_DIR/.git" ]; then
        info "Repository already exists at $INSTALL_DIR"
        
        read -p "Update existing repository? (Y/n): " -n 1 -r
        echo
        
        if [[ $REPLY =~ ^[Nn]$ ]]; then
            info "Using existing repository"
            return 0
        fi
        
        info "Updating repository..."
        cd "$INSTALL_DIR"
        git pull origin main || git pull origin master || warning "Failed to update repository"
    else
        info "Cloning repository to $INSTALL_DIR..."
        
        # Criar diretório pai se não existir
        sudo mkdir -p "$(dirname "$INSTALL_DIR")"
        
        # Verificar se temos acesso SSH ao GitHub
        if ssh -T git@github.com 2>&1 | grep -q "successfully authenticated"; then
            info "Using SSH authentication"
            sudo git clone "$REPO_URL" "$INSTALL_DIR" || {
                error "Failed to clone repository via SSH"
                info "Trying HTTPS fallback..."
                REPO_URL_HTTPS="https://github.com/hsdesouza/howbadisit.git"
                sudo git clone "$REPO_URL_HTTPS" "$INSTALL_DIR" || {
                    error "Failed to clone repository"
                    exit 1
                }
            }
        else
            info "SSH key not configured, using HTTPS"
            REPO_URL_HTTPS="https://github.com/hsdesouza/howbadisit.git"
            sudo git clone "$REPO_URL_HTTPS" "$INSTALL_DIR" || {
                error "Failed to clone repository"
                exit 1
            }
        fi
        
        # Ajustar permissões
        sudo chown -R $USER:$USER "$INSTALL_DIR"
    fi
    
    success "Repository ready at $INSTALL_DIR"
}

################################################################################
# Build Docker Image
################################################################################

build_docker_image() {
    cd "$INSTALL_DIR"
    
    if [ ! -f "Dockerfile" ]; then
        error "Dockerfile not found in $INSTALL_DIR"
        exit 1
    fi
    
    info "Building Docker image..."
    info "This may take 3-5 minutes on first run..."
    
    if docker build -t "${IMAGE_NAME}:${IMAGE_TAG}" -t "${IMAGE_NAME}:latest" . ; then
        success "Docker image built successfully!"
        
        # Mostrar informações da imagem
        IMAGE_SIZE=$(docker images "${IMAGE_NAME}:latest" --format "{{.Size}}")
        success "Image size: $IMAGE_SIZE"
    else
        error "Docker image build failed!"
        exit 1
    fi
}

################################################################################
# Configuração Pós-Installation
################################################################################

setup_helpers() {
    cd "$INSTALL_DIR"
    
    info "Setting up helper scripts..."
    
    # Tornar scripts executáveis
    chmod +x *.sh 2>/dev/null || true
    
    # Criar diretório de relatórios
    mkdir -p reports
    
    # Criar alias no bashrc/zshrc
    SHELL_RC="$HOME/.bashrc"
    if [ -f "$HOME/.zshrc" ]; then
        SHELL_RC="$HOME/.zshrc"
    fi
    
    if ! grep -q "howbadisit aliases" "$SHELL_RC"; then
        info "Adding aliases to $SHELL_RC..."
        
        cat >> "$SHELL_RC" << 'EOF'

# HowBadIsIt? aliases
alias howbadisit='cd /opt/howbadisit && ./howbadisit.sh run'
alias howbadisit-scan='cd /opt/howbadisit && ./howbadisit.sh scan'
alias howbadisit-list='cd /opt/howbadisit && ./howbadisit.sh list'
alias howbadisit-shell='cd /opt/howbadisit && ./howbadisit.sh shell'
alias howbadisit-update='cd /opt/howbadisit && git pull && docker build -t howbadisit .'
EOF
        
        success "Aliases added! Reload shell or run: source $SHELL_RC"
    else
        info "Aliases already configured"
    fi
}

create_quick_start() {
    cat > "$INSTALL_DIR/QUICK_START.txt" << 'EOF'
╔═══════════════════════════════════════════════════════════════════════╗
║                                                                       ║
║                    🎯 QUICK START GUIDE                               ║
║                                                                       ║
╚═══════════════════════════════════════════════════════════════════════╝

✅ Installation Complete!

📍 LOCATION
   All files installed in: /opt/howbadisit

🚀 QUICK START

   # Navigate to directory
   cd /opt/howbadisit

   # Interactive scan (easiest)
   ./howbadisit.sh scan

   # Direct scan
   ./howbadisit.sh run -t example.com

   # Save JSON report
   ./howbadisit.sh run -t example.com -o json -f /app/reports/report.json

   # List all reports
   ./howbadisit.sh list

   # Help
   ./howbadisit.sh help

📊 ALIASES (reload shell first: source ~/.bashrc)

   howbadisit -t example.com              # Direct scan
   howbadisit-scan                         # Interactive scan
   howbadisit-list                         # List reports
   howbadisit-shell                        # Open container shell
   howbadisit-update                       # Update from git + rebuild

📁 REPORTS

   All reports saved in: /opt/howbadisit/reports/

   View report:
   cat /opt/howbadisit/reports/report.json | jq .

📚 DOCUMENTATION

   - README.md              # Complete documentation
   - DOCKER_GUIDE.md        # Docker usage guide
   - DOCKER_README.md       # Quick Docker reference
   - QUICKSTART.md          # Quick start guide

🔧 TROUBLESHOOTING

   Docker not running (WSL):
   sudo dockerd > /dev/null 2>&1 &

   Permission issues:
   newgrp docker

   Rebuild image:
   cd /opt/howbadisit && docker build -t howbadisit .

⚠️  IMPORTANT

   ALWAYS get written authorization before scanning any target!

═══════════════════════════════════════════════════════════════════════
For detailed documentation, see: /opt/howbadisit/README.md
═══════════════════════════════════════════════════════════════════════
EOF

    success "Quick start guide created: $INSTALL_DIR/QUICK_START.txt"
}

################################################################################
# Testes de Validação
################################################################################

run_tests() {
    info "Running validation tests..."
    
    # Test 1: Docker is accessible
    if docker ps &> /dev/null; then
        success "Test 1/3: Docker is accessible"
    else
        warning "Test 1/3: Docker may not be accessible"
        return 1
    fi
    
    # Test 2: Image exists
    if docker images "${IMAGE_NAME}:latest" --format "{{.Repository}}" | grep -q "$IMAGE_NAME"; then
        success "Test 2/3: Docker image exists"
    else
        warning "Test 2/3: Docker image not found"
        return 1
    fi
    
    # Test 3: Scanner help works
    if docker run --rm "${IMAGE_NAME}:latest" --help &> /dev/null; then
        success "Test 3/3: Scanner is functional"
    else
        warning "Test 3/3: Scanner test failed"
        return 1
    fi
    
    success "All tests passed! 🎉"
}

################################################################################
# Main Installation Flow
################################################################################

main() {
    local TOTAL_STEPS=8
    
    print_banner
    
    step 1 $TOTAL_STEPS "System Detection"
    detect_distro
    detect_environment
    check_root
    
    step 2 $TOTAL_STEPS "Installing Git"
    install_git
    
    step 3 $TOTAL_STEPS "Installing Docker"
    install_docker
    
    step 4 $TOTAL_STEPS "Cloning Repository"
    clone_repository
    
    step 5 $TOTAL_STEPS "Building Docker Image"
    build_docker_image
    
    step 6 $TOTAL_STEPS "Setting Up Helpers"
    setup_helpers
    create_quick_start
    
    step 7 $TOTAL_STEPS "Running Validation Tests"
    if run_tests; then
        TESTS_PASSED=true
    else
        TESTS_PASSED=false
    fi
    
    step 8 $TOTAL_STEPS "Installation Summary"
    
    echo ""
    echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                                                                       ║${NC}"
    echo -e "${GREEN}║                    ✅ INSTALLATION COMPLETE!                          ║${NC}"
    echo -e "${GREEN}║                                                                       ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    info "Installation Directory: ${CYAN}$INSTALL_DIR${NC}"
    info "Docker Image: ${CYAN}${IMAGE_NAME}:${IMAGE_TAG}${NC}"
    
    if [ "$TESTS_PASSED" = true ]; then
        success "All validation tests passed!"
    else
        warning "Some tests failed. Check logs above."
    fi
    
    echo ""
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${CYAN}📖 NEXT STEPS:${NC}"
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo "  1️⃣  Reload your shell (for aliases):"
    echo -e "      ${CYAN}source ~/.bashrc${NC}"
    echo ""
    echo "  2️⃣  Navigate to installation:"
    echo -e "      ${CYAN}cd /opt/howbadisit${NC}"
    echo ""
    echo "  3️⃣  Run your first scan:"
    echo -e "      ${CYAN}./howbadisit.sh scan${NC}"
    echo ""
    echo "  4️⃣  Or use direct command:"
    echo -e "      ${CYAN}./howbadisit.sh run -t scanme.nmap.org${NC}"
    echo ""
    echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "${CYAN}📚 Documentation:${NC}"
    echo -e "   Quick Start: ${CYAN}cat /opt/howbadisit/QUICK_START.txt${NC}"
    echo -e "   Full Docs:   ${CYAN}cat /opt/howbadisit/README.md${NC}"
    echo ""
    echo -e "${YELLOW}⚠️  IMPORTANT:${NC}"
    echo -e "   ${RED}Always get written authorization before scanning any target!${NC}"
    echo ""
}

################################################################################
# Execute
################################################################################

main "$@"
