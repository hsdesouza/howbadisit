#!/bin/bash

# HowBadIsIt? - Docker Helper Script
# Facilita o uso do scanner via Docker

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE_NAME="howbadisit"
IMAGE_TAG="2.3.0"
REPORTS_DIR="${SCRIPT_DIR}/reports"

# Cores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Funções de output
info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Banner
show_banner() {
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║                         HowBadIsIt?                           ║"
    echo "║                           v2.3.0                              ║"
    echo "║                         CLI Wrapper                           ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo ""
}

# Verificar Docker
check_docker() {
    if ! command -v docker &> /dev/null; then
        error "Docker não está instalado!"
        echo ""
        echo "Instale o Docker:"
        echo "  Ubuntu/Debian: sudo apt-get install docker.io"
        echo "  Arch: sudo pacman -S docker"
        echo ""
        exit 1
    fi
    
    if ! docker ps &> /dev/null; then
        error "Docker não está rodando ou você não tem permissão!"
        echo ""
        echo "Soluções:"
        echo "  1. Iniciar Docker: sudo systemctl start docker"
        echo "  2. Adicionar ao grupo: sudo usermod -aG docker \$USER"
        echo "  3. Fazer logout/login ou: newgrp docker"
        echo ""
        exit 1
    fi
}

# Build da imagem
build_image() {
    info "Preparing scanner..."
    
    if ! docker build -t "${IMAGE_NAME}:${IMAGE_TAG}" -t "${IMAGE_NAME}:latest" "${SCRIPT_DIR}"; then
        error "Build failed!"
        exit 1
    fi
    
    success "Image built successfully: ${IMAGE_NAME}:${IMAGE_TAG}"
}

# Rebuild (força reconstrução)
rebuild_image() {
    info "Rebuilding Docker image (no cache)..."
    
    if ! docker build --no-cache -t "${IMAGE_NAME}:${IMAGE_TAG}" -t "${IMAGE_NAME}:latest" "${SCRIPT_DIR}"; then
        error "Rebuild failed!"
        exit 1
    fi
    
    success "Image rebuilt successfully!"
}

# Verificar se imagem existe
check_image() {
    if ! docker image inspect "${IMAGE_NAME}:latest" &> /dev/null; then
        warning "Image not found. Building..."
        build_image
    fi
}

# Executar scan
run_scan() {
    check_image
    
    # Criar diretório de relatórios
    mkdir -p "${REPORTS_DIR}"
    
    info "Running scan..."
    
    docker run --rm --network host \
        -v "${REPORTS_DIR}:/app/reports" \
        "${IMAGE_NAME}:latest" "$@"
}

# Scan interativo
interactive_scan() {
    echo ""
    read -p "Target (URL or domain): " target
    
    if [ -z "$target" ]; then
        error "Target cannot be empty!"
        exit 1
    fi
    
    read -p "Output format (text/json) [text]: " format
    format=${format:-text}
    
    if [ "$format" = "json" ]; then
        timestamp=$(date +%Y%m%d_%H%M%S)
        filename="report_${target//[^a-zA-Z0-9]/_}_${timestamp}.json"
        read -p "Output file [$filename]: " custom_filename
        filename=${custom_filename:-$filename}
        
        run_scan -t "$target" -o json -f "/app/reports/$filename"
        success "Report saved: ${REPORTS_DIR}/$filename"
    else
        run_scan -t "$target"
    fi
}

# Shell interativo no container
shell() {
    check_image
    
    info "Starting interactive shell in container..."
    
    docker run --rm -it --network host \
        -v "${REPORTS_DIR}:/app/reports" \
        --entrypoint /bin/bash \
        "${IMAGE_NAME}:latest"
}

# Listar relatórios
list_reports() {
    if [ ! -d "${REPORTS_DIR}" ] || [ -z "$(ls -A ${REPORTS_DIR} 2>/dev/null)" ]; then
        warning "No reports found in ${REPORTS_DIR}"
        return
    fi
    
    echo "Reports in ${REPORTS_DIR}:"
    echo ""
    ls -lh "${REPORTS_DIR}"
}

# Limpar relatórios
clean_reports() {
    if [ ! -d "${REPORTS_DIR}" ]; then
        info "Reports directory doesn't exist."
        return
    fi
    
    read -p "Delete all reports in ${REPORTS_DIR}? (y/N): " confirm
    
    if [ "$confirm" = "y" ] || [ "$confirm" = "Y" ]; then
        rm -rf "${REPORTS_DIR}"/*
        success "Reports cleaned!"
    else
        info "Cancelled."
    fi
}

# Info sobre imagem
image_info() {
    if docker image inspect "${IMAGE_NAME}:latest" &> /dev/null; then
        echo "Image: ${IMAGE_NAME}:${IMAGE_TAG}"
        echo "Size: $(docker images ${IMAGE_NAME}:latest --format '{{.Size}}')"
        echo "Created: $(docker images ${IMAGE_NAME}:latest --format '{{.CreatedAt}}')"
        echo ""
        echo "Layers:"
        docker history "${IMAGE_NAME}:latest" --no-trunc --format "table {{.CreatedBy}}\t{{.Size}}" | head -n 10
    else
        warning "Image not found. Run './howbadisit.sh build' first."
    fi
}

# Remover imagem
remove_image() {
    if docker image inspect "${IMAGE_NAME}:latest" &> /dev/null; then
        read -p "Remove image ${IMAGE_NAME}? (y/N): " confirm
        
        if [ "$confirm" = "y" ] || [ "$confirm" = "Y" ]; then
            docker rmi "${IMAGE_NAME}:latest" "${IMAGE_NAME}:${IMAGE_TAG}" 2>/dev/null || true
            success "Image removed!"
        else
            info "Cancelled."
        fi
    else
        info "Image not found."
    fi
}

# Help
show_help() {
    cat << EOF
Usage: $0 [COMMAND] [OPTIONS]

COMMANDS:
    build               Build Docker image
    rebuild             Rebuild image (no cache)
    scan                Run interactive scan
    run [args]          Run scanner with custom arguments
    shell               Open interactive shell in container
    
    list                List saved reports
    clean               Clean all reports
    
    info                Show image information
    remove              Remove Docker image
    
    help                Show this help

EXAMPLES:
    # Build image
    $0 build
    
    # Interactive scan
    $0 scan
    
    # Direct scan
    $0 run -t example.com
    $0 run -t example.com -o json -f /app/reports/report.json
    
    # Custom options
    $0 run -t example.com --timeout 30 -v
    
    # Open shell
    $0 shell
    
    # List reports
    $0 list

NOTES:
    - Reports are saved in: ${REPORTS_DIR}
    - Image name: ${IMAGE_NAME}:${IMAGE_TAG}
    - First run will build the image automatically

EOF
}

# Main
main() {
    show_banner
    
    case "${1:-help}" in
        build)
            check_docker
            build_image
            ;;
        rebuild)
            check_docker
            rebuild_image
            ;;
        scan)
            check_docker
            interactive_scan
            ;;
        run)
            check_docker
            shift
            run_scan "$@"
            ;;
        shell)
            check_docker
            shell
            ;;
        list)
            list_reports
            ;;
        clean)
            clean_reports
            ;;
        info)
            check_docker
            image_info
            ;;
        remove)
            check_docker
            remove_image
            ;;
        help|--help|-h)
            show_help
            ;;
        *)
            error "Unknown command: $1"
            echo ""
            show_help
            exit 1
            ;;
    esac
}

main "$@"
