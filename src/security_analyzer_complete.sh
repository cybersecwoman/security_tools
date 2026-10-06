#!/bin/bash

# ========================================
# Security Analyzer Tool v3.0 - Script Principal
# Ferramenta Avançada de Análise de Segurança
# ========================================

# Configuração inicial
set -euo pipefail  # Modo strict
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Diretório base fixo para os 'source' abaixo. Os módulos carregados redefinem
# a variável SCRIPT_DIR ao serem sourced, então usamos uma variável dedicada
# que não é sobrescrita para montar os caminhos corretamente.
__BASE_DIR="$SCRIPT_DIR"

# Carregar configurações e módulos
source "$__BASE_DIR/config.conf"
source "$__BASE_DIR/utils/security.sh"
source "$__BASE_DIR/utils/logger.sh"
source "$__BASE_DIR/modules/api_manager.sh"
source "$__BASE_DIR/modules/report_generator.sh"
source "$__BASE_DIR/analyzers/file_analyzer.sh"
source "$__BASE_DIR/analyzers/url_analyzer.sh"
source "$__BASE_DIR/analyzers/email_header_analyzer.sh"

# Cores para interface (se habilitadas)
if [[ "$ENABLE_COLORS" == "true" ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    PURPLE='\033[0;35m'
    CYAN='\033[0;36m'
    NC='\033[0m'
else
    RED='' GREEN='' YELLOW='' BLUE='' PURPLE='' CYAN='' NC=''
fi

# Inicialização do sistema
initialize_system() {
    log_info "Inicializando Security Analyzer Tool v$APP_VERSION" "MAIN"
    
    # Verificar privilégios
    check_privileges || {
        echo -e "${YELLOW}⚠️  Executando como root não é recomendado por segurança${NC}"
        echo "Deseja continuar? (s/n)"
        read -r continue_choice
        [[ "$continue_choice" =~ ^[Ss]$ ]] || exit 1
    }
    
    # Criar diretórios necessários
    create_secure_directory "$CONFIG_DIR"
    create_secure_directory "$CACHE_DIR"
    create_secure_directory "$REPORTS_DIR"
    create_secure_directory "$TEMP_DIR"
    
    # Inicializar módulos
    init_logging
    init_api_manager
    init_report_generator
    
    # Verificar dependências
    check_system_dependencies
    
    # Limpeza automática
    cleanup_old_reports >/dev/null 2>&1 &
    
    log_info "Sistema inicializado com sucesso" "MAIN"
}

# Verificar dependências do sistema
check_system_dependencies() {
    local missing_deps=()
    local deps=("curl" "jq" "dig" "whois" "file" "openssl" "python3")
    
    log_info "Verificando dependências do sistema..." "MAIN"
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &>/dev/null; then
            missing_deps+=("$dep")
            log_warn "Dependência não encontrada: $dep" "MAIN"
        fi
    done
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        echo -e "${RED}❌ Dependências faltando: ${missing_deps[*]}${NC}"
        echo -e "${YELLOW}Execute o instalador: ./scripts/install_dependencies.sh${NC}"
        
        echo "Deseja continuar mesmo assim? (s/n)"
        read -r continue_choice
        [[ "$continue_choice" =~ ^[Ss]$ ]] || exit 1
    else
        log_info "Todas as dependências estão disponíveis" "MAIN"
    fi
}

# Exibir banner principal
show_banner() {
    clear
    echo -e "${CYAN}"
    cat << "EOF"
╔══════════════════════════════════════════════════════════════════════════════╗
║   ███████╗███████╗ ██████╗██╗   ██╗██████╗ ██╗████████╗██╗   ██╗            ║
║   ██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██║╚══██╔══╝╚██╗ ██╔╝            ║
║   ███████╗█████╗  ██║     ██║   ██║██████╔╝██║   ██║    ╚████╔╝             ║
║   ╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██║   ██║     ╚██╔╝              ║
║   ███████║███████╗╚██████╗╚██████╔╝██║  ██║██║   ██║      ██║               ║
║   ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝   ╚═╝      ╚═╝               ║
║                                                                              ║
║   ████████╗ ██████╗  ██████╗ ██╗     ██╗   ██╗██████╗  ██████╗              ║
║   ╚══██╔══╝██╔═══██╗██╔═══██╗██║     ██║   ██║╚════██╗██╔═══██╗             ║
║      ██║   ██║   ██║██║   ██║██║     ██║   ██║ █████╔╝██║   ██║             ║
║      ██║   ██║   ██║██║   ██║██║      ██╗ ██╔╝ ╚═══██╗██║   ██║             ║
║      ██║   ╚██████╔╝╚██████╔╝███████╗ ╚████╔╝ ██████╔╝╚██████╔╝             ║
║      ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝  ╚═══╝  ╚═════╝  ╚═════╝              ║
║                                                                              ║
║                    🛡️  FERRAMENTA AVANÇADA DE SEGURANÇA  🛡️                  ║
║                              Versão $APP_VERSION                                ║
╚══════════════════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
    echo -e "${PURPLE}                           $APP_AUTHOR${NC}"
    echo ""
}

# Exibir menu principal
show_main_menu() {
    show_banner
    echo -e "${YELLOW}╔══════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${YELLOW}║                              MENU PRINCIPAL                                 ║${NC}"
    echo -e "${YELLOW}╚══════════════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${GREEN}  ANÁLISES PRINCIPAIS${NC}"
    echo -e "${GREEN}  [1] 📁 Analisar Arquivo${NC}          - Análise profunda de arquivos"
    echo -e "${GREEN}  [2] 🌐 Analisar URL${NC}             - Verificação completa de URLs"
    echo -e "${GREEN}  [3] 🏠 Analisar Domínio${NC}         - Investigação de domínios"
    echo -e "${GREEN}  [4] 🔢 Analisar Hash${NC}            - Consulta em bases de dados"
    echo -e "${GREEN}  [5] 📧 Analisar Email${NC}           - Verificação de endereços"
    echo -e "${GREEN}  [15] 📨 Analisar Header de Email${NC} - Análise forense de phishing/spoofing"
    echo -e "${GREEN}  [6] 🌐 Analisar IP${NC}             - Análise de endereços IP"
    echo ""
    echo -e "${BLUE}  CONFIGURAÇÃO E RELATÓRIOS${NC}"
    echo -e "${BLUE}  [7] ⚙️  Configurar APIs${NC}          - Gerenciar chaves de acesso"
    echo -e "${BLUE}  [8] 📊 Relatórios${NC}               - Visualizar relatórios"
    echo -e "${BLUE}  [9] 📈 Estatísticas${NC}             - Ver estatísticas de uso"
    echo -e "${BLUE}  [10] 📝 Logs${NC}                     - Visualizar logs do sistema"
    echo ""
    echo -e "${CYAN}  FERRAMENTAS${NC}"
    echo -e "${CYAN}  [11] 🧪 Executar Testes${NC}         - Testar funcionalidades"
    echo -e "${CYAN}  [12] 🔧 Manutenção${NC}              - Limpeza e otimização"
    echo -e "${CYAN}  [13] 📚 Ajuda${NC}                   - Documentação e suporte"
    echo -e "${CYAN}  [14] ℹ️  Sobre${NC}                   - Informações da ferramenta"
    echo ""
    echo -e "${RED}  [0] 🚪 Sair${NC}                     - Encerrar programa"
    echo ""
    echo -e "${YELLOW}╔══════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${YELLOW}║ Digite o número da opção desejada:                                          ║${NC}"
    echo -e "${YELLOW}╚══════════════════════════════════════════════════════════════════════════════╝${NC}"
    echo -n "➤ "
}

# Security Analyzer Tool v3.0 - Parte 2
# Funções de análise e interface
# ========================================

# Função principal de análise de arquivo
analyze_file_interactive() {
    echo -e "${CYAN}📁 ANÁLISE AVANÇADA DE ARQUIVO${NC}"
    echo "================================"
    echo ""
    
    echo "Digite o caminho do arquivo para análise:"
    echo -n "➤ "
    read -r file_path
    
    # Sanitizar entrada
    file_path=$(sanitize_input "$file_path")
    
    if [[ -z "$file_path" ]]; then
        echo -e "${RED}❌ Caminho não fornecido${NC}"
        return 1
    fi
    
    echo ""
    echo -e "${YELLOW}🔍 Iniciando análise...${NC}"
    echo ""
    
    # Executar análise
    local analysis_result
    if analysis_result=$(analyze_file "$file_path"); then
        echo "$analysis_result"
        
        # Oferecer geração de relatório
        echo ""
        echo -e "${CYAN}📄 Deseja gerar relatório HTML? (s/n)${NC}"
        read -r generate_report
        
        if [[ "$generate_report" =~ ^[Ss]$ ]]; then
            local risk_level=$(calculate_risk_level "$file_path")
            local report_file=$(generate_html_report "Arquivo" "$file_path" "$analysis_result" "$risk_level")
            
            if [[ -n "$report_file" ]]; then
                echo -e "${GREEN}✅ Relatório gerado: $(basename "$report_file")${NC}"
                
                echo -e "${CYAN}🌐 Deseja abrir no navegador? (s/n)${NC}"
                read -r open_browser
                
                if [[ "$open_browser" =~ ^[Ss]$ ]]; then
                    open_report_controlled "$report_file"
                fi
            fi
        fi
    else
        echo -e "${RED}❌ Erro na análise do arquivo${NC}"
        log_error "Falha na análise do arquivo: $file_path" "MAIN"
    fi
}

# Função principal de análise de URL
analyze_url_interactive() {
    echo -e "${CYAN}🌐 ANÁLISE AVANÇADA DE URL${NC}"
    echo "==========================="
    echo ""
    
    echo "Digite a URL para análise:"
    echo -n "➤ "
    read -r url
    
    # Sanitizar entrada
    url=$(sanitize_input "$url")
    
    if [[ -z "$url" ]]; then
        echo -e "${RED}❌ URL não fornecida${NC}"
        return 1
    fi
    
    echo ""
    echo -e "${YELLOW}🔍 Iniciando análise...${NC}"
    echo ""
    
    # Executar análise
    local analysis_result
    if analysis_result=$(analyze_url "$url"); then
        echo "$analysis_result"
        
        # Oferecer geração de relatório
        echo ""
        echo -e "${CYAN}📄 Deseja gerar relatório HTML? (s/n)${NC}"
        read -r generate_report
        
        if [[ "$generate_report" =~ ^[Ss]$ ]]; then
            local risk_level=$(calculate_url_risk "$url")
            local report_file=$(generate_html_report "URL" "$url" "$analysis_result" "$risk_level")
            
            if [[ -n "$report_file" ]]; then
                echo -e "${GREEN}✅ Relatório gerado: $(basename "$report_file")${NC}"
                
                echo -e "${CYAN}🌐 Deseja abrir no navegador? (s/n)${NC}"
                read -r open_browser
                
                if [[ "$open_browser" =~ ^[Ss]$ ]]; then
                    open_report_controlled "$report_file"
                fi
            fi
        fi
    else
        echo -e "${RED}❌ Erro na análise da URL${NC}"
        log_error "Falha na análise da URL: $url" "MAIN"
    fi
}

# Análise de domínio
analyze_domain_interactive() {
    echo -e "${CYAN}🏠 ANÁLISE DE DOMÍNIO${NC}"
    echo "===================="
    echo ""
    
    echo "Digite o domínio para análise:"
    echo -n "➤ "
    read -r domain
    
    domain=$(sanitize_input "$domain")
    
    if [[ -z "$domain" ]]; then
        echo -e "${RED}❌ Domínio não fornecido${NC}"
        return 1
    fi
    
    if ! validate_input "$domain" "domain"; then
        echo -e "${RED}❌ Formato de domínio inválido${NC}"
        return 1
    fi
    
    echo ""
    echo -e "${YELLOW}🔍 Analisando domínio: $domain${NC}"
    echo ""
    
    # Análise básica de domínio
    echo -e "${BLUE}[🔍 Resolução DNS]${NC}"
    if command -v dig &>/dev/null; then
        local ip_address=$(dig +short "$domain" 2>/dev/null | head -1)
        if [[ -n "$ip_address" ]]; then
            echo "IP: $ip_address"
            
            # Verificar geolocalização
            if command -v geoiplookup &>/dev/null; then
                local geo_info=$(geoiplookup "$ip_address" 2>/dev/null)
                [[ -n "$geo_info" ]] && echo "Localização: $geo_info"
            fi
        else
            echo -e "${RED}❌ Falha na resolução DNS${NC}"
        fi
    fi
    
    echo ""
    echo -e "${BLUE}[📋 Informações WHOIS]${NC}"
    if command -v whois &>/dev/null; then
        local whois_info=$(timeout 10 whois "$domain" 2>/dev/null | head -20)
        if [[ -n "$whois_info" ]]; then
            echo "$whois_info"
        else
            echo "Informações WHOIS não disponíveis"
        fi
    fi
    
    log_analysis "DOMAIN" "$domain" "BAIXO" "5"
}

# Análise de hash
analyze_hash_interactive() {
    echo -e "${CYAN}🔢 ANÁLISE DE HASH${NC}"
    echo "=================="
    echo ""
    
    echo "Digite o hash para análise:"
    echo -n "➤ "
    read -r hash
    
    hash=$(sanitize_input "$hash")
    
    if [[ -z "$hash" ]]; then
        echo -e "${RED}❌ Hash não fornecido${NC}"
        return 1
    fi
    
    # Determinar tipo de hash
    local hash_type=""
    if validate_input "$hash" "hash_md5"; then
        hash_type="MD5"
    elif validate_input "$hash" "hash_sha1"; then
        hash_type="SHA1"
    elif validate_input "$hash" "hash_sha256"; then
        hash_type="SHA256"
    else
        echo -e "${RED}❌ Formato de hash não reconhecido${NC}"
        return 1
    fi
    
    echo ""
    echo -e "${YELLOW}🔍 Analisando hash $hash_type: $hash${NC}"
    echo ""
    
    echo -e "${BLUE}[🔢 Informações do Hash]${NC}"
    echo "Tipo: $hash_type"
    echo "Hash: $hash"
    echo "Comprimento: ${#hash} caracteres"
    
    # Verificar em APIs se disponível
    if is_api_configured "virustotal"; then
        echo ""
        echo -e "${BLUE}[🌐 VirusTotal]${NC}"
        local vt_result=$(check_virustotal_file "$hash")
        echo "$vt_result"
    fi
    
    log_analysis "HASH" "$hash" "BAIXO" "3"
}

# Análise de email
analyze_email_interactive() {
    echo -e "${CYAN}📧 ANÁLISE DE EMAIL${NC}"
    echo "=================="
    echo ""
    
    echo "Digite o endereço de email para análise:"
    echo -n "➤ "
    read -r email
    
    email=$(sanitize_input "$email")
    
    if [[ -z "$email" ]]; then
        echo -e "${RED}❌ Email não fornecido${NC}"
        return 1
    fi
    
    if ! validate_input "$email" "email"; then
        echo -e "${RED}❌ Formato de email inválido${NC}"
        return 1
    fi
    
    echo ""
    echo -e "${YELLOW}🔍 Analisando email: $email${NC}"
    echo ""
    
    # Extrair domínio do email
    local domain=$(echo "$email" | cut -d'@' -f2)
    
    echo -e "${BLUE}[📧 Informações do Email]${NC}"
    echo "Email: $email"
    echo "Domínio: $domain"
    
    # Verificar domínio
    echo ""
    echo -e "${BLUE}[🏠 Verificação do Domínio]${NC}"
    if command -v dig &>/dev/null; then
        local mx_record=$(dig +short MX "$domain" 2>/dev/null)
        if [[ -n "$mx_record" ]]; then
            echo "Registro MX: $mx_record"
        else
            echo -e "${YELLOW}⚠️  Nenhum registro MX encontrado${NC}"
        fi
    fi
    
    log_analysis "EMAIL" "$email" "BAIXO" "2"
}

# Análise de IP
analyze_ip_interactive() {
    echo -e "${CYAN}🌐 ANÁLISE DE ENDEREÇO IP${NC}"
    echo "========================="
    echo ""
    
    echo "Digite o endereço IP para análise:"
    echo -n "➤ "
    read -r ip_address
    
    ip_address=$(sanitize_input "$ip_address")
    
    if [[ -z "$ip_address" ]]; then
        echo -e "${RED}❌ IP não fornecido${NC}"
        return 1
    fi
    
    if ! validate_input "$ip_address" "ip"; then
        echo -e "${RED}❌ Formato de IP inválido${NC}"
        return 1
    fi
    
    echo ""
    echo -e "${YELLOW}🔍 Analisando IP: $ip_address${NC}"
    echo ""
    
    echo -e "${BLUE}[🌐 Informações do IP]${NC}"
    echo "Endereço: $ip_address"
    
    # Verificar se é IP privado
    if [[ "$ip_address" =~ ^10\. ]] || [[ "$ip_address" =~ ^192\.168\. ]] || [[ "$ip_address" =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\. ]]; then
        echo "Tipo: IP Privado"
    else
        echo "Tipo: IP Público"
        
        # Geolocalização
        if command -v geoiplookup &>/dev/null; then
            local geo_info=$(geoiplookup "$ip_address" 2>/dev/null)
            [[ -n "$geo_info" ]] && echo "Localização: $geo_info"
        fi
    fi
    
    # Reverse DNS
    if command -v dig &>/dev/null; then
        local reverse_dns=$(dig +short -x "$ip_address" 2>/dev/null)
        [[ -n "$reverse_dns" ]] && echo "Reverse DNS: $reverse_dns"
    fi
    
    log_analysis "IP" "$ip_address" "BAIXO" "3"
}

# Security Analyzer Tool v3.0 - Parte 3
# Configurações, relatórios e utilitários
# ========================================

# Menu de configuração de APIs
configure_apis_menu() {
    while true; do
        clear
        echo -e "${CYAN}⚙️  CONFIGURAÇÃO DE APIs${NC}"
        echo "========================"
        echo ""
        
        list_configured_apis
        
        echo ""
        echo -e "${YELLOW}OPÇÕES DE CONFIGURAÇÃO${NC}"
        echo "  [1] 🔑 Configurar VirusTotal"
        echo "  [2] 🔑 Configurar URLScan.io"
        echo "  [3] 🔑 Configurar Shodan"
        echo "  [4] 🔑 Configurar ThreatFox"
        echo "  [5] 🧪 Testar Todas as APIs"
        echo "  [6] 🗑️  Remover API"
        echo "  [0] 🔙 Voltar"
        echo ""
        echo -n "➤ "
        read -r api_choice
        
        case "$api_choice" in
            1) configure_api_interactive "virustotal" ;;
            2) configure_api_interactive "urlscan" ;;
            3) configure_api_interactive "shodan" ;;
            4) configure_api_interactive "threatfox" ;;
            5) test_all_apis ;;
            6) remove_api_menu ;;
            0) break ;;
            *) 
                echo -e "${RED}Opção inválida!${NC}"
                sleep 1
                ;;
        esac
        
        if [[ "$api_choice" != "0" ]]; then
            echo ""
            echo "Pressione ENTER para continuar..."
            read -r
        fi
    done
}

# Testar todas as APIs configuradas
test_all_apis() {
    echo -e "${CYAN}🧪 TESTANDO TODAS AS APIs${NC}"
    echo "========================="
    echo ""
    
    local apis_tested=0
    local apis_working=0
    
    for api_name in "${!SUPPORTED_APIS[@]}"; do
        if is_api_configured "$api_name"; then
            echo -n "Testando ${SUPPORTED_APIS[$api_name]}... "
            
            if test_api_connection "$api_name" >/dev/null 2>&1; then
                echo -e "${GREEN}✅ OK${NC}"
                apis_working=$((apis_working + 1))
            else
                echo -e "${RED}❌ FALHA${NC}"
            fi
            
            apis_tested=$((apis_tested + 1))
        fi
    done
    
    echo ""
    echo "Resultado: $apis_working/$apis_tested APIs funcionando"
    
    if [[ $apis_working -eq $apis_tested && $apis_tested -gt 0 ]]; then
        echo -e "${GREEN}🎉 Todas as APIs estão funcionando!${NC}"
    elif [[ $apis_working -eq 0 ]]; then
        echo -e "${RED}❌ Nenhuma API está funcionando${NC}"
    else
        echo -e "${YELLOW}⚠️  Algumas APIs precisam de atenção${NC}"
    fi
}

# Menu para remover APIs
remove_api_menu() {
    echo -e "${CYAN}🗑️  REMOVER CONFIGURAÇÃO DE API${NC}"
    echo "==============================="
    echo ""
    
    local configured_apis=()
    for api_name in "${!SUPPORTED_APIS[@]}"; do
        if is_api_configured "$api_name"; then
            configured_apis+=("$api_name")
        fi
    done
    
    if [[ ${#configured_apis[@]} -eq 0 ]]; then
        echo "Nenhuma API configurada para remover."
        return
    fi
    
    echo "APIs configuradas:"
    local count=1
    for api_name in "${configured_apis[@]}"; do
        echo "  [$count] ${SUPPORTED_APIS[$api_name]}"
        count=$((count + 1))
    done
    
    echo "  [0] Cancelar"
    echo ""
    echo -n "Selecione a API para remover: "
    read -r remove_choice
    
    if [[ "$remove_choice" =~ ^[1-9][0-9]*$ ]] && [[ $remove_choice -le ${#configured_apis[@]} ]]; then
        local api_to_remove="${configured_apis[$((remove_choice - 1))]}"
        
        echo ""
        echo -e "${YELLOW}⚠️  Tem certeza que deseja remover ${SUPPORTED_APIS[$api_to_remove]}? (s/n)${NC}"
        read -r confirm
        
        if [[ "$confirm" =~ ^[Ss]$ ]]; then
            remove_api_key "$api_to_remove"
            echo -e "${GREEN}✅ API removida com sucesso${NC}"
        else
            echo "Operação cancelada"
        fi
    elif [[ "$remove_choice" != "0" ]]; then
        echo -e "${RED}Opção inválida${NC}"
    fi
}

# Menu de relatórios
reports_menu() {
    while true; do
        clear
        echo -e "${CYAN}📊 GERENCIAMENTO DE RELATÓRIOS${NC}"
        echo "=============================="
        echo ""
        
        echo -e "${YELLOW}OPÇÕES DE RELATÓRIOS${NC}"
        echo "  [1] 📋 Listar Relatórios"
        echo "  [2] 🌐 Abrir Relatório"
        echo "  [3] 🗑️  Limpar Relatórios Antigos"
        echo "  [4] 📊 Estatísticas de Relatórios"
        echo "  [0] 🔙 Voltar"
        echo ""
        echo -n "➤ "
        read -r report_choice
        
        case "$report_choice" in
            1) 
                list_reports
                ;;
            2) 
                open_report_menu
                ;;
            3) 
                cleanup_old_reports
                ;;
            4) 
                show_report_statistics
                ;;
            0) 
                break
                ;;
            *) 
                echo -e "${RED}Opção inválida!${NC}"
                sleep 1
                ;;
        esac
        
        if [[ "$report_choice" != "0" ]]; then
            echo ""
            echo "Pressione ENTER para continuar..."
            read -r
        fi
    done
}

# Menu para abrir relatório específico
open_report_menu() {
    echo -e "${CYAN}🌐 ABRIR RELATÓRIO${NC}"
    echo "=================="
    echo ""
    
    local reports=($(find "$REPORTS_DIR" -name "*.html" -type f 2>/dev/null | sort -r))
    
    if [[ ${#reports[@]} -eq 0 ]]; then
        echo "Nenhum relatório encontrado."
        return
    fi
    
    echo "Relatórios disponíveis:"
    local count=1
    for report in "${reports[@]}"; do
        local report_name=$(basename "$report")
        local report_date=$(stat -c %y "$report" 2>/dev/null | cut -d' ' -f1,2 | cut -d'.' -f1)
        
        printf "%2d. %s (%s)\n" "$count" "$report_name" "$report_date"
        count=$((count + 1))
    done
    
    echo "  [0] Cancelar"
    echo ""
    echo -n "Selecione o relatório para abrir: "
    read -r report_choice
    
    if [[ "$report_choice" =~ ^[1-9][0-9]*$ ]] && [[ $report_choice -le ${#reports[@]} ]]; then
        local selected_report="${reports[$((report_choice - 1))]}"
        echo ""
        echo -e "${YELLOW}Abrindo relatório...${NC}"
        open_report_controlled "$selected_report"
    elif [[ "$report_choice" != "0" ]]; then
        echo -e "${RED}Opção inválida${NC}"
    fi
}

# Mostrar estatísticas de relatórios
show_report_statistics() {
    echo -e "${CYAN}📊 ESTATÍSTICAS DE RELATÓRIOS${NC}"
    echo "============================="
    echo ""
    
    if [[ ! -d "$REPORTS_DIR" ]]; then
        echo "Diretório de relatórios não encontrado."
        return
    fi
    
    local total_reports=$(find "$REPORTS_DIR" -name "*.html" -type f 2>/dev/null | wc -l)
    local total_size=$(du -sh "$REPORTS_DIR" 2>/dev/null | cut -f1)
    
    echo "📋 Total de relatórios: $total_reports"
    echo "💾 Espaço utilizado: $total_size"
    
    if [[ $total_reports -gt 0 ]]; then
        echo ""
        echo "📅 Relatórios por período:"
        
        # Últimos 7 dias
        local last_week=$(find "$REPORTS_DIR" -name "*.html" -type f -mtime -7 2>/dev/null | wc -l)
        echo "  Última semana: $last_week"
        
        # Último mês
        local last_month=$(find "$REPORTS_DIR" -name "*.html" -type f -mtime -30 2>/dev/null | wc -l)
        echo "  Último mês: $last_month"
        
        # Mais antigos
        local older=$(find "$REPORTS_DIR" -name "*.html" -type f -mtime +30 2>/dev/null | wc -l)
        echo "  Mais antigos: $older"
    fi
}

# Menu de estatísticas gerais
show_statistics() {
    clear
    echo -e "${CYAN}📈 ESTATÍSTICAS DO SISTEMA${NC}"
    echo "=========================="
    echo ""
    
    # Estatísticas de logs
    echo -e "${BLUE}📝 Logs${NC}"
    analyze_logs
    
    echo ""
    echo -e "${BLUE}📊 Relatórios${NC}"
    show_report_statistics
    
    echo ""
    echo -e "${BLUE}🔑 APIs${NC}"
    local configured_apis=0
    local working_apis=0
    
    for api_name in "${!SUPPORTED_APIS[@]}"; do
        if is_api_configured "$api_name"; then
            configured_apis=$((configured_apis + 1))
            
            if test_api_connection "$api_name" >/dev/null 2>&1; then
                working_apis=$((working_apis + 1))
            fi
        fi
    done
    
    echo "APIs configuradas: $configured_apis/${#SUPPORTED_APIS[@]}"
    echo "APIs funcionando: $working_apis/$configured_apis"
    
    echo ""
    echo -e "${BLUE}💾 Sistema${NC}"
    echo "Versão: $APP_VERSION"
    echo "Diretório de configuração: $CONFIG_DIR"
    
    local config_size=$(du -sh "$CONFIG_DIR" 2>/dev/null | cut -f1)
    echo "Espaço utilizado: $config_size"
}

# Menu de logs
logs_menu() {
    while true; do
        clear
        echo -e "${CYAN}📝 VISUALIZAÇÃO DE LOGS${NC}"
        echo "======================"
        echo ""
        
        echo -e "${YELLOW}OPÇÕES DE LOGS${NC}"
        echo "  [1] 📄 Ver Logs Recentes"
        echo "  [2] 🔍 Buscar nos Logs"
        echo "  [3] 📊 Estatísticas de Logs"
        echo "  [4] 🔄 Monitorar em Tempo Real"
        echo "  [5] 📤 Exportar Logs"
        echo "  [6] 🗑️  Limpar Logs Antigos"
        echo "  [0] 🔙 Voltar"
        echo ""
        echo -n "➤ "
        read -r log_choice
        
        case "$log_choice" in
            1) 
                echo ""
                echo -e "${CYAN}📄 LOGS RECENTES (últimas 50 linhas)${NC}"
                echo "===================================="
                tail -50 "$LOG_FILE" 2>/dev/null || echo "Arquivo de log não encontrado"
                ;;
            2) 
                echo ""
                echo "Digite o termo para buscar:"
                read -r search_term
                echo ""
                echo -e "${CYAN}🔍 RESULTADOS DA BUSCA${NC}"
                echo "====================="
                search_logs "$search_term"
                ;;
            3) 
                echo ""
                analyze_logs
                ;;
            4) 
                echo ""
                echo -e "${CYAN}🔄 MONITORAMENTO EM TEMPO REAL${NC}"
                echo "=============================="
                echo "Pressione Ctrl+C para parar"
                echo ""
                tail_logs
                ;;
            5) 
                echo ""
                echo "Digite o nome do arquivo para exportar:"
                read -r export_file
                export_logs "" "" "$export_file"
                ;;
            6) 
                cleanup_old_logs
                ;;
            0) 
                break
                ;;
            *) 
                echo -e "${RED}Opção inválida!${NC}"
                sleep 1
                ;;
        esac
        
        if [[ "$log_choice" != "0" && "$log_choice" != "4" ]]; then
            echo ""
            echo "Pressione ENTER para continuar..."
            read -r
        fi
    done
}

# Menu de manutenção
maintenance_menu() {
    clear
    echo -e "${CYAN}🔧 MANUTENÇÃO DO SISTEMA${NC}"
    echo "======================="
    echo ""
    
    echo -e "${YELLOW}OPÇÕES DE MANUTENÇÃO${NC}"
    echo "  [1] 🗑️  Limpar Cache"
    echo "  [2] 📊 Limpar Relatórios Antigos"
    echo "  [3] 📝 Limpar Logs Antigos"
    echo "  [4] 🔄 Verificar Integridade"
    echo "  [5] 📦 Backup de Configurações"
    echo "  [6] 🧹 Limpeza Completa"
    echo "  [0] 🔙 Voltar"
    echo ""
    echo -n "➤ "
    read -r maintenance_choice
    
    case "$maintenance_choice" in
        1) 
            echo ""
            echo -e "${YELLOW}🗑️  Limpando cache...${NC}"
            rm -rf "$CACHE_DIR"/*
            create_secure_directory "$CACHE_DIR"
            echo -e "${GREEN}✅ Cache limpo${NC}"
            ;;
        2) 
            echo ""
            cleanup_old_reports
            ;;
        3) 
            echo ""
            cleanup_old_logs
            ;;
        4) 
            echo ""
            echo -e "${YELLOW}🔄 Verificando integridade...${NC}"
            check_system_dependencies
            ;;
        5) 
            echo ""
            backup_configurations
            ;;
        6) 
            echo ""
            full_cleanup
            ;;
        0) 
            return
            ;;
        *) 
            echo -e "${RED}Opção inválida!${NC}"
            ;;
    esac
    
    if [[ "$maintenance_choice" != "0" ]]; then
        echo ""
        echo "Pressione ENTER para continuar..."
        read -r
    fi
}

# Backup de configurações
backup_configurations() {
    echo -e "${YELLOW}📦 Criando backup de configurações...${NC}"
    
    local backup_dir="$HOME/security_analyzer_backup_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$backup_dir"
    
    # Copiar configurações (sem chaves de API por segurança)
    cp -r "$CONFIG_DIR" "$backup_dir/" 2>/dev/null || true
    
    # Remover chaves de API do backup
    rm -f "$backup_dir/.security_analyzer/api_keys.enc" 2>/dev/null
    
    # Criar arquivo de informações
    cat > "$backup_dir/backup_info.txt" << EOF
Security Analyzer Tool - Backup
Data: $(date)
Versão: $APP_VERSION
Sistema: $(uname -a)

Conteúdo:
- Logs de análise
- Relatórios HTML
- Cache (se aplicável)

NOTA: Chaves de API não foram incluídas por segurança
EOF
    
    echo -e "${GREEN}✅ Backup criado em: $backup_dir${NC}"
}

# Limpeza completa
full_cleanup() {
    echo -e "${YELLOW}🧹 Executando limpeza completa...${NC}"
    echo ""
    
    echo "⚠️  Esta operação irá:"
    echo "  - Limpar todo o cache"
    echo "  - Remover relatórios antigos"
    echo "  - Limpar logs antigos"
    echo "  - Otimizar arquivos de configuração"
    echo ""
    echo "Deseja continuar? (s/n)"
    read -r confirm_cleanup
    
    if [[ "$confirm_cleanup" =~ ^[Ss]$ ]]; then
        # Limpar cache
        rm -rf "$CACHE_DIR"/*
        create_secure_directory "$CACHE_DIR"
        echo "✅ Cache limpo"
        
        # Limpar relatórios antigos
        cleanup_old_reports
        
        # Limpar logs antigos
        cleanup_old_logs
        
        echo ""
        echo -e "${GREEN}🎉 Limpeza completa concluída!${NC}"
    else
        echo "Operação cancelada"
    fi
}

# Security Analyzer Tool v3.0 - Parte Final
# Loop principal e funções de suporte
# ========================================

# Executar testes do sistema
run_system_tests() {
    clear
    echo -e "${CYAN}🧪 EXECUTANDO TESTES DO SISTEMA${NC}"
    echo "==============================="
    echo ""
    
    local tests_passed=0
    local tests_total=0
    
    # Teste 1: Verificar dependências
    echo -n "Teste 1: Dependências do sistema... "
    tests_total=$((tests_total + 1))
    
    local missing_deps=()
    local deps=("curl" "jq" "dig" "whois" "file" "openssl" "python3")
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &>/dev/null; then
            missing_deps+=("$dep")
        fi
    done
    
    if [[ ${#missing_deps[@]} -eq 0 ]]; then
        echo -e "${GREEN}✅ PASSOU${NC}"
        tests_passed=$((tests_passed + 1))
    else
        echo -e "${RED}❌ FALHOU (faltando: ${missing_deps[*]})${NC}"
    fi
    
    # Teste 2: Verificar diretórios
    echo -n "Teste 2: Estrutura de diretórios... "
    tests_total=$((tests_total + 1))
    
    if [[ -d "$CONFIG_DIR" && -d "$CACHE_DIR" && -d "$REPORTS_DIR" ]]; then
        echo -e "${GREEN}✅ PASSOU${NC}"
        tests_passed=$((tests_passed + 1))
    else
        echo -e "${RED}❌ FALHOU${NC}"
    fi
    
    # Teste 3: Verificar permissões
    echo -n "Teste 3: Permissões de arquivos... "
    tests_total=$((tests_total + 1))
    
    if [[ -w "$CONFIG_DIR" && -w "$CACHE_DIR" && -w "$REPORTS_DIR" ]]; then
        echo -e "${GREEN}✅ PASSOU${NC}"
        tests_passed=$((tests_passed + 1))
    else
        echo -e "${RED}❌ FALHOU${NC}"
    fi
    
    # Teste 4: Verificar módulos
    echo -n "Teste 4: Carregamento de módulos... "
    tests_total=$((tests_total + 1))
    
    if declare -f generate_html_report >/dev/null 2>&1 && \
       declare -f analyze_file >/dev/null 2>&1 && \
       declare -f analyze_url >/dev/null 2>&1; then
        echo -e "${GREEN}✅ PASSOU${NC}"
        tests_passed=$((tests_passed + 1))
    else
        echo -e "${RED}❌ FALHOU${NC}"
    fi
    
    # Teste 5: Teste de conectividade
    echo -n "Teste 5: Conectividade de rede... "
    tests_total=$((tests_total + 1))
    
    if curl -s --connect-timeout 5 "https://www.google.com" >/dev/null 2>&1; then
        echo -e "${GREEN}✅ PASSOU${NC}"
        tests_passed=$((tests_passed + 1))
    else
        echo -e "${YELLOW}⚠️  AVISO (sem conectividade)${NC}"
    fi
    
    echo ""
    echo "Resultado dos testes: $tests_passed/$tests_total passaram"
    
    if [[ $tests_passed -eq $tests_total ]]; then
        echo -e "${GREEN}🎉 Todos os testes passaram! Sistema funcionando perfeitamente.${NC}"
    elif [[ $tests_passed -ge $((tests_total * 3 / 4)) ]]; then
        echo -e "${YELLOW}⚠️  A maioria dos testes passou. Sistema funcional com limitações.${NC}"
    else
        echo -e "${RED}❌ Muitos testes falharam. Sistema pode não funcionar corretamente.${NC}"
    fi
}

# Mostrar informações sobre a ferramenta
show_about() {
    clear
    echo -e "${CYAN}"
    cat << "EOF"
╔══════════════════════════════════════════════════════════════════════════════╗
║                              SOBRE A FERRAMENTA                             ║
╚══════════════════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
    echo ""
    echo -e "${BLUE}🛡️  Security Analyzer Tool${NC}"
    echo -e "${BLUE}Versão: $APP_VERSION${NC}"
    echo -e "${BLUE}Desenvolvido por: $APP_AUTHOR${NC}"
    echo ""
    echo -e "${YELLOW}📋 DESCRIÇÃO${NC}"
    echo "Ferramenta avançada de análise de segurança da informação que integra"
    echo "múltiplas fontes de threat intelligence para detectar arquivos maliciosos,"
    echo "URLs perigosas, domínios suspeitos e atividades de phishing."
    echo ""
    echo -e "${YELLOW}✨ PRINCIPAIS FUNCIONALIDADES${NC}"
    echo "• Análise profunda de arquivos com múltiplos algoritmos de hash"
    echo "• Verificação completa de URLs com análise de certificados SSL"
    echo "• Investigação de domínios com consultas DNS e WHOIS"
    echo "• Integração com APIs de threat intelligence (VirusTotal, URLScan, etc.)"
    echo "• Geração de relatórios HTML profissionais"
    echo "• Sistema de logging avançado e auditoria"
    echo "• Criptografia de chaves de API para segurança"
    echo ""
    echo -e "${YELLOW}🔧 TECNOLOGIAS UTILIZADAS${NC}"
    echo "• Bash Script para máxima compatibilidade"
    echo "• OpenSSL para criptografia"
    echo "• cURL para comunicação com APIs"
    echo "• jq para processamento JSON"
    echo "• Python3 para servidor web de relatórios"
    echo ""
    echo -e "${YELLOW}📊 ESTATÍSTICAS DESTA SESSÃO${NC}"
    local session_analyses=$(grep -c "ANALYSIS_COMPLETE" "$LOG_FILE" 2>/dev/null || echo "0")
    local session_reports=$(find "$REPORTS_DIR" -name "*.html" -type f -mmin -60 2>/dev/null | wc -l)
    echo "• Análises realizadas: $session_analyses"
    echo "• Relatórios gerados: $session_reports"
    echo ""
    echo -e "${YELLOW}⚠️  DISCLAIMER${NC}"
    echo "Esta ferramenta é destinada apenas para fins educacionais e de segurança"
    echo "legítima. O uso inadequado é de responsabilidade do usuário."
    echo ""
    echo -e "${YELLOW}📞 SUPORTE${NC}"
    echo "Para suporte e dúvidas, consulte os logs em:"
    echo "$LOG_FILE"
}

# Mostrar ajuda e documentação
show_help() {
    clear
    echo -e "${CYAN}📚 AJUDA E DOCUMENTAÇÃO${NC}"
    echo "======================="
    echo ""
    
    echo -e "${YELLOW}🚀 GUIA RÁPIDO${NC}"
    echo ""
    echo -e "${BLUE}1. Análise de Arquivo:${NC}"
    echo "   • Selecione opção 1 no menu principal"
    echo "   • Digite o caminho completo do arquivo"
    echo "   • Aguarde a análise completa"
    echo "   • Opcionalmente gere um relatório HTML"
    echo ""
    echo -e "${BLUE}2. Análise de URL:${NC}"
    echo "   • Selecione opção 2 no menu principal"
    echo "   • Digite a URL completa (incluindo http/https)"
    echo "   • A ferramenta verificará conectividade e segurança"
    echo "   • Relatório detalhado será exibido"
    echo ""
    echo -e "${BLUE}3. Configuração de APIs:${NC}"
    echo "   • Selecione opção 7 no menu principal"
    echo "   • Escolha a API desejada"
    echo "   • Digite sua chave de API (será criptografada)"
    echo "   • Teste a conexão para verificar funcionamento"
    echo ""
    echo -e "${YELLOW}🔑 OBTENDO CHAVES DE API${NC}"
    echo ""
    echo -e "${BLUE}VirusTotal:${NC}"
    echo "   1. Acesse: https://www.virustotal.com/"
    echo "   2. Crie uma conta gratuita"
    echo "   3. Vá em 'API Key' no seu perfil"
    echo "   4. Copie a chave de 64 caracteres"
    echo ""
    echo -e "${BLUE}URLScan.io:${NC}"
    echo "   1. Acesse: https://urlscan.io/"
    echo "   2. Registre-se gratuitamente"
    echo "   3. Vá em 'Settings' > 'API'"
    echo "   4. Gere uma nova chave de API"
    echo ""
    echo -e "${BLUE}Shodan:${NC}"
    echo "   1. Acesse: https://www.shodan.io/"
    echo "   2. Crie uma conta"
    echo "   3. Vá em 'My Account'"
    echo "   4. Copie sua API Key"
    echo ""
    echo -e "${YELLOW}📋 DICAS DE USO${NC}"
    echo ""
    echo "• Mantenha suas chaves de API seguras"
    echo "• Execute análises em arquivos suspeitos em ambiente isolado"
    echo "• Verifique os logs regularmente para auditoria"
    echo "• Use relatórios HTML para documentação"
    echo "• Mantenha a ferramenta atualizada"
    echo ""
    echo -e "${YELLOW}🔧 SOLUÇÃO DE PROBLEMAS${NC}"
    echo ""
    echo -e "${BLUE}Erro de dependências:${NC}"
    echo "   Execute: ./scripts/install_dependencies.sh"
    echo ""
    echo -e "${BLUE}Problemas de permissão:${NC}"
    echo "   Verifique se tem permissão de escrita em $CONFIG_DIR"
    echo ""
    echo -e "${BLUE}APIs não funcionando:${NC}"
    echo "   • Verifique sua conexão com a internet"
    echo "   • Confirme se as chaves de API estão corretas"
    echo "   • Teste cada API individualmente"
    echo ""
    echo -e "${BLUE}Relatórios não abrindo:${NC}"
    echo "   • Verifique se Python3 está instalado"
    echo "   • Confirme se a porta 8080 está livre"
    echo "   • Tente abrir o arquivo HTML manualmente"
}

# Loop principal da aplicação
main_loop() {
    while true; do
        show_main_menu
        
        # Ler escolha do usuário com timeout
        if read -t $MENU_TIMEOUT -r choice; then
            echo ""
            
            case "$choice" in
                1)
                    analyze_file_interactive
                    ;;
                2)
                    analyze_url_interactive
                    ;;
                3)
                    analyze_domain_interactive
                    ;;
                4)
                    analyze_hash_interactive
                    ;;
                5)
                    analyze_email_interactive
                    ;;
                15)
                    analyze_email_header_interactive
                    ;;
                6)
                    analyze_ip_interactive
                    ;;
                7)
                    configure_apis_menu
                    ;;
                8)
                    reports_menu
                    ;;
                9)
                    show_statistics
                    ;;
                10)
                    logs_menu
                    ;;
                11)
                    run_system_tests
                    ;;
                12)
                    maintenance_menu
                    ;;
                13)
                    show_help
                    ;;
                14)
                    show_about
                    ;;
                0)
                    echo -e "${GREEN}Obrigado por usar o Security Analyzer Tool!${NC}"
                    echo -e "${PURPLE}$APP_AUTHOR${NC}"
                    log_info "Aplicação encerrada pelo usuário" "MAIN"
                    exit 0
                    ;;
                *)
                    echo -e "${RED}❌ Opção inválida! Tente novamente.${NC}"
                    sleep 2
                    continue
                    ;;
            esac
            
            # Pausa após cada operação (exceto sair)
            if [[ "$choice" != "0" ]]; then
                echo ""
                echo -e "${CYAN}Pressione ENTER para continuar...${NC}"
                read -r
            fi
            
        else
            # Timeout atingido
            echo ""
            echo -e "${YELLOW}⏰ Timeout atingido. Encerrando...${NC}"
            log_info "Aplicação encerrada por timeout" "MAIN"
            exit 0
        fi
    done
}

# Função principal de inicialização
main() {
    # Capturar sinais para limpeza adequada
    trap 'echo -e "\n${YELLOW}Encerrando aplicação...${NC}"; log_info "Aplicação interrompida por sinal" "MAIN"; exit 0' INT TERM
    
    # Inicializar sistema
    initialize_system
    
    # Executar loop principal
    main_loop
}

# Verificar se o script está sendo executado diretamente
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
