#!/bin/bash

# ========================================
# Security Analyzer Tool v3.0 - Versão Funcional
# Ferramenta Avançada de Análise de Segurança
# ========================================

set -euo pipefail

# Configurações
APP_NAME="Security Analyzer Tool"
APP_VERSION="3.0.0"
APP_AUTHOR="@cybersecwonderwoman"

# Diretórios
CONFIG_DIR="$HOME/.security_analyzer"
LOG_FILE="$CONFIG_DIR/analysis.log"
CACHE_DIR="$CONFIG_DIR/cache"
REPORTS_DIR="$CONFIG_DIR/reports"
API_KEYS_FILE="$CONFIG_DIR/api_keys.enc"

# Cores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Criar diretórios necessários
mkdir -p "$CONFIG_DIR" "$CACHE_DIR" "$REPORTS_DIR"

# Função de logging
log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

# Validar entrada
validate_input() {
    local input="$1"
    local type="$2"
    
    case "$type" in
        "url")
            [[ "$input" =~ ^https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(/.*)?$ ]]
            ;;
        "file")
            [[ -f "$input" && -r "$input" ]]
            ;;
        "domain")
            [[ "$input" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]
            ;;
        "email")
            [[ "$input" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]
            ;;
        "ip")
            [[ "$input" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]
            ;;
        *)
            return 1
            ;;
    esac
}

# Sanitizar entrada
sanitize_input() {
    local input="$1"
    input=$(echo "$input" | tr -d '`$(){}[]|&;<>?*')
    input=$(echo "$input" | cut -c1-1000)
    echo "$input"
}

# Banner principal
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
║                    🛡️  FERRAMENTA AVANÇADA DE SEGURANÇA  🛡️                  ║
║                              Versão 3.0.0                                   ║
╚══════════════════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
    echo -e "${PURPLE}                           @cybersecwonderwoman${NC}"
    echo ""
}

# Menu principal
show_main_menu() {
    show_banner
    echo -e "${YELLOW}╔══════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${YELLOW}║                              MENU PRINCIPAL                                 ║${NC}"
    echo -e "${YELLOW}╚══════════════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${GREEN}  [1] 📁 Analisar Arquivo${NC}          - Análise profunda de arquivos"
    echo -e "${GREEN}  [2] 🌐 Analisar URL${NC}             - Verificação completa de URLs"
    echo -e "${GREEN}  [3] 🏠 Analisar Domínio${NC}         - Investigação de domínios"
    echo -e "${GREEN}  [4] 🔢 Analisar Hash${NC}            - Consulta em bases de dados"
    echo -e "${GREEN}  [5] 📧 Analisar Email${NC}           - Verificação de endereços"
    echo -e "${GREEN}  [15] 📨 Analisar Header de Email${NC} - Análise forense de phishing/spoofing"
    echo -e "${GREEN}  [6] 🌐 Analisar IP${NC}             - Análise de endereços IP"
    echo ""
    echo -e "${BLUE}  [7] ⚙️  Configurar APIs${NC}          - Gerenciar chaves de acesso"
    echo -e "${BLUE}  [8] 📊 Relatórios${NC}               - Visualizar relatórios"
    echo -e "${BLUE}  [9] 📝 Logs${NC}                     - Visualizar logs do sistema"
    echo -e "${BLUE}  [10] 🧪 Executar Testes${NC}         - Testar funcionalidades"
    echo ""
    echo -e "${CYAN}  [11] 📚 Ajuda${NC}                   - Documentação e suporte"
    echo -e "${CYAN}  [12] ℹ️  Sobre${NC}                   - Informações da ferramenta"
    echo ""
    echo -e "${RED}  [0] 🚪 Sair${NC}                     - Encerrar programa"
    echo ""
    echo -e "${YELLOW}╔══════════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${YELLOW}║ Digite o número da opção desejada:                                          ║${NC}"
    echo -e "${YELLOW}╚══════════════════════════════════════════════════════════════════════════════╝${NC}"
    echo -n "➤ "
}

# Análise de arquivo
analyze_file() {
    echo -e "${CYAN}📁 ANÁLISE AVANÇADA DE ARQUIVO${NC}"
    echo "================================"
    echo ""
    
    echo "Digite o caminho do arquivo para análise:"
    echo -n "➤ "
    read -r file_path
    
    file_path=$(sanitize_input "$file_path")
    
    if [[ -z "$file_path" ]]; then
        echo -e "${RED}❌ Caminho não fornecido${NC}"
        return 1
    fi
    
    if ! validate_input "$file_path" "file"; then
        echo -e "${RED}❌ Arquivo não encontrado ou inacessível${NC}"
        return 1
    fi
    
    echo ""
    echo -e "${YELLOW}🔍 Analisando arquivo: $file_path${NC}"
    echo ""
    
    # Informações básicas
    echo -e "${BLUE}[📋 Informações Básicas]${NC}"
    echo "Nome: $(basename "$file_path")"
    echo "Caminho: $file_path"
    
    local file_size=$(stat -c%s "$file_path" 2>/dev/null || echo "0")
    local size_mb=$((file_size / 1024 / 1024))
    echo "Tamanho: $file_size bytes (${size_mb}MB)"
    
    local file_type=$(file -b "$file_path" 2>/dev/null || echo "Desconhecido")
    echo "Tipo: $file_type"
    
    local modified=$(stat -c%y "$file_path" 2>/dev/null | cut -d'.' -f1)
    echo "Modificado: $modified"
    
    echo ""
    
    # Hashes
    echo -e "${BLUE}[🔢 Hashes Criptográficos]${NC}"
    if command -v md5sum &>/dev/null; then
        local md5_hash=$(md5sum "$file_path" | cut -d ' ' -f 1)
        echo "MD5:    $md5_hash"
    fi
    
    if command -v sha1sum &>/dev/null; then
        local sha1_hash=$(sha1sum "$file_path" | cut -d ' ' -f 1)
        echo "SHA1:   $sha1_hash"
    fi
    
    if command -v sha256sum &>/dev/null; then
        local sha256_hash=$(sha256sum "$file_path" | cut -d ' ' -f 1)
        echo "SHA256: $sha256_hash"
    fi
    
    echo ""
    
    # Análise de risco básica
    echo -e "${BLUE}[⚖️  Avaliação de Risco]${NC}"
    local risk_score=0
    local extension="${file_path##*.}"
    extension=$(echo "$extension" | tr '[:upper:]' '[:lower:]')
    
    # Verificar extensões perigosas
    case "$extension" in
        exe|scr|bat|cmd|com|pif|vbs|js)
            risk_score=$((risk_score + 30))
            echo "⚠️  Extensão potencialmente perigosa: .$extension"
            ;;
    esac
    
    # Verificar tamanho
    if [[ $file_size -gt 50000000 ]]; then
        risk_score=$((risk_score + 10))
        echo "⚠️  Arquivo muito grande (> 50MB)"
    elif [[ $file_size -lt 1000 ]]; then
        risk_score=$((risk_score + 15))
        echo "⚠️  Arquivo muito pequeno (< 1KB)"
    fi
    
    # Determinar nível de risco
    if [[ $risk_score -ge 30 ]]; then
        echo -e "${RED}🔴 RISCO ALTO - Arquivo potencialmente perigoso${NC}"
        echo "   Recomendação: NÃO EXECUTAR"
    elif [[ $risk_score -ge 15 ]]; then
        echo -e "${YELLOW}🟡 RISCO MÉDIO - Arquivo requer atenção${NC}"
        echo "   Recomendação: Analisar com cuidado"
    else
        echo -e "${GREEN}🟢 RISCO BAIXO - Arquivo aparentemente seguro${NC}"
        echo "   Recomendação: Verificação adicional recomendada"
    fi
    
    log_message "Arquivo analisado: $file_path (risco: $risk_score)"
}

# Análise de URL
analyze_url() {
    echo -e "${CYAN}🌐 ANÁLISE AVANÇADA DE URL${NC}"
    echo "==========================="
    echo ""
    
    echo "Digite a URL para análise:"
    echo -n "➤ "
    read -r url
    
    url=$(sanitize_input "$url")
    
    if [[ -z "$url" ]]; then
        echo -e "${RED}❌ URL não fornecida${NC}"
        return 1
    fi
    
    if ! validate_input "$url" "url"; then
        echo -e "${RED}❌ Formato de URL inválido${NC}"
        return 1
    fi
    
    echo ""
    echo -e "${YELLOW}🔍 Analisando URL: $url${NC}"
    echo ""
    
    # Análise da estrutura
    echo -e "${BLUE}[🔍 Estrutura da URL]${NC}"
    local protocol=$(echo "$url" | sed -n 's|^\([^:]*\)://.*|\1|p')
    local domain=$(echo "$url" | sed -n 's|^[^:]*://\([^/]*\).*|\1|p')
    local path=$(echo "$url" | sed -n 's|^[^:]*://[^/]*\(.*\)|\1|p')
    
    echo "Protocolo: $protocol"
    echo "Domínio: $domain"
    echo "Caminho: ${path:-/}"
    
    if [[ "$protocol" == "https" ]]; then
        echo -e "${GREEN}✅ Protocolo seguro (HTTPS)${NC}"
    else
        echo -e "${YELLOW}⚠️  Protocolo inseguro (HTTP)${NC}"
    fi
    
    echo ""
    
    # Teste de conectividade
    echo -e "${BLUE}[🔗 Teste de Conectividade]${NC}"
    local http_code=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 10 "$url" 2>/dev/null)
    
    if [[ -n "$http_code" ]]; then
        echo "Código HTTP: $http_code"
        
        case "$http_code" in
            200)
                echo -e "${GREEN}✅ Site acessível${NC}"
                ;;
            301|302|303|307|308)
                echo -e "${YELLOW}🔄 Redirecionamento detectado${NC}"
                ;;
            404)
                echo -e "${RED}❌ Página não encontrada${NC}"
                ;;
            403)
                echo -e "${RED}🚫 Acesso negado${NC}"
                ;;
            *)
                echo -e "${YELLOW}⚠️  Resposta inesperada${NC}"
                ;;
        esac
    else
        echo -e "${RED}❌ Falha na conexão${NC}"
    fi
    
    echo ""
    
    # Análise de risco
    echo -e "${BLUE}[⚖️  Avaliação de Risco]${NC}"
    local risk_score=0
    
    # Verificar protocolo
    [[ "$protocol" != "https" ]] && risk_score=$((risk_score + 20))
    
    # Verificar se usa IP em vez de domínio
    if [[ "$url" =~ [0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3} ]]; then
        risk_score=$((risk_score + 25))
        echo "⚠️  URL usa endereço IP em vez de domínio"
    fi
    
    # Verificar comprimento
    if [[ ${#url} -gt 200 ]]; then
        risk_score=$((risk_score + 10))
        echo "⚠️  URL muito longa (${#url} caracteres)"
    fi
    
    # Determinar nível de risco
    if [[ $risk_score -ge 30 ]]; then
        echo -e "${RED}🔴 RISCO ALTO - URL potencialmente perigosa${NC}"
        echo "   Recomendação: NÃO ACESSAR"
    elif [[ $risk_score -ge 15 ]]; then
        echo -e "${YELLOW}🟡 RISCO MÉDIO - URL requer atenção${NC}"
        echo "   Recomendação: Acessar com cuidado"
    else
        echo -e "${GREEN}🟢 RISCO BAIXO - URL aparentemente segura${NC}"
        echo "   Recomendação: Verificação adicional recomendada"
    fi
    
    log_message "URL analisada: $url (risco: $risk_score)"
}
# Análise de domínio
analyze_domain() {
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
    
    echo -e "${BLUE}[🔍 Resolução DNS]${NC}"
    if command -v dig &>/dev/null; then
        local ip_address=$(dig +short "$domain" 2>/dev/null | head -1)
        if [[ -n "$ip_address" ]]; then
            echo "IP: $ip_address"
        else
            echo -e "${RED}❌ Falha na resolução DNS${NC}"
        fi
    else
        echo "dig não disponível"
    fi
    
    echo ""
    echo -e "${BLUE}[📋 Informações WHOIS]${NC}"
    if command -v whois &>/dev/null; then
        local whois_info=$(timeout 10 whois "$domain" 2>/dev/null | head -10)
        if [[ -n "$whois_info" ]]; then
            echo "$whois_info"
        else
            echo "Informações WHOIS não disponíveis"
        fi
    else
        echo "whois não disponível"
    fi
    
    log_message "Domínio analisado: $domain"
}

# Análise de hash
analyze_hash() {
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
    case ${#hash} in
        32)
            if [[ "$hash" =~ ^[a-fA-F0-9]{32}$ ]]; then
                hash_type="MD5"
            fi
            ;;
        40)
            if [[ "$hash" =~ ^[a-fA-F0-9]{40}$ ]]; then
                hash_type="SHA1"
            fi
            ;;
        64)
            if [[ "$hash" =~ ^[a-fA-F0-9]{64}$ ]]; then
                hash_type="SHA256"
            fi
            ;;
    esac
    
    if [[ -z "$hash_type" ]]; then
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
    
    log_message "Hash analisado: $hash ($hash_type)"
}

# Análise de email
analyze_email() {
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
    
    local domain=$(echo "$email" | cut -d'@' -f2)
    
    echo -e "${BLUE}[📧 Informações do Email]${NC}"
    echo "Email: $email"
    echo "Domínio: $domain"
    
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
    
    log_message "Email analisado: $email"
}

# Análise de Header de Email (forense de phishing/spoofing)
analyze_email_header() {
    # Esta função usa muitos condicionais '[[ ... ]] && cmd' onde a condição
    # falsa é fluxo normal (não erro). Desligamos 'errexit' localmente para
    # não abortar sob o 'set -e' global do script.
    set +e
    echo -e "${CYAN}📨 ANÁLISE DE EMAIL (Show Original / .eml)${NC}"
    echo "=========================================="
    echo ""
    echo "Você pode:"
    echo "  (a) Informar o CAMINHO de um arquivo .eml/.txt na primeira linha, ou"
    echo "  (b) COLAR o conteúdo completo (header + corpo) do 'Show Original'."
    echo -e "Para colar, termine digitando ${YELLOW}FIM${NC} em uma linha sozinha:"
    echo ""

    local header_content=""
    local line first_line_checked=0
    while IFS= read -r line; do
        [[ "$line" == "FIM" || "$line" == "fim" || "$line" == "END" ]] && break
        if [[ "$first_line_checked" -eq 0 ]]; then
            first_line_checked=1
            local trimmed="${line#"${line%%[![:space:]]*}"}"
            trimmed="${trimmed%"${trimmed##*[![:space:]]}"}"
            if [[ -n "$trimmed" && -f "$trimmed" && -r "$trimmed" ]]; then
                echo -e "${YELLOW}📂 Lendo arquivo: $trimmed${NC}"
                header_content=$(cat "$trimmed")
                break
            fi
        fi
        header_content+="$line"$'\n'
    done

    if [[ -z "${header_content//[$'\n\t ']/}" ]]; then
        echo -e "${RED}❌ Nenhum conteúdo fornecido${NC}"
        return 1
    fi

    if ! echo "$header_content" | grep -qiE "^(From|Received|Return-Path|Message-ID|Authentication-Results):"; then
        echo -e "${RED}❌ O conteúdo não parece um email válido${NC}"
        return 1
    fi

    echo ""
    echo -e "${YELLOW}🔍 Analisando (header + corpo)...${NC}"
    echo ""

    # --- Helpers locais ---
    _hdr_field() {
        local field="$1"
        echo "$header_content" | awk -v f="$field" '
            BEGIN { IGNORECASE = 1; found = 0 }
            {
                if (found) {
                    if ($0 ~ /^[ \t]+/) { line=$0; sub(/^[ \t]+/," ",line); printf "%s", line; next }
                    else { print ""; exit }
                }
                if ($0 ~ "^" f ":") { val=$0; sub("^" f ":[ \t]*","",val); printf "%s", val; found=1 }
            }
            END { if (found) print "" }'
    }
    _hdr_addr() {
        local value="$1" addr
        addr=$(echo "$value" | grep -oE '<[^>]+@[^>]+>' | head -1 | tr -d '<>')
        [[ -z "$addr" ]] && addr=$(echo "$value" | grep -oE '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' | head -1)
        echo "$addr"
    }
    _hdr_domain() { echo "$1" | sed -n 's/.*@//p' | tr '[:upper:]' '[:lower:]'; }
    _is_private_ip() {
        local ip="$1"
        [[ "$ip" =~ ^10\. || "$ip" =~ ^192\.168\. || "$ip" =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\. || "$ip" =~ ^127\. || "$ip" =~ ^169\.254\. ]]
    }

    local from_raw=$(_hdr_field "From")
    local to_raw=$(_hdr_field "To")
    local return_path=$(_hdr_field "Return-Path")
    local reply_to=$(_hdr_field "Reply-To")
    local subject=$(_hdr_field "Subject")
    local date_field=$(_hdr_field "Date")
    local message_id=$(_hdr_field "Message-ID")
    local x_mailer=$(_hdr_field "X-Mailer")
    local auth_results=$(_hdr_field "Authentication-Results")
    local received_spf=$(_hdr_field "Received-SPF")
    local dkim_sig=$(_hdr_field "DKIM-Signature")

    local from_addr=$(_hdr_addr "$from_raw")
    local from_domain=$(_hdr_domain "$from_addr")
    local return_domain=$(_hdr_domain "$(_hdr_addr "$return_path")")
    local reply_domain=$(_hdr_domain "$(_hdr_addr "$reply_to")")

    local risk_score=0

    # 1. Campos principais
    echo -e "${BLUE}[🔍 Campos Principais]${NC}"
    [[ -n "$from_raw" ]]    && echo "From: $from_raw"
    [[ -n "$to_raw" ]]      && echo "To: $to_raw"
    [[ -n "$return_path" ]] && echo "Return-Path: $return_path"
    [[ -n "$reply_to" ]]    && echo "Reply-To: $reply_to"
    [[ -n "$subject" ]]     && echo "Subject: $subject"
    [[ -n "$date_field" ]]  && echo "Date: $date_field"
    [[ -n "$message_id" ]]  && echo "Message-ID: $message_id"
    [[ -n "$x_mailer" ]]    && echo "X-Mailer: $x_mailer"
    [[ -n "$from_domain" ]] && echo "Domínio do remetente: $from_domain"

    if [[ -n "$x_mailer" ]] && echo "$x_mailer" | grep -qiE "PHP ?Mailer|Mass Mailing|bulk"; then
        echo -e "${YELLOW}⚠️  X-Mailer suspeito (envio em massa)${NC}"
        risk_score=$((risk_score + 15))
    fi
    if [[ -n "$subject" ]] && echo "$subject" | grep -qiE "urgent|immediate action|account.*(suspend|compromis|lock|block)|verify your account|password.*(expir|reset)|unusual activity|security alert"; then
        echo -e "${YELLOW}⚠️  Assunto com padrão típico de phishing${NC}"
        risk_score=$((risk_score + 10))
    fi

    # 2. Autenticação
    echo ""
    echo -e "${BLUE}[🔐 Autenticação do Remetente]${NC}"
    local spf_status=""
    [[ -n "$auth_results" ]] && spf_status=$(echo "$auth_results" | grep -oiE "spf=[a-z]+" | head -1 | cut -d'=' -f2 | tr '[:upper:]' '[:lower:]')
    [[ -z "$spf_status" && -n "$received_spf" ]] && spf_status=$(echo "$received_spf" | awk '{print tolower($1)}')
    case "$spf_status" in
        pass) echo "✅ SPF: pass" ;;
        fail) echo -e "${RED}🚨 SPF: fail (remetente não autorizado - possível spoofing)${NC}"; risk_score=$((risk_score + 30)) ;;
        softfail|neutral|none) echo -e "${YELLOW}⚠️  SPF: $spf_status${NC}"; risk_score=$((risk_score + 15)) ;;
        "") echo "❓ SPF: não encontrado" ;;
        *) echo -e "${YELLOW}⚠️  SPF: $spf_status${NC}" ;;
    esac

    local dkim_status=""
    [[ -n "$auth_results" ]] && dkim_status=$(echo "$auth_results" | grep -oiE "dkim=[a-z]+" | head -1 | cut -d'=' -f2 | tr '[:upper:]' '[:lower:]')
    case "$dkim_status" in
        pass) echo "✅ DKIM: pass" ;;
        fail) echo -e "${RED}🚨 DKIM: fail (assinatura inválida)${NC}"; risk_score=$((risk_score + 20)) ;;
        none) echo -e "${YELLOW}⚠️  DKIM: none${NC}"; risk_score=$((risk_score + 10)) ;;
        "") [[ -n "$dkim_sig" ]] && echo "❓ DKIM: assinatura presente, sem resultado" || { echo -e "${YELLOW}⚠️  DKIM: não encontrado${NC}"; risk_score=$((risk_score + 10)); } ;;
        *) echo -e "${YELLOW}⚠️  DKIM: $dkim_status${NC}" ;;
    esac
    if [[ -n "$dkim_sig" ]]; then
        local dkim_domain=$(echo "$dkim_sig" | grep -oiE "d=[a-zA-Z0-9.-]+" | head -1 | cut -d'=' -f2)
        [[ -n "$dkim_domain" ]] && echo "   Domínio assinante (DKIM d=): $dkim_domain"
    fi

    local dmarc_status=""
    [[ -n "$auth_results" ]] && dmarc_status=$(echo "$auth_results" | grep -oiE "dmarc=[a-z]+" | head -1 | cut -d'=' -f2 | tr '[:upper:]' '[:lower:]')
    case "$dmarc_status" in
        pass) echo "✅ DMARC: pass" ;;
        fail) echo -e "${RED}🚨 DMARC: fail (desalinhamento - forte indício de spoofing)${NC}"; risk_score=$((risk_score + 30)) ;;
        none) echo -e "${YELLOW}⚠️  DMARC: none${NC}"; risk_score=$((risk_score + 10)) ;;
        "") echo "❓ DMARC: não encontrado" ;;
        *) echo -e "${YELLOW}⚠️  DMARC: $dmarc_status${NC}" ;;
    esac
    local dmarc_from=""
    if [[ -n "$auth_results" ]]; then
        dmarc_from=$(echo "$auth_results" | grep -oiE "header.from=[a-zA-Z0-9.-]+" | head -1 | cut -d'=' -f2 | tr '[:upper:]' '[:lower:]')
        [[ -n "$dmarc_from" ]] && echo "   DMARC header.from: $dmarc_from"
    fi

    # 3. Rota (Received) e IPs
    echo ""
    echo -e "${BLUE}[🛤️  Rota de Entrega (Received)]${NC}"
    local hop_count=$(echo "$header_content" | grep -ciE "^Received:")
    echo "Número de servidores (hops): $hop_count"
    if [[ "$hop_count" -gt 0 ]]; then
        local ips=$(echo "$header_content" | grep -iE "^Received:|^Received-SPF:|^Authentication-Results:" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u)
        if [[ -n "$ips" ]]; then
            echo "Endereços IP identificados:"
            while IFS= read -r ip; do
                [[ -z "$ip" ]] && continue
                if _is_private_ip "$ip"; then echo "  • $ip (privado/interno)"; else echo "  • $ip (público)"; fi
            done <<< "$ips"
        fi
    fi

    # 4. Inconsistências
    echo ""
    echo -e "${BLUE}[🕵️  Detecção de Inconsistências]${NC}"
    local issues=0
    if [[ -n "$from_domain" && -n "$return_domain" ]]; then
        if [[ "$from_domain" != "$return_domain" ]]; then
            echo -e "${RED}🚨 From ($from_domain) difere do Return-Path ($return_domain)${NC}"
            risk_score=$((risk_score + 20)); issues=$((issues + 1))
        else
            echo "✅ From e Return-Path usam o mesmo domínio ($from_domain)"
        fi
    fi
    if [[ -n "$from_domain" && -n "$reply_domain" && "$from_domain" != "$reply_domain" ]]; then
        echo -e "${YELLOW}⚠️  Reply-To ($reply_domain) difere do From ($from_domain)${NC}"
        issues=$((issues + 1))
    fi
    if [[ -n "$dmarc_from" && -n "$from_domain" && "$dmarc_from" != "$from_domain" ]]; then
        echo -e "${RED}🚨 DMARC header.from ($dmarc_from) difere do From ($from_domain) - desalinhamento${NC}"
        risk_score=$((risk_score + 20)); issues=$((issues + 1))
    fi
    [[ "$issues" -eq 0 ]] && echo "✅ Nenhuma inconsistência evidente entre os campos de identidade"

    # 5. Análise de Links e Domínios (online)
    echo ""
    echo -e "${BLUE}[🔗 Links e Domínios (análise online)]${NC}"

    # Listas de apoio
    local SUSPICIOUS_TLDS="tk ml ga cf gq pw top click download zip mov xyz country kim work link"
    local SHORTENERS="bit.ly tinyurl.com goo.gl t.co ow.ly is.gd buff.ly rebrand.ly cutt.ly rb.gy shorturl.at tiny.cc"
    local BRANDS="paypal microsoft google apple amazon netflix bank bradesco itau santander nubank caixa correios"

    # Heurísticas offline sobre um host. Saída em stdout: "flags|score".
    _check_host() {
        local host; host=$(echo "$1" | tr '[:upper:]' '[:lower:]')
        local flags="" score=0 t s b tld dots
        if [[ "$host" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
            flags+="IP-como-host; "; score=$((score + 25))
        fi
        if [[ "$host" == xn--* || "$host" == *.xn--* ]]; then
            flags+="punycode/IDN; "; score=$((score + 20))
        fi
        tld="${host##*.}"
        for t in $SUSPICIOUS_TLDS; do
            [[ "$tld" == "$t" ]] && { flags+="TLD suspeito .$tld; "; score=$((score + 15)); break; }
        done
        for s in $SHORTENERS; do
            [[ "$host" == "$s" || "$host" == *".$s" ]] && { flags+="encurtador ($s); "; score=$((score + 15)); break; }
        done
        for b in $BRANDS; do
            if echo "$host" | grep -qi "$b" && ! echo "$host" | grep -qiE "(^|\.)$b\.(com|net|org|com\.br)$"; then
                flags+="possível typosquatting de '$b'; "; score=$((score + 20)); break
            fi
        done
        dots="${host//[^.]/}"
        [[ ${#dots} -ge 4 ]] && { flags+="muitos subdomínios; "; score=$((score + 10)); }
        echo "${flags}|${score}"
    }

    # DNS + idade WHOIS. Saída em stdout: "ip|score|note".
    _check_domain_online() {
        local domain="$1" ip="" score=0 note="" created cre_s days
        if command -v dig &>/dev/null; then
            ip=$(dig +short "$domain" 2>/dev/null | grep -E '^[0-9]' | head -1)
        fi
        [[ -z "$ip" ]] && { note+="não resolve em DNS; "; score=$((score + 10)); }
        if command -v whois &>/dev/null; then
            created=$(timeout 10 whois "$domain" 2>/dev/null | grep -iE "creation date|created|registered on" | head -1 | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2}')
            if [[ -n "$created" ]]; then
                cre_s=$(date -d "$created" +%s 2>/dev/null || echo "")
                if [[ -n "$cre_s" ]]; then
                    days=$(( ( $(date +%s) - cre_s ) / 86400 ))
                    if [[ $days -lt 90 ]]; then
                        note+="criado há ${days}d (RECENTE); "; score=$((score + 15))
                    else
                        note+="criado em $created; "
                    fi
                fi
            fi
        fi
        echo "${ip}|${score}|${note}"
    }

    local urls id_domains d host hres dres flags ip note http_code redirect
    urls=$(echo "$header_content" | grep -oiE 'https?://[a-zA-Z0-9./?=_%:+~#-]+' | sed 's/[).,;>"'"'"']*$//' | sort -u)
    id_domains=$(printf "%s\n%s\n%s\n" "$from_domain" "$return_domain" "$reply_domain" | grep -vE '^$' | sort -u)

    # 5a. Domínios de identidade
    if [[ -n "$id_domains" ]]; then
        echo "Domínios de identidade (From/Return-Path/Reply-To):"
        while IFS= read -r d; do
            [[ -z "$d" ]] && continue
            hres=$(_check_host "$d"); flags="${hres%|*}"
            dres=$(_check_domain_online "$d"); ip="${dres%%|*}"; note="${dres##*|}"
            local line="  • $d"
            [[ -n "$ip" ]] && line+=" → $ip"
            echo "$line"
            [[ -n "$flags" ]] && { echo -e "    ${YELLOW}⚠️  $flags${NC}"; risk_score=$((risk_score + ${hres##*|})); }
            [[ -n "$note" ]] && echo -e "    ${YELLOW}ℹ️  $note${NC}"
            dres="${dres#*|}"; risk_score=$((risk_score + ${dres%|*}))
        done <<< "$id_domains"
    fi

    # 5b. Links encontrados no header
    if [[ -n "$urls" ]]; then
        echo ""
        echo "Links encontrados no header:"
        while IFS= read -r url; do
            [[ -z "$url" ]] && continue
            host=$(echo "$url" | sed -E 's#^https?://##; s#/.*$##; s#:.*$##; s#.*@##')
            echo "  🔗 $url"
            [[ "$url" == http://* ]] && { echo -e "    ${YELLOW}⚠️  HTTP sem criptografia${NC}"; risk_score=$((risk_score + 5)); }
            echo "$url" | grep -qE '://[^/]*@' && { echo -e "    ${RED}🚨 contém '@' (destino real ofuscado)${NC}"; risk_score=$((risk_score + 20)); }
            hres=$(_check_host "$host"); flags="${hres%|*}"
            [[ -n "$flags" ]] && { echo -e "    ${YELLOW}⚠️  $flags${NC}"; risk_score=$((risk_score + ${hres##*|})); }
            dres=$(_check_domain_online "$host"); ip="${dres%%|*}"; note="${dres##*|}"
            [[ -n "$ip" ]] && echo "    DNS: $host → $ip"
            [[ -n "$note" ]] && echo "    WHOIS: $note"
            dres="${dres#*|}"; risk_score=$((risk_score + ${dres%|*}))
            if command -v curl &>/dev/null; then
                http_code=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 8 --max-time 12 "$url" 2>/dev/null)
                [[ -n "$http_code" && "$http_code" != "000" ]] && echo "    HTTP: $http_code"
                if [[ "$http_code" =~ ^30 ]]; then
                    redirect=$(curl -s -I --connect-timeout 8 --max-time 12 "$url" 2>/dev/null | grep -i '^location:' | head -1 | cut -d' ' -f2- | tr -d '\r')
                    [[ -n "$redirect" ]] && echo -e "    ${YELLOW}🔄 redireciona para: $redirect${NC}"
                fi
            fi
        done <<< "$urls"
    else
        echo ""
        echo "Nenhum link http(s) encontrado no header."
    fi

    # 5.5 Análise do corpo do email (MIME)
    echo ""
    echo -e "${BLUE}[📄 Corpo do Email (MIME)]${NC}"
    if echo "$header_content" | grep -qiE "^Content-Type:|^Content-Transfer-Encoding:|boundary="; then
        local body
        body=$(echo "$header_content" | awk 'BEGIN{b=0} /^[[:space:]]*$/{if(!b){b=1;next}} {if(b)print}')

        local ctypes
        ctypes=$(echo "$header_content" | grep -oiE "Content-Type:[ ]*[a-zA-Z0-9._/+-]+" | sed -E 's/Content-Type:[ ]*//I' | sort -u | tr '\n' ' ')
        [[ -n "$ctypes" ]] && echo "Tipos de conteúdo: $ctypes"
        local has_html="não"; echo "$header_content" | grep -qiE "Content-Type:[ ]*text/html" && has_html="sim" || true
        local has_text="não"; echo "$header_content" | grep -qiE "Content-Type:[ ]*text/plain" && has_text="sim" || true
        echo "Parte texto: $has_text | Parte HTML: $has_html"

        # URLs do corpo
        echo ""
        echo -e "${BLUE}[🔗 URLs no corpo]${NC}"
        local body_urls bu bhost bhres bdres bflags bip bnote
        body_urls=$(echo "$body" | grep -oiE 'https?://[a-zA-Z0-9./?=_%:&+~#@-]+' | sed 's/[").,;>"'"'"']*$//' | sort -u)
        if [[ -n "$body_urls" ]]; then
            while IFS= read -r bu; do
                [[ -z "$bu" ]] && continue
                bhost=$(echo "$bu" | sed -E 's#^https?://##; s#/.*$##; s#:.*$##; s#.*@##')
                echo "  🔗 $bu"
                [[ "$bu" == http://* ]] && { echo -e "    ${YELLOW}⚠️  HTTP sem criptografia${NC}"; risk_score=$((risk_score + 5)); }
                echo "$bu" | grep -qE '://[^/]*@' && { echo -e "    ${RED}🚨 contém '@' (destino ofuscado)${NC}"; risk_score=$((risk_score + 20)); } || true
                bhres=$(_check_host "$bhost"); bflags="${bhres%|*}"
                [[ -n "$bflags" ]] && { echo -e "    ${YELLOW}⚠️  $bflags${NC}"; risk_score=$((risk_score + ${bhres##*|})); }
                bdres=$(_check_domain_online "$bhost"); bip="${bdres%%|*}"; bnote="${bdres##*|}"
                [[ -n "$bip" ]] && echo "    DNS: $bhost → $bip"
                [[ -n "$bnote" ]] && echo "    WHOIS: $bnote"
                bdres="${bdres#*|}"; risk_score=$((risk_score + ${bdres%|*}))
            done <<< "$body_urls"

            # Texto visível vs destino em links HTML
            local anchor href_host text text_host
            while IFS= read -r anchor; do
                [[ -z "$anchor" ]] && continue
                href_host=$(echo "$anchor" | grep -oiE 'href="https?://[^"]+"' | head -1 | sed -E 's/href="https?:\/\///I; s#[/"].*$##')
                text=$(echo "$anchor" | sed -E 's/<[^>]+>//g')
                text_host=$(echo "$text" | grep -oiE '[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' | head -1)
                if [[ -n "$text_host" && -n "$href_host" ]] && ! echo "$href_host" | grep -qi "$text_host"; then
                    echo -e "    ${RED}🚨 Link exibe '$text_host' mas aponta para '$href_host'${NC}"
                    risk_score=$((risk_score + 25))
                fi
            done < <(echo "$body" | grep -oiE '<a[^>]+href="https?://[^"]+"[^>]*>[^<]+</a>')
        else
            echo "  Nenhuma URL encontrada no corpo."
        fi

        # Imagens embutidas (Base64) + hash
        echo ""
        echo -e "${BLUE}[🖼️  Imagens]${NC}"
        local btmp="${TEMP_DIR:-/tmp}/email_body_$$"
        mkdir -p "$btmp" 2>/dev/null
        echo "$header_content" > "$btmp/parts.txt"
        local img_count=0 img_info iext ib64 ifpath isha imd5 isize
        img_info=$(awk '
            BEGIN{IGNORECASE=1; inimg=0; inhdr=0; indata=0; data=""; ctype=""}
            /^Content-Type:[ ]*image\//{ ctype=$0; sub(/.*image\//,"",ctype); sub(/[;].*/,"",ctype); gsub(/[ \t\r]/,"",ctype); inimg=1; inhdr=1; indata=0; data=""; next }
            inimg && inhdr { if ($0 ~ /^[[:space:]]*$/) { inhdr=0; indata=1 } next }
            inimg && indata {
                if ($0 ~ /^[[:space:]]*$/ || $0 ~ /^--/) { if (data!=""){print ctype "\t" data}; inimg=0; indata=0; data=""; ctype=""; next }
                line=$0; gsub(/[ \t\r]/,"",line); data=data line
            }
            END{if(data!=""){print ctype "\t" data}}
        ' "$btmp/parts.txt")
        if [[ -n "$img_info" ]]; then
            while IFS=$'\t' read -r iext ib64; do
                [[ -z "$ib64" ]] && continue
                img_count=$((img_count + 1))
                ifpath="$btmp/img_${img_count}.${iext:-bin}"
                echo "$ib64" | base64 -d > "$ifpath" 2>/dev/null
                if [[ -s "$ifpath" ]]; then
                    isize=$(stat -c%s "$ifpath" 2>/dev/null || echo "0")
                    isha=$(sha256sum "$ifpath" 2>/dev/null | cut -d' ' -f1)
                    imd5=$(md5sum "$ifpath" 2>/dev/null | cut -d' ' -f1)
                    echo "  Imagem #$img_count (image/$iext, ${isize} bytes)"
                    echo "    SHA256: $isha"
                    echo "    MD5:    $imd5"
                else
                    echo "  Imagem #$img_count: falha ao decodificar Base64"
                fi
            done <<< "$img_info"
        fi
        # Imagens remotas
        local remote_imgs ri
        remote_imgs=$(echo "$body" | grep -oiE '<img[^>]+src="https?://[^"]+"' | grep -oiE 'https?://[^"]+' | sort -u)
        if [[ -n "$remote_imgs" ]]; then
            while IFS= read -r ri; do
                [[ -z "$ri" ]] && continue
                img_count=$((img_count + 1))
                echo "  Imagem remota: $ri"
                if echo "$body" | grep -qiE "<img[^>]+src=\"${ri//\//\\/}\"[^>]*(width=\"?1\"?|height=\"?1\"?)"; then
                    echo -e "    ${YELLOW}⚠️  possível tracking pixel (1x1)${NC}"
                fi
            done <<< "$remote_imgs"
        fi
        [[ "$img_count" -eq 0 ]] && echo "  Nenhuma imagem detectada."
        rm -rf "$btmp" 2>/dev/null
    else
        echo "Corpo MIME não detectado (parece ser apenas o header)."
    fi

    # 6. Avaliação de risco
    echo ""
    echo -e "${BLUE}[⚖️  Avaliação de Risco]${NC}"
    local risk_level
    if [[ $risk_score -ge 50 ]]; then risk_level="ALTO"
    elif [[ $risk_score -ge 25 ]]; then risk_level="MÉDIO"
    else risk_level="BAIXO"; fi
    case "$risk_level" in
        "ALTO")  echo -e "${RED}🔴 RISCO ALTO - fortes indícios de phishing/spoofing${NC}"; echo "   NÃO clique em links, NÃO responda, NÃO forneça dados" ;;
        "MÉDIO") echo -e "${YELLOW}🟡 RISCO MÉDIO - sinais suspeitos${NC}"; echo "   Verifique o remetente por outro canal antes de interagir" ;;
        "BAIXO") echo -e "${GREEN}🟢 RISCO BAIXO - autenticação consistente${NC}"; echo "   Mantenha atenção normal a conteúdo e anexos" ;;
    esac

    log_message "Header de email analisado: ${from_addr:-desconhecido} (risco=$risk_level, score=$risk_score)"
}

# Análise de IP
analyze_ip() {
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
    fi
    
    # Reverse DNS
    if command -v dig &>/dev/null; then
        local reverse_dns=$(dig +short -x "$ip_address" 2>/dev/null)
        [[ -n "$reverse_dns" ]] && echo "Reverse DNS: $reverse_dns"
    fi
    
    log_message "IP analisado: $ip_address"
}

# Configurar APIs (simplificado)
configure_apis() {
    echo -e "${CYAN}⚙️  CONFIGURAÇÃO DE APIs${NC}"
    echo "========================"
    echo ""
    
    echo "Esta funcionalidade permite configurar chaves de API para:"
    echo "• VirusTotal - Análise de arquivos e URLs"
    echo "• URLScan.io - Análise comportamental de URLs"
    echo "• Shodan - Intelligence sobre dispositivos"
    echo ""
    echo "Para configurar, edite o arquivo: $API_KEYS_FILE"
    echo ""
    echo "Formato:"
    echo "VIRUSTOTAL_API_KEY=sua_chave_aqui"
    echo "URLSCAN_API_KEY=sua_chave_aqui"
    echo "SHODAN_API_KEY=sua_chave_aqui"
    echo ""
    echo "Pressione ENTER para continuar..."
    read -r
}

# Ver relatórios
view_reports() {
    echo -e "${CYAN}📊 RELATÓRIOS${NC}"
    echo "============="
    echo ""
    
    if [[ -d "$REPORTS_DIR" ]]; then
        local reports=($(find "$REPORTS_DIR" -name "*.html" -type f 2>/dev/null | sort -r))
        
        if [[ ${#reports[@]} -gt 0 ]]; then
            echo "Relatórios encontrados:"
            local count=1
            for report in "${reports[@]}"; do
                local report_name=$(basename "$report")
                local report_date=$(stat -c %y "$report" 2>/dev/null | cut -d' ' -f1,2 | cut -d'.' -f1)
                
                printf "%2d. %s (%s)\n" "$count" "$report_name" "$report_date"
                count=$((count + 1))
            done
            echo ""
            echo "Total: $((count - 1)) relatórios"
        else
            echo "Nenhum relatório encontrado."
        fi
    else
        echo "Diretório de relatórios não encontrado."
    fi
    
    echo ""
    echo "Pressione ENTER para continuar..."
    read -r
}

# Ver logs
view_logs() {
    echo -e "${CYAN}📝 LOGS DO SISTEMA${NC}"
    echo "=================="
    echo ""
    
    if [[ -f "$LOG_FILE" ]]; then
        echo "Últimas 20 entradas do log:"
        echo ""
        tail -20 "$LOG_FILE"
    else
        echo "Arquivo de log não encontrado."
    fi
    
    echo ""
    echo "Pressione ENTER para continuar..."
    read -r
}

# Executar testes
run_tests() {
    echo -e "${CYAN}🧪 EXECUTANDO TESTES${NC}"
    echo "===================="
    echo ""
    
    local tests_passed=0
    local tests_total=5
    
    # Teste 1: Verificar dependências
    echo -n "Teste 1: Dependências básicas... "
    local deps=("curl" "file" "stat")
    local missing_deps=()
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &>/dev/null; then
            missing_deps+=("$dep")
        fi
    done
    
    if [[ ${#missing_deps[@]} -eq 0 ]]; then
        echo -e "${GREEN}✅ PASSOU${NC}"
        tests_passed=$((tests_passed + 1))
    else
        echo -e "${RED}❌ FALHOU${NC}"
    fi
    
    # Teste 2: Verificar diretórios
    echo -n "Teste 2: Estrutura de diretórios... "
    if [[ -d "$CONFIG_DIR" && -d "$CACHE_DIR" && -d "$REPORTS_DIR" ]]; then
        echo -e "${GREEN}✅ PASSOU${NC}"
        tests_passed=$((tests_passed + 1))
    else
        echo -e "${RED}❌ FALHOU${NC}"
    fi
    
    # Teste 3: Verificar permissões
    echo -n "Teste 3: Permissões de escrita... "
    if [[ -w "$CONFIG_DIR" ]]; then
        echo -e "${GREEN}✅ PASSOU${NC}"
        tests_passed=$((tests_passed + 1))
    else
        echo -e "${RED}❌ FALHOU${NC}"
    fi
    
    # Teste 4: Teste de validação
    echo -n "Teste 4: Funções de validação... "
    if validate_input "https://example.com" "url" && validate_input "test@example.com" "email"; then
        echo -e "${GREEN}✅ PASSOU${NC}"
        tests_passed=$((tests_passed + 1))
    else
        echo -e "${RED}❌ FALHOU${NC}"
    fi
    
    # Teste 5: Teste de conectividade
    echo -n "Teste 5: Conectividade de rede... "
    if curl -s --connect-timeout 5 "https://www.google.com" >/dev/null 2>&1; then
        echo -e "${GREEN}✅ PASSOU${NC}"
        tests_passed=$((tests_passed + 1))
    else
        echo -e "${YELLOW}⚠️  AVISO${NC}"
    fi
    
    echo ""
    echo "Resultado: $tests_passed/$tests_total testes passaram"
    
    if [[ $tests_passed -eq $tests_total ]]; then
        echo -e "${GREEN}🎉 Todos os testes passaram!${NC}"
    elif [[ $tests_passed -ge 3 ]]; then
        echo -e "${YELLOW}⚠️  Sistema funcional com limitações${NC}"
    else
        echo -e "${RED}❌ Sistema pode não funcionar corretamente${NC}"
    fi
    
    echo ""
    echo "Pressione ENTER para continuar..."
    read -r
}

# Mostrar ajuda
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
    echo ""
    echo -e "${BLUE}2. Análise de URL:${NC}"
    echo "   • Selecione opção 2 no menu principal"
    echo "   • Digite a URL completa (incluindo http/https)"
    echo "   • A ferramenta verificará conectividade e segurança"
    echo ""
    echo -e "${BLUE}3. Configuração de APIs:${NC}"
    echo "   • Selecione opção 7 no menu principal"
    echo "   • Siga as instruções para configurar suas chaves"
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
    echo -e "${YELLOW}📋 DICAS DE USO${NC}"
    echo ""
    echo "• Execute análises em arquivos suspeitos em ambiente isolado"
    echo "• Verifique os logs regularmente para auditoria"
    echo "• Mantenha suas chaves de API seguras"
    echo "• Use a ferramenta apenas para fins legítimos"
    echo ""
    echo "Pressione ENTER para continuar..."
    read -r
}

# Mostrar informações sobre
show_about() {
    clear
    echo -e "${CYAN}ℹ️  SOBRE A FERRAMENTA${NC}"
    echo "===================="
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
    echo "• Análise de hashes e endereços IP"
    echo "• Sistema de logging avançado e auditoria"
    echo ""
    echo -e "${YELLOW}📊 ESTATÍSTICAS${NC}"
    local total_analyses=$(grep -c "analisad" "$LOG_FILE" 2>/dev/null || echo "0")
    echo "• Análises realizadas: $total_analyses"
    echo "• Diretório de configuração: $CONFIG_DIR"
    echo ""
    echo -e "${YELLOW}⚠️  DISCLAIMER${NC}"
    echo "Esta ferramenta é destinada apenas para fins educacionais e de segurança"
    echo "legítima. O uso inadequado é de responsabilidade do usuário."
    echo ""
    echo "Pressione ENTER para continuar..."
    read -r
}

# Loop principal
main_loop() {
    while true; do
        show_main_menu
        
        read -r choice
        echo ""
        
        case "$choice" in
            1)
                analyze_file
                ;;
            2)
                analyze_url
                ;;
            3)
                analyze_domain
                ;;
            4)
                analyze_hash
                ;;
            5)
                analyze_email
                ;;
            15)
                analyze_email_header
                ;;
            6)
                analyze_ip
                ;;
            7)
                configure_apis
                ;;
            8)
                view_reports
                ;;
            9)
                view_logs
                ;;
            10)
                run_tests
                ;;
            11)
                show_help
                ;;
            12)
                show_about
                ;;
            0)
                echo -e "${GREEN}Obrigado por usar o Security Analyzer Tool!${NC}"
                echo -e "${PURPLE}$APP_AUTHOR${NC}"
                log_message "Aplicação encerrada pelo usuário"
                exit 0
                ;;
            *)
                echo -e "${RED}❌ Opção inválida! Tente novamente.${NC}"
                sleep 2
                continue
                ;;
        esac
        
        echo ""
        echo -e "${CYAN}Pressione ENTER para continuar...${NC}"
        read -r
    done
}

# Verificar dependências básicas
check_dependencies() {
    local missing_deps=()
    local deps=("bash" "curl")
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" >/dev/null 2>&1; then
            missing_deps+=("$dep")
        fi
    done
    
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        echo -e "${RED}❌ Dependências básicas faltando: ${missing_deps[*]}${NC}"
        echo ""
        echo "Para instalar as dependências, execute:"
        echo "sudo apt install curl  # Ubuntu/Debian"
        echo "sudo dnf install curl  # Fedora/CentOS"
        echo "brew install curl      # macOS"
        echo ""
        exit 1
    fi
}

# Função principal
main() {
    # Verificar dependências
    check_dependencies
    
    # Inicializar log
    log_message "Security Analyzer Tool v$APP_VERSION iniciado"
    
    # Executar loop principal
    main_loop
}

# Executar se chamado diretamente
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
