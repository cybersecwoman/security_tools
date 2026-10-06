#!/bin/bash

# ========================================
# Advanced Email Header Analyzer
# Análise forense de cabeçalhos (headers) de email
# Detecção de phishing, spoofing e falhas de autenticação
# ========================================

# Carregar dependências
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../config.conf"
source "$SCRIPT_DIR/../utils/security.sh"
source "$SCRIPT_DIR/../utils/logger.sh"

# Mailers/ferramentas frequentemente associados a envios em massa / spam
SUSPICIOUS_MAILERS=("PHP Mailer" "PHPMailer" "Mass Mailing" "bulk" "X-PHP-Script" "sendmail-bulk")

# Assuntos com padrões típicos de phishing / engenharia social
PHISHING_SUBJECT_PATTERNS=("urgent" "immediate action" "account.*(suspend|compromis|lock|block)" "verify your account" "password.*(expir|reset)" "confirm your" "unusual activity" "security alert" "won|winner|prize" "invoice|payment overdue")

# ========================================
# Função principal
# ========================================
analyze_email_header() {
    local header_content="$1"
    local start_time=$(date +%s)

    log_info "Iniciando análise de header de email" "EMAIL_HEADER_ANALYZER"

    # Validação inicial
    if [[ -z "$header_content" ]]; then
        log_error "Conteúdo do header vazio" "EMAIL_HEADER_ANALYZER"
        echo -e "❌ Nenhum conteúdo de header fornecido"
        return 1
    fi

    # Verificação mínima: precisa parecer um header de email
    if ! echo "$header_content" | grep -qiE "^(From|Received|Return-Path|Message-ID|Authentication-Results):"; then
        log_error "Conteúdo não parece um header de email válido" "EMAIL_HEADER_ANALYZER"
        echo -e "❌ O conteúdo fornecido não parece um header de email válido"
        return 1
    fi

    # Inicializar resultado
    local analysis_result=""
    analysis_result+="📧 ANÁLISE AVANÇADA DE HEADER DE EMAIL\n"
    analysis_result+="======================================\n\n"

    # 1. Campos principais
    analysis_result+="$(analyze_header_fields "$header_content")\n\n"

    # 2. Autenticação (SPF/DKIM/DMARC)
    analysis_result+="$(analyze_header_authentication "$header_content")\n\n"

    # 3. Rastreamento de rota (Received) e IPs
    analysis_result+="$(analyze_header_received "$header_content")\n\n"

    # 4. Detecção de inconsistências e spoofing
    analysis_result+="$(analyze_header_inconsistencies "$header_content")\n\n"

    # 5. Análise de links e domínios (online)
    analysis_result+="$(analyze_header_links "$header_content")\n\n"

    # 5.5 Análise do corpo do email (MIME: texto, URLs, imagens)
    analysis_result+="$(analyze_email_body "$header_content")\n\n"

    # 6. Análise de risco
    local risk_level=$(calculate_header_risk "$header_content")
    analysis_result+="$(generate_header_risk_assessment "$risk_level")\n\n"

    # 7. Recomendações
    analysis_result+="$(generate_header_recommendations "$risk_level")\n\n"

    local end_time=$(date +%s)
    local duration=$((end_time - start_time))

    analysis_result+="Análise concluída em ${duration}s - $(date '+%Y-%m-%d %H:%M:%S')\n"

    # Log da análise
    local from_addr=$(extract_header_field "$header_content" "From")
    log_analysis "EMAIL_HEADER" "${from_addr:-desconhecido}" "$risk_level" "$duration"

    echo -e "$analysis_result"
    return 0
}

# ========================================
# Utilitários de extração
# ========================================

# Extrai o valor (primeira ocorrência) de um campo do header, lidando com
# "folding" (continuação em linhas iniciadas por espaço/tab).
extract_header_field() {
    local header_content="$1"
    local field="$2"

    echo "$header_content" | awk -v f="$field" '
        BEGIN { IGNORECASE = 1; found = 0 }
        {
            if (found) {
                # Linha de continuação (folding): começa com espaço ou tab
                if ($0 ~ /^[ \t]+/) {
                    line = $0
                    sub(/^[ \t]+/, " ", line)
                    printf "%s", line
                    next
                } else {
                    print ""
                    exit
                }
            }
            if ($0 ~ "^" f ":") {
                val = $0
                sub("^" f ":[ \t]*", "", val)
                printf "%s", val
                found = 1
            }
        }
        END { if (found) print "" }
    '
}

# Extrai o endereço de email (dentro de <>) ou o token com @ de um valor de campo
extract_email_address() {
    local value="$1"
    local addr

    # Preferir o conteúdo entre < e >
    addr=$(echo "$value" | grep -oE '<[^>]+@[^>]+>' | head -1 | tr -d '<>')
    if [[ -z "$addr" ]]; then
        addr=$(echo "$value" | grep -oE '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' | head -1)
    fi
    echo "$addr"
}

# Extrai o domínio de um endereço de email
extract_domain_from_email() {
    local email="$1"
    echo "$email" | sed -n 's/.*@//p' | tr '[:upper:]' '[:lower:]'
}

# ========================================
# Seção 1: Campos principais
# ========================================
analyze_header_fields() {
    local header_content="$1"
    local result=""

    result+="[🔍 Campos Principais]\n"

    local from_raw=$(extract_header_field "$header_content" "From")
    local to_raw=$(extract_header_field "$header_content" "To")
    local return_path=$(extract_header_field "$header_content" "Return-Path")
    local reply_to=$(extract_header_field "$header_content" "Reply-To")
    local subject=$(extract_header_field "$header_content" "Subject")
    local date_field=$(extract_header_field "$header_content" "Date")
    local message_id=$(extract_header_field "$header_content" "Message-ID")
    local x_mailer=$(extract_header_field "$header_content" "X-Mailer")

    [[ -n "$from_raw" ]]     && result+="From: $from_raw\n"
    [[ -n "$to_raw" ]]       && result+="To: $to_raw\n"
    [[ -n "$return_path" ]]  && result+="Return-Path: $return_path\n"
    [[ -n "$reply_to" ]]     && result+="Reply-To: $reply_to\n"
    [[ -n "$subject" ]]      && result+="Subject: $subject\n"
    [[ -n "$date_field" ]]   && result+="Date: $date_field\n"
    [[ -n "$message_id" ]]   && result+="Message-ID: $message_id\n"
    [[ -n "$x_mailer" ]]     && result+="X-Mailer: $x_mailer\n"

    # Domínio do remetente (From)
    local from_addr=$(extract_email_address "$from_raw")
    local from_domain=$(extract_domain_from_email "$from_addr")
    [[ -n "$from_domain" ]] && result+="Domínio do remetente: $from_domain\n"

    # Verificar X-Mailer suspeito
    if [[ -n "$x_mailer" ]]; then
        for mailer in "${SUSPICIOUS_MAILERS[@]}"; do
            if echo "$x_mailer" | grep -qiE "$mailer"; then
                result+="⚠️  X-Mailer suspeito (ferramenta de envio em massa): $x_mailer\n"
                break
            fi
        done
    fi

    # Verificar assunto com padrões de phishing
    if [[ -n "$subject" ]]; then
        for pattern in "${PHISHING_SUBJECT_PATTERNS[@]}"; do
            if echo "$subject" | grep -qiE "$pattern"; then
                result+="⚠️  Assunto contém padrão típico de phishing/engenharia social\n"
                break
            fi
        done
    fi

    echo -e "$result"
}

# ========================================
# Seção 2: Autenticação (SPF/DKIM/DMARC)
# ========================================
analyze_header_authentication() {
    local header_content="$1"
    local result=""

    result+="[🔐 Autenticação do Remetente]\n"

    local auth_results=$(extract_header_field "$header_content" "Authentication-Results")
    local received_spf=$(extract_header_field "$header_content" "Received-SPF")
    local dkim_sig=$(extract_header_field "$header_content" "DKIM-Signature")

    # --- SPF ---
    local spf_status=""
    if [[ -n "$auth_results" ]]; then
        spf_status=$(echo "$auth_results" | grep -oiE "spf=[a-z]+" | head -1 | cut -d'=' -f2 | tr '[:upper:]' '[:lower:]')
    fi
    if [[ -z "$spf_status" && -n "$received_spf" ]]; then
        spf_status=$(echo "$received_spf" | awk '{print tolower($1)}')
    fi

    case "$spf_status" in
        pass)        result+="✅ SPF: pass (remetente autorizado pelo domínio)\n" ;;
        fail)        result+="🚨 SPF: fail (remetente NÃO autorizado - possível spoofing)\n" ;;
        softfail)    result+="⚠️  SPF: softfail (remetente provavelmente não autorizado)\n" ;;
        neutral)     result+="⚠️  SPF: neutral (domínio não afirma nada sobre o remetente)\n" ;;
        none)        result+="⚠️  SPF: none (domínio sem registro SPF)\n" ;;
        "")          result+="❓ SPF: não encontrado no header\n" ;;
        *)           result+="⚠️  SPF: $spf_status\n" ;;
    esac

    # --- DKIM ---
    local dkim_status=""
    if [[ -n "$auth_results" ]]; then
        dkim_status=$(echo "$auth_results" | grep -oiE "dkim=[a-z]+" | head -1 | cut -d'=' -f2 | tr '[:upper:]' '[:lower:]')
    fi

    case "$dkim_status" in
        pass)   result+="✅ DKIM: pass (assinatura criptográfica válida)\n" ;;
        fail)   result+="🚨 DKIM: fail (assinatura inválida - conteúdo possivelmente adulterado)\n" ;;
        none)   result+="⚠️  DKIM: none (mensagem sem assinatura DKIM)\n" ;;
        "")
            if [[ -n "$dkim_sig" ]]; then
                result+="❓ DKIM: assinatura presente, mas sem resultado de verificação\n"
            else
                result+="⚠️  DKIM: não encontrado (mensagem sem assinatura)\n"
            fi
            ;;
        *)      result+="⚠️  DKIM: $dkim_status\n" ;;
    esac

    # Domínio assinante do DKIM (d=)
    if [[ -n "$dkim_sig" ]]; then
        local dkim_domain=$(echo "$dkim_sig" | grep -oiE "d=[a-zA-Z0-9.-]+" | head -1 | cut -d'=' -f2)
        [[ -n "$dkim_domain" ]] && result+="   Domínio assinante (DKIM d=): $dkim_domain\n"
    fi

    # --- DMARC ---
    local dmarc_status=""
    if [[ -n "$auth_results" ]]; then
        dmarc_status=$(echo "$auth_results" | grep -oiE "dmarc=[a-z]+" | head -1 | cut -d'=' -f2 | tr '[:upper:]' '[:lower:]')
    fi

    case "$dmarc_status" in
        pass)   result+="✅ DMARC: pass (alinhamento de domínio verificado)\n" ;;
        fail)   result+="🚨 DMARC: fail (falha de alinhamento - forte indício de spoofing)\n" ;;
        none)   result+="⚠️  DMARC: none (domínio sem política DMARC)\n" ;;
        "")     result+="❓ DMARC: não encontrado no header\n" ;;
        *)      result+="⚠️  DMARC: $dmarc_status\n" ;;
    esac

    # header.from informado no DMARC vs domínio assinante
    if [[ -n "$auth_results" ]]; then
        local dmarc_from=$(echo "$auth_results" | grep -oiE "header.from=[a-zA-Z0-9.-]+" | head -1 | cut -d'=' -f2)
        [[ -n "$dmarc_from" ]] && result+="   DMARC header.from: $dmarc_from\n"
    fi

    echo -e "$result"
}

# ========================================
# Seção 3: Rastreamento de rota (Received) e IPs
# ========================================
analyze_header_received() {
    local header_content="$1"
    local result=""

    result+="[🛤️  Rota de Entrega (Received)]\n"

    # Contar hops Received
    local hop_count=$(echo "$header_content" | grep -ciE "^Received:")
    result+="Número de servidores (hops): $hop_count\n"

    if [[ "$hop_count" -eq 0 ]]; then
        result+="⚠️  Nenhum cabeçalho Received encontrado\n"
        echo -e "$result"
        return
    fi

    # Listar hops (do mais recente - topo - ao mais antigo - origem)
    result+="\nCaminho (do destino de volta à origem):\n"
    local hop_num=1
    while IFS= read -r line; do
        # Remover prefixo "Received:" e espaços
        local hop=$(echo "$line" | sed -E 's/^Received:[ \t]*//')
        # Compactar espaços para legibilidade
        hop=$(echo "$hop" | tr -s ' \t' ' ' | cut -c1-120)
        result+="  [$hop_num] $hop\n"
        hop_num=$((hop_num + 1))
    done < <(echo "$header_content" | grep -iE "^Received:")

    # Extrair IPs públicos envolvidos
    result+="\nEndereços IP identificados:\n"
    local ips=$(echo "$header_content" | grep -iE "^Received:|^Received-SPF:|^Authentication-Results:" \
        | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u)

    if [[ -n "$ips" ]]; then
        while IFS= read -r ip; do
            [[ -z "$ip" ]] && continue
            if is_private_ip "$ip"; then
                result+="  • $ip (IP privado/interno)\n"
            else
                result+="  • $ip (IP público)\n"
            fi
        done <<< "$ips"
    else
        result+="  Nenhum IP identificado\n"
    fi

    echo -e "$result"
}

# Verifica se um IP é privado (RFC1918) / loopback
is_private_ip() {
    local ip="$1"
    [[ "$ip" =~ ^10\. ]] && return 0
    [[ "$ip" =~ ^192\.168\. ]] && return 0
    [[ "$ip" =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\. ]] && return 0
    [[ "$ip" =~ ^127\. ]] && return 0
    [[ "$ip" =~ ^169\.254\. ]] && return 0
    return 1
}

# ========================================
# Seção 4: Inconsistências e spoofing
# ========================================
analyze_header_inconsistencies() {
    local header_content="$1"
    local result=""

    result+="[🕵️  Detecção de Inconsistências]\n"

    local from_raw=$(extract_header_field "$header_content" "From")
    local return_path_raw=$(extract_header_field "$header_content" "Return-Path")
    local reply_to_raw=$(extract_header_field "$header_content" "Reply-To")
    local auth_results=$(extract_header_field "$header_content" "Authentication-Results")

    local from_addr=$(extract_email_address "$from_raw")
    local from_domain=$(extract_domain_from_email "$from_addr")
    local return_addr=$(extract_email_address "$return_path_raw")
    local return_domain=$(extract_domain_from_email "$return_addr")
    local reply_addr=$(extract_email_address "$reply_to_raw")
    local reply_domain=$(extract_domain_from_email "$reply_addr")

    local issues=0

    # 1. From vs Return-Path (envelope)
    if [[ -n "$from_domain" && -n "$return_domain" ]]; then
        if [[ "$from_domain" != "$return_domain" ]]; then
            result+="🚨 Domínio do 'From' ($from_domain) difere do 'Return-Path' ($return_domain)\n"
            result+="   Indício clássico de spoofing: o endereço exibido não é o envelope real.\n"
            issues=$((issues + 1))
        else
            result+="✅ From e Return-Path usam o mesmo domínio ($from_domain)\n"
        fi
    fi

    # 2. From vs Reply-To
    if [[ -n "$from_domain" && -n "$reply_domain" ]]; then
        if [[ "$from_domain" != "$reply_domain" ]]; then
            result+="⚠️  Reply-To ($reply_domain) difere do From ($from_domain) - respostas iriam para outro domínio\n"
            issues=$((issues + 1))
        fi
    fi

    # 3. Display name spoofing: nome exibido cita uma marca/banco mas o domínio é outro
    local display_name=$(echo "$from_raw" | sed -E 's/<[^>]*>//g' | tr -d '"' | sed -E 's/^[ \t]+|[ \t]+$//g')
    if [[ -n "$display_name" && -n "$from_domain" ]]; then
        if echo "$display_name" | grep -qiE "bank|paypal|microsoft|google|apple|amazon|netflix|security|suporte|support|conta|account"; then
            # Verificar se alguma palavra do nome exibido aparece no domínio
            local brand_word=$(echo "$display_name" | grep -oiE "bank|paypal|microsoft|google|apple|amazon|netflix" | head -1 | tr '[:upper:]' '[:lower:]')
            if [[ -n "$brand_word" ]] && ! echo "$from_domain" | grep -qi "$brand_word"; then
                result+="🚨 Possível spoofing do nome exibido: \"$display_name\" não corresponde ao domínio '$from_domain'\n"
                issues=$((issues + 1))
            fi
        fi
    fi

    # 4. DMARC header.from diferente do From real (desalinhamento explícito)
    if [[ -n "$auth_results" && -n "$from_domain" ]]; then
        local dmarc_from=$(echo "$auth_results" | grep -oiE "header.from=[a-zA-Z0-9.-]+" | head -1 | cut -d'=' -f2 | tr '[:upper:]' '[:lower:]')
        if [[ -n "$dmarc_from" && "$dmarc_from" != "$from_domain" ]]; then
            result+="🚨 DMARC header.from ($dmarc_from) difere do domínio do From ($from_domain) - desalinhamento de identidade\n"
            issues=$((issues + 1))
        fi
    fi

    if [[ "$issues" -eq 0 ]]; then
        result+="✅ Nenhuma inconsistência evidente entre os campos de identidade\n"
    else
        result+="\nTotal de inconsistências detectadas: $issues\n"
    fi

    echo -e "$result"
}

# ========================================
# Seção 5: Análise de links e domínios (online)
# ========================================

# Listas de apoio (compartilhadas)
HEADER_SUSPICIOUS_TLDS="tk ml ga cf gq pw top click download zip mov xyz country kim work link"
HEADER_SHORTENERS="bit.ly tinyurl.com goo.gl t.co ow.ly is.gd buff.ly rebrand.ly cutt.ly rb.gy shorturl.at tiny.cc"
HEADER_BRANDS="paypal microsoft google apple amazon netflix bank bradesco itau santander nubank caixa correios"

# Heurísticas offline sobre um host. Saída: "flags|score" (flags pode ter '; ' internos).
check_host_heuristics() {
    local host=$(echo "$1" | tr '[:upper:]' '[:lower:]')
    local flags=""
    local score=0

    if [[ "$host" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        flags+="IP-como-host; "; score=$((score + 25))
    fi
    if [[ "$host" == xn--* || "$host" == *.xn--* ]]; then
        flags+="punycode/IDN; "; score=$((score + 20))
    fi
    local tld="${host##*.}"
    for t in $HEADER_SUSPICIOUS_TLDS; do
        [[ "$tld" == "$t" ]] && { flags+="TLD suspeito .$tld; "; score=$((score + 15)); break; }
    done
    for s in $HEADER_SHORTENERS; do
        [[ "$host" == "$s" || "$host" == *".$s" ]] && { flags+="encurtador ($s); "; score=$((score + 15)); break; }
    done
    for b in $HEADER_BRANDS; do
        if echo "$host" | grep -qi "$b" && ! echo "$host" | grep -qiE "(^|\.)$b\.(com|net|org|com\.br)$"; then
            flags+="possível typosquatting de '$b'; "; score=$((score + 20)); break
        fi
    done
    local dots="${host//[^.]/}"
    [[ ${#dots} -ge 4 ]] && { flags+="muitos subdomínios; "; score=$((score + 10)); }

    echo "${flags}|${score}"
}

# Consulta DNS + idade WHOIS. Saída: "ip|score|note".
check_domain_online() {
    local domain="$1"
    local ip=""
    local score=0
    local note=""

    if command -v dig &>/dev/null; then
        ip=$(dig +short "$domain" 2>/dev/null | grep -E '^[0-9]' | head -1)
    fi
    [[ -z "$ip" ]] && { note+="não resolve em DNS; "; score=$((score + 10)); }

    if command -v whois &>/dev/null; then
        local created
        created=$(timeout 10 whois "$domain" 2>/dev/null | grep -iE "creation date|created|registered on" | head -1 | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2}')
        if [[ -n "$created" ]]; then
            local cre_s days
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

# Extrai URLs do header
extract_header_urls() {
    local header_content="$1"
    echo "$header_content" | grep -oiE 'https?://[a-zA-Z0-9./?=_%:+~#-]+' | sed 's/[).,;>"'"'"']*$//' | sort -u
}

analyze_header_links() {
    local header_content="$1"
    local result=""
    result+="[🔗 Links e Domínios (análise online)]\n"

    local from_domain=$(extract_domain_from_email "$(extract_email_address "$(extract_header_field "$header_content" "From")")")
    local return_domain=$(extract_domain_from_email "$(extract_email_address "$(extract_header_field "$header_content" "Return-Path")")")
    local reply_domain=$(extract_domain_from_email "$(extract_email_address "$(extract_header_field "$header_content" "Reply-To")")")

    # 5a. Domínios de identidade
    local id_domains=$(printf "%s\n%s\n%s\n" "$from_domain" "$return_domain" "$reply_domain" | grep -vE '^$' | sort -u)
    if [[ -n "$id_domains" ]]; then
        result+="Domínios de identidade (From/Return-Path/Reply-To):\n"
        local d hres dres flags ip note
        while IFS= read -r d; do
            [[ -z "$d" ]] && continue
            hres=$(check_host_heuristics "$d")
            dres=$(check_domain_online "$d")
            flags="${hres%|*}"
            ip="${dres%%|*}"
            note="${dres##*|}"
            result+="  • $d"
            [[ -n "$ip" ]] && result+=" → $ip"
            result+="\n"
            [[ -n "$flags" ]] && result+="    ⚠️  $flags\n"
            [[ -n "$note" ]] && result+="    ℹ️  $note\n"
        done <<< "$id_domains"
    fi

    # 5b. Links do header
    local urls=$(extract_header_urls "$header_content")
    if [[ -n "$urls" ]]; then
        result+="\nLinks encontrados no header:\n"
        local url host hres dres flags ip note http_code redirect
        while IFS= read -r url; do
            [[ -z "$url" ]] && continue
            host=$(echo "$url" | sed -E 's#^https?://##; s#/.*$##; s#:.*$##; s#.*@##')
            result+="  🔗 $url\n"
            [[ "$url" == http://* ]] && result+="    ⚠️  HTTP sem criptografia\n"
            echo "$url" | grep -qE '://[^/]*@' && result+="    🚨 contém '@' (destino real ofuscado)\n"
            hres=$(check_host_heuristics "$host")
            flags="${hres%|*}"
            [[ -n "$flags" ]] && result+="    ⚠️  $flags\n"
            dres=$(check_domain_online "$host")
            ip="${dres%%|*}"
            note="${dres##*|}"
            [[ -n "$ip" ]] && result+="    DNS: $host → $ip\n"
            [[ -n "$note" ]] && result+="    WHOIS: $note\n"
            if command -v curl &>/dev/null; then
                http_code=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 8 --max-time 12 "$url" 2>/dev/null)
                [[ -n "$http_code" && "$http_code" != "000" ]] && result+="    HTTP: $http_code\n"
                if [[ "$http_code" =~ ^30 ]]; then
                    redirect=$(curl -s -I --connect-timeout 8 --max-time 12 "$url" 2>/dev/null | grep -i '^location:' | head -1 | cut -d' ' -f2- | tr -d '\r')
                    [[ -n "$redirect" ]] && result+="    🔄 redireciona para: $redirect\n"
                fi
            fi
        done <<< "$urls"
    else
        result+="\nNenhum link http(s) encontrado no header.\n"
    fi

    echo -e "$result"
}

# Pontuação de risco agregada dos links/domínios (usada por calculate_header_risk)
calculate_links_risk() {
    local header_content="$1"
    local score=0

    local from_domain=$(extract_domain_from_email "$(extract_email_address "$(extract_header_field "$header_content" "From")")")
    local return_domain=$(extract_domain_from_email "$(extract_email_address "$(extract_header_field "$header_content" "Return-Path")")")
    local reply_domain=$(extract_domain_from_email "$(extract_email_address "$(extract_header_field "$header_content" "Reply-To")")")

    local id_domains=$(printf "%s\n%s\n%s\n" "$from_domain" "$return_domain" "$reply_domain" | grep -vE '^$' | sort -u)
    local d hres dres
    while IFS= read -r d; do
        [[ -z "$d" ]] && continue
        hres=$(check_host_heuristics "$d"); score=$((score + ${hres##*|}))
        dres=$(check_domain_online "$d"); dres="${dres#*|}"; score=$((score + ${dres%|*}))
    done <<< "$id_domains"

    local urls=$(extract_header_urls "$header_content")
    local url host hres dres
    while IFS= read -r url; do
        [[ -z "$url" ]] && continue
        host=$(echo "$url" | sed -E 's#^https?://##; s#/.*$##; s#:.*$##; s#.*@##')
        [[ "$url" == http://* ]] && score=$((score + 5))
        echo "$url" | grep -qE '://[^/]*@' && score=$((score + 20))
        hres=$(check_host_heuristics "$host"); score=$((score + ${hres##*|}))
        dres=$(check_domain_online "$host"); dres="${dres#*|}"; score=$((score + ${dres%|*}))
    done <<< "$urls"

    echo "$score"
}

# ========================================
# Seção 5.5: Análise do corpo do email (MIME)
# ========================================

# Diretório temporário para artefatos extraídos (imagens)
HEADER_BODY_TMPDIR="${TEMP_DIR:-/tmp}/email_body_$$"

# Verifica se o conteúdo tem um corpo MIME (além do header)
header_has_body() {
    local content="$1"
    # Precisa ter uma linha em branco separando header do corpo E algum Content-Type de corpo
    echo "$content" | grep -qiE "^Content-Type:|^Content-Transfer-Encoding:|boundary="
}

# Extrai o corpo (tudo após a primeira linha em branco)
extract_body() {
    local content="$1"
    echo "$content" | awk 'BEGIN{b=0} /^[[:space:]]*$/{if(!b){b=1;next}} {if(b)print}'
}

# Converte HTML simples para texto (remove tags) e extrai href/src
html_to_text() {
    sed -E 's/<[^>]+>/ /g' | sed -E 's/&nbsp;/ /g; s/&amp;/\&/g; s/&lt;/</g; s/&gt;/>/g' | tr -s ' '
}

analyze_email_body() {
    local content="$1"
    local result=""
    result+="[📄 Corpo do Email (MIME)]\n"

    if ! header_has_body "$content"; then
        result+="Corpo MIME não detectado (parece ser apenas o header).\n"
        echo -e "$result"
        return 0
    fi

    local body=$(extract_body "$content")

    # Tipos de conteúdo presentes
    local ctypes=$(echo "$content" | grep -oiE "Content-Type:[ ]*[a-zA-Z0-9._/+-]+" | sed -E 's/Content-Type:[ ]*//I' | sort -u | tr '\n' ' ')
    [[ -n "$ctypes" ]] && result+="Tipos de conteúdo: $ctypes\n"

    local has_html="não"; echo "$content" | grep -qiE "Content-Type:[ ]*text/html" && has_html="sim"
    local has_text="não"; echo "$content" | grep -qiE "Content-Type:[ ]*text/plain" && has_text="sim"
    result+="Parte texto: $has_text | Parte HTML: $has_html\n"

    # --- URLs do corpo (href, src e texto puro) ---
    result+="\n[🔗 URLs no corpo]\n"
    local body_urls
    body_urls=$(echo "$body" | grep -oiE 'https?://[a-zA-Z0-9./?=_%:&+~#@-]+' | sed 's/[").,;>"'"'"']*$//' | sort -u)
    if [[ -n "$body_urls" ]]; then
        local u host hres dres flags ip note
        while IFS= read -r u; do
            [[ -z "$u" ]] && continue
            host=$(echo "$u" | sed -E 's#^https?://##; s#/.*$##; s#:.*$##; s#.*@##')
            result+="  🔗 $u\n"
            [[ "$u" == http://* ]] && result+="    ⚠️  HTTP sem criptografia\n"
            echo "$u" | grep -qE '://[^/]*@' && result+="    🚨 contém '@' (destino ofuscado)\n"
            hres=$(check_host_heuristics "$host"); flags="${hres%|*}"
            [[ -n "$flags" ]] && result+="    ⚠️  $flags\n"
            dres=$(check_domain_online "$host"); ip="${dres%%|*}"; note="${dres##*|}"
            [[ -n "$ip" ]] && result+="    DNS: $host → $ip\n"
            [[ -n "$note" ]] && result+="    WHOIS: $note\n"
        done <<< "$body_urls"

        # Comparação texto-visível vs destino em links HTML (<a href=...>texto</a>)
        local mismatch
        mismatch=$(echo "$body" | grep -oiE '<a[^>]+href="https?://[^"]+"[^>]*>[^<]+</a>' | while IFS= read -r anchor; do
            local href_host text
            href_host=$(echo "$anchor" | grep -oiE 'href="https?://[^"]+"' | head -1 | sed -E 's/href="https?:\/\///I; s#[/"].*$##')
            text=$(echo "$anchor" | sed -E 's/<[^>]+>//g')
            # Se o texto contém um domínio diferente do href
            local text_host
            text_host=$(echo "$text" | grep -oiE '[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' | head -1)
            if [[ -n "$text_host" && -n "$href_host" ]] && ! echo "$href_host" | grep -qi "$text_host"; then
                echo "  🚨 Link exibe '$text_host' mas aponta para '$href_host'"
            fi
        done)
        [[ -n "$mismatch" ]] && result+="\n  [Texto vs destino]\n$mismatch\n"
    else
        result+="  Nenhuma URL encontrada no corpo.\n"
    fi

    # --- Imagens embutidas (Base64) ---
    result+="\n[🖼️  Imagens]\n"
    mkdir -p "$HEADER_BODY_TMPDIR" 2>/dev/null
    local img_count=0
    # Localiza blocos com Content-Type: image/* e Content-Transfer-Encoding: base64
    # Estratégia: para cada parte image/*, capturar o bloco base64 subsequente até linha em branco/boundary
    local parts_file="$HEADER_BODY_TMPDIR/parts.txt"
    echo "$content" > "$parts_file"
    # Usa awk para extrair pares (tipo, base64)
    local img_info
    img_info=$(awk '
        BEGIN{IGNORECASE=1; inimg=0; inhdr=0; indata=0; data=""; ctype=""}
        /^Content-Type:[ ]*image\//{
            ctype=$0; sub(/.*image\//,"",ctype); sub(/[;].*/,"",ctype); gsub(/[ \t\r]/,"",ctype)
            inimg=1; inhdr=1; indata=0; data=""; next
        }
        # Dentro dos headers da parte imagem, aguardamos a linha em branco que inicia o corpo
        inimg && inhdr {
            if ($0 ~ /^[[:space:]]*$/) { inhdr=0; indata=1 }
            next
        }
        # Coletando o corpo base64 até linha em branco ou boundary
        inimg && indata {
            if ($0 ~ /^[[:space:]]*$/ || $0 ~ /^--/) {
                if (data!=""){print ctype "\t" data}
                inimg=0; indata=0; data=""; ctype=""; next
            }
            line=$0; gsub(/[ \t\r]/,"",line); data=data line
        }
        END{if(data!=""){print ctype "\t" data}}
    ' "$parts_file")

    if [[ -n "$img_info" ]]; then
        local ext b64 fpath sha md5sum_ size vt_note
        while IFS=$'\t' read -r ext b64; do
            [[ -z "$b64" ]] && continue
            img_count=$((img_count + 1))
            fpath="$HEADER_BODY_TMPDIR/img_${img_count}.${ext:-bin}"
            echo "$b64" | base64 -d > "$fpath" 2>/dev/null
            if [[ -s "$fpath" ]]; then
                size=$(stat -c%s "$fpath" 2>/dev/null || echo "0")
                sha=$(sha256sum "$fpath" 2>/dev/null | cut -d' ' -f1)
                md5sum_=$(md5sum "$fpath" 2>/dev/null | cut -d' ' -f1)
                result+="  Imagem #$img_count (image/$ext, ${size} bytes)\n"
                result+="    SHA256: $sha\n"
                result+="    MD5:    $md5sum_\n"
                # VirusTotal se configurado (online)
                if declare -f is_api_configured >/dev/null 2>&1 && is_api_configured "virustotal" 2>/dev/null; then
                    local vt
                    vt=$(make_api_request "virustotal" "${VIRUSTOTAL_API_URL}/files/$sha" 2>/dev/null)
                    local mal=$(echo "$vt" | jq -r '.data.attributes.last_analysis_stats.malicious // empty' 2>/dev/null)
                    if [[ -n "$mal" && "$mal" != "0" ]]; then
                        result+="    🚨 VirusTotal: $mal engines detectaram como malicioso\n"
                    elif [[ -n "$mal" ]]; then
                        result+="    ✅ VirusTotal: limpa\n"
                    else
                        result+="    VirusTotal: hash não encontrado na base\n"
                    fi
                fi
            else
                result+="  Imagem #$img_count: falha ao decodificar Base64\n"
            fi
        done <<< "$img_info"
    fi

    # --- Imagens remotas (<img src="http...">) ---
    local remote_imgs
    remote_imgs=$(echo "$body" | grep -oiE '<img[^>]+src="https?://[^"]+"' | grep -oiE 'https?://[^"]+' | sort -u)
    if [[ -n "$remote_imgs" ]]; then
        local ri rhost
        while IFS= read -r ri; do
            [[ -z "$ri" ]] && continue
            img_count=$((img_count + 1))
            rhost=$(echo "$ri" | sed -E 's#^https?://##; s#/.*$##')
            result+="  Imagem remota: $ri\n"
            # Possível tracking pixel (dimensões 1x1 no atributo)
            if echo "$body" | grep -qiE "<img[^>]+src=\"${ri//\//\\/}\"[^>]*(width=\"?1\"?|height=\"?1\"?)"; then
                result+="    ⚠️  possível tracking pixel (1x1)\n"
            fi
        done <<< "$remote_imgs"
    fi

    [[ "$img_count" -eq 0 ]] && result+="  Nenhuma imagem detectada.\n"

    # Limpeza dos artefatos temporários
    rm -rf "$HEADER_BODY_TMPDIR" 2>/dev/null

    echo -e "$result"
}

# Pontuação de risco do corpo
calculate_body_risk() {
    local content="$1"
    local score=0

    header_has_body "$content" || { echo 0; return; }
    local body=$(extract_body "$content")

    # URLs do corpo
    local body_urls
    body_urls=$(echo "$body" | grep -oiE 'https?://[a-zA-Z0-9./?=_%:&+~#@-]+' | sed 's/[").,;>"'"'"']*$//' | sort -u)
    local u host hres dres
    while IFS= read -r u; do
        [[ -z "$u" ]] && continue
        host=$(echo "$u" | sed -E 's#^https?://##; s#/.*$##; s#:.*$##; s#.*@##')
        [[ "$u" == http://* ]] && score=$((score + 5))
        echo "$u" | grep -qE '://[^/]*@' && score=$((score + 20))
        hres=$(check_host_heuristics "$host"); score=$((score + ${hres##*|}))
        dres=$(check_domain_online "$host"); dres="${dres#*|}"; score=$((score + ${dres%|*}))
    done <<< "$body_urls"

    # Texto vs destino divergente
    local mismatch_count
    mismatch_count=$(echo "$body" | grep -oiE '<a[^>]+href="https?://[^"]+"[^>]*>[^<]+</a>' | while IFS= read -r anchor; do
        local href_host text text_host
        href_host=$(echo "$anchor" | grep -oiE 'href="https?://[^"]+"' | head -1 | sed -E 's/href="https?:\/\///I; s#[/"].*$##')
        text=$(echo "$anchor" | sed -E 's/<[^>]+>//g')
        text_host=$(echo "$text" | grep -oiE '[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' | head -1)
        if [[ -n "$text_host" && -n "$href_host" ]] && ! echo "$href_host" | grep -qi "$text_host"; then
            echo "x"
        fi
    done | grep -c "x")
    [[ "$mismatch_count" -gt 0 ]] && score=$((score + mismatch_count * 25))

    echo "$score"
}

# ========================================
# Seção 6: Cálculo de risco
# ========================================
calculate_header_risk() {
    local header_content="$1"
    local risk_score=0

    local auth_results=$(extract_header_field "$header_content" "Authentication-Results")
    local received_spf=$(extract_header_field "$header_content" "Received-SPF")

    # SPF
    local spf_status=""
    [[ -n "$auth_results" ]] && spf_status=$(echo "$auth_results" | grep -oiE "spf=[a-z]+" | head -1 | cut -d'=' -f2 | tr '[:upper:]' '[:lower:]')
    [[ -z "$spf_status" && -n "$received_spf" ]] && spf_status=$(echo "$received_spf" | awk '{print tolower($1)}')
    case "$spf_status" in
        fail)            risk_score=$((risk_score + 30)) ;;
        softfail|neutral|none) risk_score=$((risk_score + 15)) ;;
    esac

    # DKIM
    local dkim_status=""
    [[ -n "$auth_results" ]] && dkim_status=$(echo "$auth_results" | grep -oiE "dkim=[a-z]+" | head -1 | cut -d'=' -f2 | tr '[:upper:]' '[:lower:]')
    case "$dkim_status" in
        fail) risk_score=$((risk_score + 20)) ;;
        none) risk_score=$((risk_score + 10)) ;;
    esac

    # DMARC
    local dmarc_status=""
    [[ -n "$auth_results" ]] && dmarc_status=$(echo "$auth_results" | grep -oiE "dmarc=[a-z]+" | head -1 | cut -d'=' -f2 | tr '[:upper:]' '[:lower:]')
    case "$dmarc_status" in
        fail) risk_score=$((risk_score + 30)) ;;
        none) risk_score=$((risk_score + 10)) ;;
    esac

    # From vs Return-Path
    local from_domain=$(extract_domain_from_email "$(extract_email_address "$(extract_header_field "$header_content" "From")")")
    local return_domain=$(extract_domain_from_email "$(extract_email_address "$(extract_header_field "$header_content" "Return-Path")")")
    if [[ -n "$from_domain" && -n "$return_domain" && "$from_domain" != "$return_domain" ]]; then
        risk_score=$((risk_score + 20))
    fi

    # DMARC header.from desalinhado
    if [[ -n "$auth_results" && -n "$from_domain" ]]; then
        local dmarc_from=$(echo "$auth_results" | grep -oiE "header.from=[a-zA-Z0-9.-]+" | head -1 | cut -d'=' -f2 | tr '[:upper:]' '[:lower:]')
        [[ -n "$dmarc_from" && "$dmarc_from" != "$from_domain" ]] && risk_score=$((risk_score + 20))
    fi

    # X-Mailer suspeito
    local x_mailer=$(extract_header_field "$header_content" "X-Mailer")
    if [[ -n "$x_mailer" ]]; then
        for mailer in "${SUSPICIOUS_MAILERS[@]}"; do
            if echo "$x_mailer" | grep -qiE "$mailer"; then
                risk_score=$((risk_score + 15))
                break
            fi
        done
    fi

    # Assunto com padrão de phishing
    local subject=$(extract_header_field "$header_content" "Subject")
    if [[ -n "$subject" ]]; then
        for pattern in "${PHISHING_SUBJECT_PATTERNS[@]}"; do
            if echo "$subject" | grep -qiE "$pattern"; then
                risk_score=$((risk_score + 10))
                break
            fi
        done
    fi

    # Risco agregado de links e domínios (online)
    local links_score=$(calculate_links_risk "$header_content")
    [[ -n "$links_score" ]] && risk_score=$((risk_score + links_score))

    # Risco agregado do corpo do email (URLs e links enganosos)
    local body_score=$(calculate_body_risk "$header_content")
    [[ -n "$body_score" ]] && risk_score=$((risk_score + body_score))

    # Determinar nível
    if [[ $risk_score -ge 50 ]]; then
        echo "ALTO"
    elif [[ $risk_score -ge 25 ]]; then
        echo "MÉDIO"
    else
        echo "BAIXO"
    fi
}

# ========================================
# Seção 6: Avaliação e recomendações
# ========================================
generate_header_risk_assessment() {
    local risk_level="$1"
    local result=""

    result+="[⚖️  Avaliação de Risco]\n"

    case "$risk_level" in
        "ALTO")
            result+="🔴 RISCO ALTO - Email com fortes indícios de phishing/spoofing\n"
            result+="   Recomendação: NÃO interagir, NÃO clicar em links, NÃO responder\n"
            ;;
        "MÉDIO")
            result+="🟡 RISCO MÉDIO - Email apresenta sinais suspeitos\n"
            result+="   Recomendação: Tratar com cautela e verificar o remetente por outro canal\n"
            ;;
        "BAIXO")
            result+="🟢 RISCO BAIXO - Autenticação consistente, sem sinais evidentes de fraude\n"
            result+="   Recomendação: Mantenha atenção normal a conteúdo e anexos\n"
            ;;
    esac

    echo -e "$result"
}

generate_header_recommendations() {
    local risk_level="$1"
    local result=""

    result+="[💡 Recomendações]\n"

    case "$risk_level" in
        "ALTO")
            result+="• NÃO clique em nenhum link nem baixe anexos\n"
            result+="• NÃO responda e NÃO forneça credenciais ou dados pessoais\n"
            result+="• Reporte o email ao time de segurança / abuse do provedor\n"
            result+="• Bloqueie o remetente e o domínio de origem\n"
            result+="• Se a mensagem imita uma marca, acesse o site oficial digitando a URL manualmente\n"
            ;;
        "MÉDIO")
            result+="• Confirme a legitimidade do remetente por um canal alternativo\n"
            result+="• Passe o mouse sobre os links antes de clicar (verifique o destino real)\n"
            result+="• Desconfie de urgência e pedidos de ação imediata\n"
            result+="• Verifique registros SPF/DKIM/DMARC do domínio alegado\n"
            ;;
        "BAIXO")
            result+="• Mantenha boas práticas de higiene de email\n"
            result+="• Verifique anexos antes de abrir\n"
            result+="• Em caso de dúvida, confirme com o remetente\n"
            ;;
    esac

    echo -e "$result"
}

# ========================================
# Interface interativa
# ========================================
analyze_email_header_interactive() {
    # Cores (caso não estejam definidas pelo entry point)
    local CYAN='\033[0;36m'; local RED='\033[0;31m'; local YELLOW='\033[1;33m'; local NC='\033[0m'

    echo -e "${CYAN}📧 ANÁLISE DE EMAIL (Show Original / .eml)${NC}"
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
        # Se a PRIMEIRA linha for um caminho de arquivo existente, lê o arquivo e encerra
        if [[ "$first_line_checked" -eq 0 ]]; then
            first_line_checked=1
            local trimmed="${line#"${line%%[![:space:]]*}"}"   # trim leading
            trimmed="${trimmed%"${trimmed##*[![:space:]]}"}"     # trim trailing
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

    echo ""
    echo -e "${YELLOW}🔍 Analisando (header + corpo)...${NC}"
    echo ""

    analyze_email_header "$header_content"
}
