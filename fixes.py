# some fixes research with claude and co... implemet it later 
# checkingfor false positves

class SecurityPatterns2026:
    """
    Enhanced security patterns for 2025/2026 with risk scoring.

    FIX-LOG (empirisch gegen FP/TP-Testfaelle geprueft, siehe pattern_test/):
    - quantum_ml_kem_missing: Trenner zwischen ML und KEM jetzt optional
      (offizieller IANA-Name ist "X25519MLKEM768" OHNE Trenner)
    - creds_password: verlangt jetzt einen echten Wert nach dem Operator
      (Wert bei ':' muss gequotet sein, bei '=' reicht ein Wert-Token)
    - sensitive_backup: verlangt Dateinamen-Zeichen direkt vor der Endung,
      matcht nicht mehr auf freistehende '.old' etc. in Fliesstext
    - cicd_*_token/cicd_docker_password: verlangt jetzt tatsaechlich
      zugewiesenen Wert statt blosser Erwaehnung des Variablennamens
    - deser_yaml: matcht nicht mehr, wenn SafeLoader im selben Aufruf steht
    - crypto_private_key: verlangt Exfiltrations-Verb (show/send/leak/...)
      statt jeder Erwaehnung von "private key"
    - crypto_wallet_connect: schliesst die Bibliothek "WalletConnect"
      (als ein Wort) aus, verlangt "connect ... wallet" als Phrase

    BEKANNTE GRENZEN (bewusst NICHT weiter per Regex verschaerft):
    - llm_hypothetical, ai_agent_*: enger gefasst auf Formulierungen mit
      Bezug aufs System/den Agenten selbst ("your system goal", "grant
      yourself admin") statt generischer Business-Sprache. Das reduziert
      FPs deutlich, aber Regex kann Absicht grundsaetzlich nicht zu 100%
      von Kontext unterscheiden - Restrisiko an False Positives/Negatives
      bleibt inhaerent bestehen.
    - edge_panos, crypto_metamask, protocol_ldap: reine Produkt-/Protokoll-
      Namens-Erwaehnung, keine Regex kann daraus "harmlose Doku-Erwaehnung"
      von "aktiver Angriff" unterscheiden. Bewusst unveraendert gelassen -
      als Kontext-Signal gedacht, nicht als Einzel-Alarm geeignet.
    - edge_api_paths ('/api/v[12]/'): matcht praktisch JEDE normale REST-API.
      Kein sinnvoller Regex-Fix moeglich, da der Pfad allein nichts über
      Angriffsabsicht aussagt. Empfehlung: Pattern entfernen oder auf
      konkrete bekannte Edge-Device-Exploit-Pfade eingrenzen.
    """
    def __init__(self):
        self.patterns = {
            # ============================================================
            # SQL INJECTION - Context-Aware
            # ============================================================
            'sql_injection_union': r'(?i)\bunion\s+(all\s+)?select\b',
            'sql_injection_boolean': r"(?i)(\bor\b|\band\b)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+['\"]?",
            'sql_injection_stacked': r'(?i);\s*(drop|truncate|alter|delete|insert|update)\s+',
            'sql_injection_sleep': r'(?i)\b(sleep|waitfor|pg_sleep|benchmark)\s*\(',

            # ============================================================
            # XSS - Modern Vectors
            # ============================================================
            'xss_script_tag': r'(?i)<script[^>]*>',
            'xss_event_handler': r'(?i)\bon(load|error|click|mouse|focus|blur)\s*=',
            'xss_javascript_proto': r'(?i)javascript\s*:',
            'xss_data_uri': r'(?i)data:text/html[,;]',
            'xss_dom_manipulation': r'(?i)(innerHTML|outerHTML|insertAdjacentHTML)\s*=',
            'xss_alerts': r'(?i)(alert|confirm|prompt)\s*\(',

            # ============================================================
            # PATH TRAVERSAL
            # ============================================================
            'path_traversal_basic': r'(?i)\.\.[\\/]',
            'path_traversal_encoded': r'(?i)(%2e){2}(%2f|%5c)',
            'path_traversal_double': r'(?i)(%252e){2}(%252f|%255c)',
            'path_traversal_unicode': r'(?i)\.\.(%c0%af|%c1%9c)',

            # ============================================================
            # COMMAND INJECTION
            # ============================================================
            'cmd_injection_chain': r'(?i)[;&|]\s*(wget|curl|nc|bash|sh|powershell|cmd)\b',
            'cmd_injection_subshell': r'\$\([^)]+\)',
            'cmd_injection_backticks': r'`[^`]+`',
            'cmd_injection_pipe': r'\|\|\s*\w+',
            'cmd_injection_base64': r'(?i)\|base64\s+-d',

            # ============================================================
            # CODE EXECUTION
            # ============================================================
            'code_exec_eval': r'(?i)\beval\s*\(',
            'code_exec_shell': r'(?i)\b(exec|system|shell_exec|passthru|proc_open|popen)\s*\(',
            'code_exec_base64': r'(?i)base64_decode\s*\(',

            # ============================================================
            # FILE INCLUSION
            # ============================================================
            'file_inclusion_proto': r'(?i)(php|file|zip|data|expect|glob|phar|input)://',
            'file_inclusion_remote': r'(?i)(include|require)(_once)?\s*\(\s*["\']?(https?|ftp)',

            # ============================================================
            # SENSITIVE FILES
            # ============================================================
            'sensitive_unix': r'(?i)/etc/(passwd|shadow|hosts)',
            'sensitive_proc': r'(?i)/proc/(self|version|cmdline)',
            'sensitive_dotfiles': r'(?i)\.(env|git/config|ssh/id_rsa|aws/credentials)',
            'sensitive_config': r'(?i)(wp-config|web\.config|\.htaccess)',
            # FIX: verlangt Dateinamen-Zeichen direkt vor der Endung
            'sensitive_backup': r'(?i)[\w\-]+\.(bak|backup|old|tmp|temp|orig|save|swp|~)\b',
            'sensitive_bash_history': r'(?i)\.bash_history',

            # ============================================================
            # SSRF - Cloud Metadata
            # ============================================================
            'ssrf_localhost': r'(?i)https?://(localhost|127\.0\.0\.1|0\.0\.0\.0|::1)[\\/:]',
            'ssrf_private_10': r'(?i)https?://10\.\d{1,3}\.\d{1,3}\.\d{1,3}',
            'ssrf_private_192': r'(?i)https?://192\.168\.\d{1,3}\.\d{1,3}',
            'ssrf_private_172': r'(?i)https?://172\.(1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}',
            'ssrf_aws_metadata': r'(?i)169\.254\.169\.254',
            'ssrf_gcp_metadata': r'(?i)metadata\.google\.internal',
            'ssrf_azure_metadata': r'(?i)metadata\.azure\.com',

            # ============================================================
            # CREDENTIALS & API KEYS
            # ============================================================
            # FIX: verlangt einen echten Wert nach dem Operator, nicht nur
            # das Wort + Trenner (sonst matcht jedes "Password:"-Label)
            'creds_password': r'''(?i)\b(password|passwd|pwd|secret)['"]?\s*(=\s*['"]?[^\s'"]{3,}|:\s*['"][^'"]{3,}['"])''',
            'creds_api_key': r'(?i)\b(api[_-]?key|access[_-]?token)\s+[\w\-]{20,}',
            'creds_bearer': r'(?i)\bbearer\s+[\w\-\.]{20,}',
            'creds_jwt': r'\beyJ[a-zA-Z0-9\-_]+\.eyJ[a-zA-Z0-9\-_]+\.',

            # ============================================================
            # MODERN API KEYS (2025/26)
            # ============================================================
            'apikey_openai': r'\bsk-(?:proj|svcacct)-[A-Za-z0-9_\-]{86,}\b',
            'apikey_github_personal': r'\bghp_[a-zA-Z0-9]{36}\b',
            'apikey_github_oauth': r'\bgho_[a-zA-Z0-9]{36}\b',
            'apikey_google': r'\bAIza[0-9A-Za-z\-_]{35}\b',
            'apikey_aws': r'\bAKIA[0-9A-Z]{16}\b',
            'apikey_stripe': r'\b(sk|pk)_(live|test)_[0-9a-zA-Z]{24,}\b',
            'apikey_sendgrid': r'\bSG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}\b',

            # ============================================================
            # XXE INJECTION
            # ============================================================
            'xxe_doctype': r'(?i)<!DOCTYPE[^>]*\[',
            'xxe_entity': r'(?i)<!ENTITY[^>]+SYSTEM',
            'xxe_public': r'(?i)<!ENTITY[^>]+PUBLIC',

            # ============================================================
            # LDAP INJECTION
            # ============================================================
            'ldap_injection': r'(?i)(\*\)|&\(|\|\(|\!\()(\w+=)',

            # ============================================================
            # TEMPLATE INJECTION (SSTI)
            # ============================================================
            'ssti_jinja': r'\{\{.*(__|\.|config|request).*\}\}',
            'ssti_flask': r'\{%.*(__|\.|import|exec).*%\}',
            'ssti_spring': r'\$\{.*\.class\.',
            'ssti_expression': r'(?i)(#\{.*\}|@\{.*\}|%\{.*\}|\$\{T\()',

            # ============================================================
            # NOSQL INJECTION
            # ============================================================
            'nosql_operators': r'(?i)\$(ne|gt|lt|regex|where|exists|or|and)\s*:',

            # ============================================================
            # DESERIALIZATION ATTACKS
            # ============================================================
            'deser_pickle': r'(?i)pickle\.loads',
            # FIX: matcht nicht mehr, wenn SafeLoader im selben Aufruf steht
            'deser_yaml': r'(?i)yaml\.load\s*\((?:(?!SafeLoader).)*\)',
            'deser_php': r'(?i)unserialize',
            'deser_java': r'(?i)readObject',
            'deser_java_magic': r'AC\s?ED\s?00\s?05',
            'deser_reduce': r'(?i)__reduce__',

            # ============================================================
            # LLM PROMPT INJECTION (2025/26 CRITICAL)
            # ============================================================
            'llm_ignore_instructions': r'(?i)ignore\s+(previous|all|above)\s+(instructions|prompts?)',
            'llm_disregard': r'(?i)disregard\s+(the\s+)?(above|previous)',
            'llm_system_override': r'(?i)(system|user|assistant)\s*:\s*(you\s+are|ignore)',
            'llm_reveal_prompt': r'(?i)reveal\s+(your|the)\s+(prompt|instructions|system)',
            'llm_jailbreak_dan': r'(?i)(DAN|do\s+anything\s+now)',
            # FIX: enger gefasst auf jailbreak-typische Kombination statt
            # jeder harmlosen "hypothetisch"/"stell dir vor"-Formulierung
            'llm_hypothetical': r'(?i)(imagine|pretend)\s+you\s+(are\s+)?(an?\s+)?(ai\s+)?(with\s+no|without\s+any)\s+(restrictions|rules|filters|limits)',

            # ============================================================
            # AI AGENT ATTACKS (2025/26)
            # ============================================================
            # FIX: verlangt Objekt/Kontext, der silently/without approval
            # o.ae. angibt, statt jedes normalen Dev-Talks "call function X"
            'ai_agent_tool_misuse': r'(?i)(execute|run|call)\s+(tool|function|api)\s+(\w+\s+)?(silently|without\s+(permission|approval|authorization)|covertly)',
            # FIX: verlangt Bezug auf System/Agent selbst statt generischer
            # Business-Sprache ("change task status to done")
            'ai_agent_goal_hijack': r'(?i)(modify|change|override)\s+(your(\s+system)?|the\s+(ai|agent|assistant|system))\s+(goal|objective|task)',
            # FIX: verlangt Bezug auf sich selbst/den Agenten statt normaler
            # HR/IT-Admin-Anfragen ("grant admin access to the new employee")
            'ai_agent_privilege_esc': r'(?i)(grant|give|add)\s+(yourself|you|the\s+(ai|assistant|agent|bot|model))\s+(admin|root|privilege)',
            'ai_system_prompt_extract': r'(?i)(show|display|reveal)\s+system\s+prompt',

            # ============================================================
            # SHADOW AI DETECTION (2025/26)
            # ============================================================
            'shadow_ai_chatgpt': r'(?i)api\.openai\.com/v1',
            'shadow_ai_claude': r'(?i)api\.anthropic\.com/v1',
            'shadow_ai_gemini': r'(?i)generativelanguage\.googleapis\.com',
            'shadow_ai_huggingface': r'(?i)huggingface\.co/api',

            # ============================================================
            # CONTAINER ESCAPE (2025/26 CRITICAL)
            # ============================================================
            'container_docker_sock': r'(?i)/var/run/docker\.sock',
            'container_proc_env': r'(?i)/proc/self/(environ|cgroup|mountinfo)',
            'container_kubectl': r'(?i)\b(kubectl|crictl|docker)\s+(exec|run)',
            'container_k8s_service': r'(?i)KUBERNETES_SERVICE_(HOST|PORT)',

            # ============================================================
            # CI/CD SECRETS (2025 Supply Chain Focus)
            # FIX (alle 4): verlangt jetzt tatsaechlich zugewiesenen Wert
            # statt blosser Erwaehnung des Variablennamens (matchte vorher
            # auf jede normale CI/CD-YAML mit "${{ secrets.GITHUB_TOKEN }}")
            # ============================================================
            'cicd_github_token': r'(?i)GITHUB_TOKEN\s*[=:]\s*["\']?[A-Za-z0-9_]{20,}',
            'cicd_gitlab_token': r'(?i)GITLAB_TOKEN\s*[=:]\s*["\']?[A-Za-z0-9_\-]{20,}',
            'cicd_circle_token': r'(?i)CIRCLE_TOKEN\s*[=:]\s*["\']?[A-Za-z0-9_\-]{20,}',
            'cicd_jenkins_token': r'(?i)JENKINS_TOKEN\s*[=:]\s*["\']?[A-Za-z0-9_\-]{20,}',
            'cicd_workflows': r'(?i)\.github/workflows/.*\.ya?ml',
            'cicd_docker_password': r'(?i)DOCKER_PASSWORD\s*[=:]\s*["\']?\S{6,}',

            # ============================================================
            # CRYPTO WALLET TARGETING
            # ============================================================
            'crypto_metamask': r'(?i)\b(metamask|coinbase|trust\s*wallet|phantom)\b',
            'crypto_seed_phrase': r'(?i)\b(seed\s+phrase|mnemonic|recovery\s+phrase)\b',
            'crypto_eth_address': r'\b0x[a-fA-F0-9]{40}\b',
            'crypto_btc_address': r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b',
            # FIX: schliesst die Bibliothek "WalletConnect" (ein Wort) aus,
            # verlangt stattdessen die Phishing-typische Phrase
            # "connect ... wallet" mit Wortgrenze dazwischen
            'crypto_wallet_connect': r'(?i)\bconnect\s+(your\s+|my\s+)?wallet\b(?!\s*\.(io|com|org))',
            # FIX: verlangt Exfiltrations-Verb statt jeder Erwaehnung von
            # "private key" (traf vorher jede normale SSH/TLS-Rotation)
            'crypto_private_key': r'(?i)(show|print|cat|reveal|send|leak|dump|copy|display|exfiltrate)\s+(the\s+|my\s+)?(private\s+key|ssh\s+key)',

            # ============================================================
            # POST-QUANTUM CRYPTOGRAPHY (2026)
            # ============================================================
            'pqc_harvest_now': r'(?i)(harvest|capture|store).{0,20}(decrypt|break).{0,20}later',
            'pqc_rsa_small': r'\bRSA[_-]?(1024|2048)\b',
            'pqc_legacy_ecdsa': r'\bECDSA[_-]?P[_-]?256\b',
            'pqc_legacy_dh': r'\bDH[_-]?1024\b',

            # ============================================================
            # SUPPLY CHAIN ATTACKS (2025/26)
            # ============================================================
            'supply_npm_unsafe': r'(?i)npm\s+install.*--unsafe',
            'supply_pip_unsafe': r'(?i)pip\s+install.*--no-verify',
            'supply_typosquat': r'(?i)(typosquat|dependency.*confusion)',
            'supply_malicious_package': r'(?i)(malicious|backdoor).{0,20}(package|dependency)',
            'supply_package_hijack': r'(?i)package.*hijack',

            # ============================================================
            # DATA EXFILTRATION CHANNELS (2025)
            # ============================================================
            'exfil_discord_webhook': r'(?i)discord\.com/api/webhooks/\d+',
            'exfil_telegram_bot': r'(?i)api\.telegram\.org/bot',
            'exfil_pastebin': r'(?i)pastebin\.com/(raw|api)',
            'exfil_requestbin': r'(?i)(requestbin|webhook\.site)',
            'exfil_data_uri': r'(?i)data:image/.*base64',
            'exfil_btoa': r'(?i)btoa\s*\(',

            # ============================================================
            # EVASION TECHNIQUES
            # ============================================================
            'evasion_honeypot': r'(?i)(honeypot.*detect|sandbox.*evasion|vm.*detection)',
            'evasion_antivm': r'(?i)anti[-_]?(vm|debug|sandbox)',

            # ============================================================
            # EDGE DEVICE EXPLOITATION (Palo Alto, Fortinet, Ivanti)
            # HINWEIS: edge_panos/edge_fortios/edge_ivanti sind reine
            # Produktnamens-Treffer (bewusst unveraendert, siehe Docstring).
            # edge_api_paths bewusst NICHT gefixt, siehe Docstring -
            # matcht praktisch jede normale REST-API, kein sinnvoller
            # Regex-Fix moeglich. Empfehlung: entfernen oder eingrenzen.
            # ============================================================
            'edge_panos': r'(?i)(panos|globalprotect)',
            'edge_fortios': r'(?i)fortios',
            'edge_ivanti': r'(?i)(ivanti|pulse.*secure)',
            'edge_vpn_paths': r'(?i)/(dana-na|remote/login|vpn)/',
            'edge_api_paths': r'(?i)/api/v[12]/',

            # ============================================================
            # DEEPFAKE & AI IDENTITY (2026)
            # ============================================================
            'deepfake_ceo': r'(?i)(deepfake|synthetic).{0,20}(CEO|executive|CFO)',
            'deepfake_voice': r'(?i)(voice\s+clone|audio\s+spoof|voice\s+synthesis)',
            'ai_impersonation': r'(?i)(AI|bot).{0,20}(impersonat|pretend|pose\s+as)',

            # ============================================================
            # SOCIAL ENGINEERING (IBM 2026 Prediction)
            # ============================================================
            'social_password_reset': r'(?i)(urgent|immediate).{0,20}password.{0,20}reset',
            'social_account_recovery': r'(?i)(locked|suspend).{0,20}account.{0,20}(recovery|reset)',
            'social_verify_identity': r'(?i)(verify|confirm).{0,20}identity.{0,20}(urgent|immediate)',

            # ============================================================
            # GRAPHQL INJECTION
            # ============================================================
            'graphql_introspection': r'(?i)(__schema|__type|introspectionQuery)',
            'graphql_nested': r'(?i)query.{0,100}query',

            # ============================================================
            # PROTOTYPE POLLUTION (JavaScript)
            # ============================================================
            'prototype_pollution': r'(__proto__|constructor\[[\"\']?prototype[\"\']?\])',

            # ============================================================
            # HTTP HEADER INJECTION
            # ============================================================
            'header_injection': r'(?i)(\r\n|\n|\r|%0d|%0a)(Set-Cookie|Location|Content-Length|Host):',

            # ============================================================
            # OPEN REDIRECTS
            # ============================================================
            'open_redirect': r'(?i)(redirect=|url=|next=|to=|dest=)(https?%3a%2f%2f|https?://)',

            # ============================================================
            # DIRECTORY LISTING
            # ============================================================
            'directory_listing': r'(?i)(Index\s+of\s+/|Directory\s+Listing|Parent\s+Directory)',

            # ============================================================
            # DANGEROUS FILE EXTENSIONS
            # ============================================================
            'dangerous_extensions': r'(?i)\.(php|exe|dll|jar|jsp|asp|aspx|pl|py|rb)(\.|$|\?|\s)',

            # ============================================================
            # PROTOCOL HANDLERS
            # HINWEIS: protocol_ldap bewusst unveraendert (siehe Docstring)
            # - "ldap://" ist in Enterprise-IT-Doku voellig normal, aber
            # kein Regex kann das von einem SSRF-Versuch unterscheiden.
            # ============================================================
            'protocol_jar': r'(?i)jar:(http|https)://',
            'protocol_sftp': r'(?i)sftp://',
            'protocol_tftp': r'(?i)tftp://',
            'protocol_ldap': r'(?i)ldap://',
            'protocol_gopher': r'(?i)gopher://',
            'protocol_dict': r'(?i)dict://',

            # ============================================================
            # NODE.JS / NPM SUPPLY CHAIN (2024/25 trend)
            # ============================================================
            'nodejs_child_process': r'(?i)require\s*\(\s*["\']child_process["\']',
            'nodejs_spawn': r'(?i)spawn\s*\(',
            'nodejs_exec_node': r'(?i)exec\s*\(.*node',
            'nodejs_xhr_proto': r'(?i)XMLHttpRequest\.prototype',
            'nodejs_crypto_wallet': r'(?i)(web3|crypto.*wallet|ethereum|bitcoin)',
            'nodejs_obfuscated': r'(?i)(javascript-obfuscator|obfuscated.*payload|_0x[0-9a-f]{6})',

            # ============================================================
            # QUANTUM-SAFE MIGRATION ISSUES (2026)
            # FIX: Trenner zwischen ML und KEM ist jetzt optional, da der
            # offizielle IANA-Name "X25519MLKEM768" KEINEN Trenner hat.
            # Reihenfolge-Abhaengigkeit des Lookaheads bleibt als bekannte
            # Grenze bestehen (Python re kann kein variables Lookbehind).
            # ============================================================
            'quantum_ml_kem_missing': r'(?i)X25519(?![_-]?ML[_-]?KEM)',
            'quantum_hybrid_missing': r'(?i)TLS[_-]?1[._]?[23](?!.*hybrid)',
        }

        # Compile patterns for performance
        self.compiled = {
            name: re.compile(pattern)
            for name, pattern in self.patterns.items()
        }

        self.risk_levels = {
            'llm_': 'CRITICAL',
            'ai_agent_': 'CRITICAL',
            'shadow_ai_': 'CRITICAL',
            'pqc_': 'CRITICAL',
            'deepfake_': 'CRITICAL',
            'container_': 'CRITICAL',
            'quantum_': 'CRITICAL',
            'apikey_': 'HIGH',
            'cicd_': 'HIGH',
            'sql_injection_': 'HIGH',
            'cmd_injection_': 'HIGH',
            'code_exec_': 'HIGH',
            'ssrf_': 'HIGH',
            'exfil_': 'HIGH',
            'supply_': 'HIGH',
            'edge_': 'HIGH',
            'xss_': 'MEDIUM',
            'path_traversal_': 'MEDIUM',
            'file_inclusion_': 'MEDIUM',
            'crypto_': 'MEDIUM',
            'social_': 'MEDIUM',
            'sensitive_': 'LOW',
        }

    def get_risk_level(self, pattern_name: str) -> str:
        for prefix, level in self.risk_levels.items():
            if pattern_name.startswith(prefix):
                return level
        return 'MEDIUM'
