rule base64_exec_payload {
  meta:
    description = "Base64 encoded payload executed via eval/exec"
    severity = "critical"
    source = "guarddog-compatible"
  strings:
    $py_b64exec1 = "base64.b64decode" ascii
    $py_b64exec2 = "base64.b64encode" ascii
    $py_exec = "exec(" ascii
    $py_eval = "eval(" ascii
    $js_b64 = "Buffer.from(" ascii
    $js_atob = "atob(" ascii
    $js_eval = "eval(" ascii
    $js_func = "Function(" ascii
  condition:
    ($py_b64exec1 or $py_b64exec2) and ($py_exec or $py_eval)
    or ($js_b64 or $js_atob) and ($js_eval or $js_func)
}

rule environment_exfiltration {
  meta:
    description = "Environment variable bulk access combined with network exfiltration"
    severity = "critical"
    source = "guarddog-compatible"
  strings:
    $py_env1 = "os.environ" ascii
    $py_env2 = "os.getenv" ascii
    $js_env = "process.env" ascii
    $py_net1 = "urllib" ascii
    $py_net2 = "requests." ascii
    $py_net3 = "httpx." ascii
    $js_net1 = "https.get" ascii
    $js_net2 = "https.request" ascii
    $js_net3 = "fetch(" ascii
  condition:
    ($py_env1 or $py_env2) and ($py_net1 or $py_net2 or $py_net3)
    or $js_env and ($js_net1 or $js_net2 or $js_net3)
}

rule credential_file_access {
  meta:
    description = "Access to credential files (SSH keys, AWS credentials, etc.)"
    severity = "critical"
    source = "guarddog-compatible"
  strings:
    $ssh = ".ssh/" ascii
    $aws = ".aws/" ascii
    $gnupg = ".gnupg/" ascii
    $npmrc = ".npmrc" ascii
    $docker = ".docker/" ascii
    $kube = ".kube/" ascii
    $gcloud = ".config/gcloud" ascii
  condition:
    2 of them
}

rule reverse_shell_pattern {
  meta:
    description = "Reverse shell connection pattern"
    severity = "critical"
    source = "guarddog-compatible"
  strings:
    $py_socket = "socket.socket" ascii
    $py_connect = ".connect(" ascii
    $py_dup2 = "os.dup2" ascii
    $js_net = "net.connect" ascii
    $js_spawn = "child_process" ascii
    $rb_tcp = "TCPSocket" ascii
  condition:
    ($py_socket and $py_connect and $py_dup2)
    or ($js_net and $js_spawn)
    or $rb_tcp
}

rule cryptocurrency_miner {
  meta:
    description = "Cryptocurrency mining indicators"
    severity = "critical"
    source = "guarddog-compatible"
  strings:
    $stratum = "stratum+tcp://" ascii
    $xmrig = "xmrig" ascii nocase
    $coinhive = "coinhive" ascii nocase
    $monero = "monero" ascii nocase
    $cryptonight = "cryptonight" ascii nocase
    $ethash = "ethash" ascii nocase
    $minexmr = "minexmr" ascii nocase
  condition:
    any of them
}

rule obfuscated_code_execution {
  meta:
    description = "Obfuscated code execution via string manipulation"
    severity = "high"
    source = "guarddog-compatible"
  strings:
    $js_charcode = "String.fromCharCode" ascii
    $js_constructor = "Function(" ascii
    $py_getattr = "getattr(__builtins__" ascii
    $py_import = "__import__(" ascii
    $rb_send = ".send(:system" ascii
    $rb_eval = "instance_eval" ascii
  condition:
    any of them
}

rule suspicious_network_domains {
  meta:
    description = "Network communication to suspicious domains"
    severity = "high"
    source = "guarddog-compatible"
  strings:
    $ngrok = "ngrok.io" ascii nocase
    $serveo = "serveo.net" ascii nocase
    $localtunnel = "localtunnel.me" ascii nocase
    $telegram = "api.telegram.org" ascii nocase
    $discord_wh = "discord.com/api/webhooks" ascii nocase
    $pastebin = "pastebin.com" ascii nocase
  condition:
    any of them
}

rule install_script_dropper {
  meta:
    description = "Download and execute pattern in install scripts"
    severity = "critical"
    source = "guarddog-compatible"
  strings:
    $curl_bash = "curl" ascii
    $wget = "wget" ascii
    $pipe_bash = "| bash" ascii
    $pipe_sh = "| sh" ascii
    $chmod_exec = "chmod +x" ascii
    $chmod_777 = "chmod 777" ascii
  condition:
    ($curl_bash or $wget) and ($pipe_bash or $pipe_sh or $chmod_exec or $chmod_777)
}
