#!/usr/bin/bash

###############################################################################
#                              INSTALLATION                                   #
###############################################################################

REPOS=(
  "anew|https://github.com/tomnomnom/anew.git"
  "apkleaks|https://github.com/dwisiswant0/apkleaks.git"
  "Arjun|https://github.com/s0md3v/Arjun.git"
  "buster|https://github.com/sham00n/buster.git"
  "cent|https://github.com/xm1k3/cent.git"
  "Chimera|https://github.com/georgesotiriadis/Chimera.git"
  "cloudfox|https://github.com/BishopFox/cloudfox.git"
  "cloudsploit|https://github.com/aquasecurity/cloudsploit.git"
  "cook|https://github.com/glitchedgitz/cook.git"
  "cve-search|https://github.com/cve-search/cve-search.git"
  "dalfox|https://github.com/hahwul/dalfox.git"
  "goclone|https://github.com/imthaghost/goclone.git"
  "grex|https://github.com/pemistahl/grex.git"
  "Havoc|https://github.com/HavocFramework/Havoc.git"
  "impacket|https://github.com/fortra/impacket.git"
  "kerbrute|https://github.com/ropnop/kerbrute.git"
  "Luyten|https://github.com/deathmarine/Luyten.git"
  "nishang|https://github.com/samratashok/nishang.git"
  "Nuclei-bug-hunter|https://github.com/ayadim/Nuclei-bug-hunter.git"
  "octosuite|https://github.com/bellingcat/octosuite.git"
  "pagodo|https://github.com/opsdisk/pagodo.git"
  "payloadkit|https://github.com/jordanjoewatson/payloadkit.git"
  "PayloadsAllTheThings|https://github.com/swisskyrepo/PayloadsAllTheThings.git"
  "pydictor|https://github.com/LandGrey/pydictor.git"
  "RedGuard|https://github.com/wikiZ/RedGuard.git"
  "sliver|https://github.com/BishopFox/sliver.git"
  "trufflehog|https://github.com/trufflesecurity/trufflehog.git"
  "WinPwnage|https://github.com/rootm0s/WinPwnage.git"
  "firefly|https://github.com/Brum3ns/firefly.git"
  "unfurl|https://github.com/tomnomnom/unfurl.git"
  "Clifty|https://github.com/Alygnt/Clifty.git"
  "ParamSpider|https://github.com/0xKayala/ParamSpider.git"
  "CloudFlair|https://github.com/christophetd/CloudFlair.git"
  "mkp224o|https://github.com/cathugger/mkp224o.git"
  "spyhunt|https://github.com/gotr00t0day/spyhunt.git"
  "cve|https://github.com/trickest/cve.git"
  "SharpCollection|https://github.com/Flangvik/SharpCollection.git"
  "username-anarchy|https://github.com/urbanadventurer/username-anarchy.git"
  "pencode|https://github.com/ffuf/pencode.git"
  "ligolo-ng|https://github.com/nicocha30/ligolo-ng.git"
  "pdtm|https://github.com/projectdiscovery/pdtm.git"
  "uro|https://github.com/s0md3v/uro.git"
  "gf|https://github.com/1ndianl33t/Gf-Patterns.git"
  "burtespray|https://github.com/x90skysn3k/brutespray.git"
  "linkfinder|https://github.com/GerbenJavado/LinkFinder.git"
  "Hakrawler|https://github.com/hakluke/hakrawler.git"
  "sherlock|https://github.com/sherlock-project/sherlock.git"
  "gitleaks|https://github.com/gitleaks/gitleaks"
  "SQLiDetector|https://github.com/eslam3kl/SQLiDetector.git"
  "penelope|https://github.com/brightio/penelope.git"
)
GO_TOOLS=(
  "github.com/takshal/freq@latest"
  "github.com/lc/gau/v2/cmd/gau@latest"
  "github.com/tomnomnom/gf@latest"
  "github.com/hakluke/hakrawler@latest"
  "github.com/takshal/bfxss@latest"
  "github.com/tomnomnom/qsreplace@latest"
  "github.com/tomnomnom/waybackurls@latest"
  "github.com/tomnomnom/gron@latest"
  "github.com/hakluke/hakcheckurl@latest"
  "github.com/tomnomnom/httprobe@latest"
)

INSTALL_DIR="/opt"
DEFAULT_JOBS=5

log() {
  local LEVEL="$1"
  local MESSAGE="$2"
  case "$LEVEL" in
    INFO)    echo -e "\033[0;34m[INFO]\033[0m $MESSAGE" ;;
    WARN)    echo -e "\033[1;33m[WARN]\033[0m $MESSAGE" ;;
    ERROR)   echo -e "\033[0;31m[ERROR]\033[0m $MESSAGE" ;;
    SUCCESS) echo -e "\033[0;32m[OK]\033[0m $MESSAGE" ;;
  esac
}

check_root() {
  if [[ "$(id -u)" -ne 0 ]]; then
    log ERROR "Script must be run as root or with sudo."
    exit 1
  fi
}

check_dependencies() {
  for DEP in git curl go parallel; do
    if ! command -v "$DEP" &>/dev/null; then
      log ERROR "Missing dependency: $DEP"
      exit 1
    fi
  done
}

install_go_tools() {
  log INFO "Installing Go tools..."
  for TOOL in "${GO_TOOLS[@]}"; do
    log INFO "Installing $TOOL..."
    if go install "$TOOL" &>> /tmp/go_install.log; then
      log SUCCESS "$TOOL installed successfully."
    else
      log ERROR "Failed to install $TOOL"
    fi
  done
}

clone_or_update() {
  local FULL="$1"
  local REPO_NAME="${FULL%%|*}"
  local REPO_URL="${FULL##*|}"
  local DEST="${INSTALL_DIR}/${REPO_NAME}"

  mkdir -p "$INSTALL_DIR"

  if [[ -d "$DEST" ]]; then
    log INFO "Updating repo: ${REPO_NAME} in ${DEST}"
    (cd "$DEST" && git pull --rebase && log SUCCESS "Updated ${REPO_NAME}") || log ERROR "Failed to update ${REPO_NAME}"
  else
    log INFO "Cloning ${REPO_NAME} into ${DEST}..."
    git clone --depth=1 "$REPO_URL" "$DEST" && log SUCCESS "Cloned ${REPO_NAME}" || log ERROR "Failed to clone ${REPO_NAME}"
  fi
}


go-exploitdb() {

  repo_path="${GOPATH:-$HOME/go}/src/github.com/vulsio/go-exploitdb"
  mkdir -p "$(dirname "$repo_path")"

  if [ ! -d "$repo_path" ]; then
    git clone https://github.com/vulsio/go-exploitdb.git "$repo_path" || { echo "Failed to clone repository"; return 1; }
  else
    echo "Repository already exists, skipping clone."
    echo "[+] Checking for updates"
    
    cd "$repo_path" || { echo "Failed to enter directory"; return 1; }
    git pull || { echo "Failed to update repository"; return 1; }
  fi

  cd "$repo_path" || { echo "Failed to enter directory"; return 1; }
  make install
}



###############################################################################
#                                 MAIN                                        #
###############################################################################

check_root
check_dependencies

log INFO "Setting up installation directory: ${INSTALL_DIR}"
mkdir -p "$INSTALL_DIR" || { log ERROR "Could not create ${INSTALL_DIR}"; exit 1; }
chmod -R 755 "$INSTALL_DIR"

log INFO "Starting repository cloning into ${INSTALL_DIR}..."

# ✅ Export functions for parallel execution
export -f log clone_or_update
export INSTALL_DIR

# ✅ Clone repositories in parallel
printf "%s\n" "${REPOS[@]}" | parallel -j "$DEFAULT_JOBS" clone_or_update {}

install_go_tools
go-exploitdb
# Ronin install script URL
RONIN_INSTALL_URL="https://raw.githubusercontent.com/ronin-rb/scripts/main/ronin-install.sh"

log INFO "Installing Ronin..."
if curl -fsSL -o ronin-install.sh "$RONIN_INSTALL_URL"; then
  bash ronin-install.sh && log SUCCESS "Ronin installed successfully." || log ERROR "Failed to install Ronin."
  rm -f ronin-install.sh
else
  log ERROR "Failed to download Ronin install script."
fi

log INFO "All tasks completed successfully!"
