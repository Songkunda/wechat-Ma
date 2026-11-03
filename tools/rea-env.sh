# REA + Ghidra 环境。用法：source tools/rea-env.sh
export GHIDRA_INSTALL_DIR="$HOME/opt/ghidra_12.1.4_PUBLIC"
export JAVA_HOME="$HOME/Library/Java/JavaVirtualMachines/openjdk-24.0.2/Contents/Home"
# 165MB 核心库超出 REA 默认 330s 导入超时，放宽到 1h
export REA_GHIDRA_STARTUP_TIMEOUT_MS=3600000
# 本机外网需走本机 socks5 代理（pypi/github 直连超时）
export ALL_PROXY=socks5h://127.0.0.1:1081
alias rea='npx rea-agents@latest'
