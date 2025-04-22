# Clear any existing Python-related environment variables
unset PYTHONPATH
unset PYTHONHOME
unset PYTHONSTARTUP
unset PYTHONUSERBASE

# Create project-specific directory for packages
mkdir -p ./.packages

# Set up environment for writable package installation
export PYTHONUSERBASE=$(pwd)/.packages
export PATH=$PYTHONUSERBASE/bin:$PATH

# Configure Python path to include our local packages
PYVER=$(python -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
export PYTHONPATH=$PYTHONUSERBASE/lib/python$PYVER/site-packages:$(pwd)

# Crucial for making uv work with editable installs
export PIP_USER=1
export PIP_PREFIX=$(pwd)/.packages

# Create custom pip.conf
mkdir -p $(pwd)/.pip
cat > $(pwd)/.pip/pip.conf << EOF
[global]
user = true
prefix = $(pwd)/.packages
EOF

export PIP_CONFIG_FILE=$(pwd)/.pip/pip.conf

# Configure uv
export UV_SYSTEM_PYTHON=0
export UV_PIP_USER=1
export UV_EXTRA_INDEX_URL=""

# Create aliases to ensure proper flags are used
alias uvpip='uv pip install --prefix $(pwd)/.packages'
alias uvinit='uv pip install -e . --prefix $(pwd)/.packages'

# Enable vim keybindings
bindkey -v

# Set prompt to show nix environment
PS1="%F{cyan}[nix:py312]%f %F{green}%~%f %# "

# Display environment info
echo "Python $(python --version | cut -d' ' -f2) with uv $(uv --version)"
echo "• Install packages: uvpip <package>"
echo "• For uv init: uvinit"
echo "• Vim keybindings enabled"
echo "• All packages installed to $(pwd)/.packages"
