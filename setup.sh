#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
PURPLE='\033[0;35m'
NC='\033[0m'

success() {
    echo -e "${GREEN}[✓]${NC} :: $1"
}

info() {
    echo -e "${BLUE}[i]${NC} :: $1"
}

warning() {
    echo -e "${YELLOW}[!]${NC} :: $1"
}

error() {
    echo -e "${RED}[✗]${NC} :: $1"
}

section() {
    echo -e "${CYAN}[ $1 ]${NC}"
}

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# ---
# Uninstallations
# ---

section "Starting Uninstallations"

if command_exists vim; then
    sudo apt remove vim --purge -y
    success "Vim uninstalled"
else
    info "Vim is not installed"
fi

if command_exists nano; then
    sudo apt remove nano --purge -y
    success "Nano uninstalled"
else
    info "Nano is not installed"
fi

if command_exists snap && snap list | grep -q autopsy; then
    sudo snap remove autopsy
    success "Autopsy uninstalled"
else
    info "Autopsy is not installed"
fi

# ---
# Configuration Files (Dotfiles)
# ---

section "Cloning and Configuring Dotfiles"

DOTFILES_DIR=~/tools/dotfiles
TOOLS_DIR=~/tools

mkdir -p "$TOOLS_DIR"
cd "$TOOLS_DIR"

if [ -d "dotfiles" ]; then
    warning "Dotfiles directory exists. Removing and re-cloning..."
    rm -rf dotfiles
    success "Old dotfiles removed"
fi

git clone https://github.com/Yoswell/dotfiles.git
success "Dotfiles cloned to $DOTFILES_DIR"

# ---
# Desktop/Wallpapers and Login Configuration
# ---

section "Configuring Wallpapers"

WALLPAPERS_DIR=~/Desktop/wallpapers
mkdir -p "$WALLPAPERS_DIR"

if [ -d "$DOTFILES_DIR/wallpapers" ]; then
    cp -r "$DOTFILES_DIR/wallpapers"/* "$WALLPAPERS_DIR"
    success "Wallpapers copied to $WALLPAPERS_DIR"
else
    warning "Wallpapers directory not found in dotfiles"
fi

# Configure login wallpaper
SNOW_IMAGE="$WALLPAPERS_DIR/snow.png"
if [ -f "$SNOW_IMAGE" ]; then
    sudo cp "$SNOW_IMAGE" /usr/share/backgrounds/kali/kali-maze-16x9.jpg 2>/dev/null || true
    sudo cp "$SNOW_IMAGE" /usr/share/backgrounds/kali/login.svg 2>/dev/null || true
    success "Login wallpaper configured"
else
    info "Snow image not found, skipping login wallpaper configuration"
fi

# ---
# Directory Structure in Documents
# ---

section "Creating Directory Structure"

cd ~/Documents
mkdir -p {htb_academy,htb_apps,htb_challenges,testing}
success "Directory structure created in ~/Documents"

# ---
# BIN and ZSH Configuration
# ---

section "Configuring BIN and ZSH"

cd ~
if [ -d "$DOTFILES_DIR/bin" ]; then
    mv "$DOTFILES_DIR/bin" .
    success "BIN directory configured"
else
    warning "BIN directory not found in dotfiles"
fi

# Install Oh My Zsh if not installed
if [ ! -d ~/.oh-my-zsh ]; then
    info "Installing Oh My Zsh"
    sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)" "" --unattended
    success "Oh My Zsh installed"
else
    info "Oh My Zsh already installed"
fi

# ZSH plugins
if [ -d ~/.oh-my-zsh/custom/plugins ]; then
    info "Installing ZSH plugins"
    cd ~/.oh-my-zsh/custom/plugins
    [ ! -d "zsh-autosuggestions" ] && git clone https://github.com/zsh-users/zsh-autosuggestions.git
    [ ! -d "zsh-syntax-highlighting" ] && git clone https://github.com/zsh-users/zsh-syntax-highlighting.git
    success "ZSH plugins installed"
fi

# Powerlevel10k theme
if [ -d ~/.oh-my-zsh ]; then
    info "Installing Powerlevel10k theme"
    cd ~/.oh-my-zsh
    [ ! -d "powerlevel10k" ] && git clone --depth=1 https://github.com/romkatv/powerlevel10k.git powerlevel10k
    success "Powerlevel10k theme installed"
fi

# Root user styling (zshrc and micro)
info "Configuring style for root user"
if [ -d "$DOTFILES_DIR" ]; then
    sudo mkdir -p /root/.config/micro/colorschemes 2>/dev/null || true
    sudo cp "$DOTFILES_DIR/zshrc" /root/.zshrc 2>/dev/null || true
    
    if [ -f "$DOTFILES_DIR/micro_theme.micro" ]; then
        sudo cp "$DOTFILES_DIR/micro_theme.micro" /root/.config/micro/colorschemes/micro_theme.micro 2>/dev/null || true
    fi
    
    success "Root user configuration applied"
else
    warning "Dotfiles directory not found for root configuration"
fi

# ---
# Appearance Configuration (Themes, Editor, Terminal)
# ---

section "Applying Appearance Configuration"

cd "$DOTFILES_DIR"

# GTK Theme (mantinight)
THEMES_DIR=~/.themes
mkdir -p "$THEMES_DIR"

if [ -f "mantinight.tar" ]; then
    info "Extracting mantinight theme"
    [ -d "mantinight" ] && rm -rf mantinight
    tar -xf mantinight.tar
    mv mantinight "$THEMES_DIR/mantinight"
    success "Mantinight theme installed"
    rm -f mantinight.tar
else
    warning "Mantinight theme archive not found"
fi

# GTK Theme (darksun)
if [ -f "darksun.tar" ]; then
    info "Extracting darksun theme"
    [ -d "darksun" ] && rm -rf darksun
    tar -xf darksun.tar
    mv darksun "$THEMES_DIR/darksun"
    success "Darksun theme installed"
    rm -rf darksun.tar
else
    warning "Darksun theme archive not found"
fi

# Micro editor configuration
MICRO_COLOR_DIR=~/.config/micro/colorschemes
mkdir -p "$MICRO_COLOR_DIR"

if [ -f "micro_theme.micro" ]; then
    cp micro_theme.micro "$MICRO_COLOR_DIR/"
    success "Micro theme configured"
else
    warning "Micro theme file not found"
fi

# Kitty terminal configuration
KITTY_DIR=~/.config/kitty
mkdir -p "$KITTY_DIR"

if [ -f "kitty.conf" ]; then
    cp kitty.conf "$KITTY_DIR/kitty.conf"
    success "Kitty terminal configured"
else
    warning "Kitty configuration file not found"
fi

# Rofi configuration
if [ -f "rofi_theme.rasi" ]; then
    sudo cp -f rofi_theme.rasi /usr/share/rofi/themes/rofi_theme.rasi 2>/dev/null || true
    success "Rofi theme configured"
else
    warning "Rofi theme file not found"
fi

# XFCE configuration files
XFCE_CONFIG_DIR=~/.config/xfce4/xfconf/xfce-perchannel-xml
mkdir -p "$XFCE_CONFIG_DIR"

if [ -f "xfce4-keyboard-shortcuts.xml" ]; then
    cp xfce4-keyboard-shortcuts.xml "$XFCE_CONFIG_DIR/"
    success "XFCE keyboard shortcuts configured"
else
    warning "XFCE keyboard shortcuts file not found"
fi

if [ -f "xfce4-power-manager.xml" ]; then
    cp xfce4-power-manager.xml "$XFCE_CONFIG_DIR/"
    success "XFCE power manager configured"
else
    warning "XFCE power manager file not found"
fi

if [ -f "xfce4Settings.xml" ]; then
    cp xfce4Settings.xml "$XFCE_CONFIG_DIR/"
    success "XFCE settings configured"
else
    warning "XFCE settings file not found"
fi

# GTK configuration
GTK_CONFIG_DIR=~/.config/gtk-3.0
mkdir -p "$GTK_CONFIG_DIR"

cat > "$GTK_CONFIG_DIR/settings.ini" << 'EOF_GTK'
[Settings]
gtk-theme-name=mantinight
gtk-application-prefer-dark-theme=1
EOF_GTK

success "GTK configuration created"

# Root user themes configuration
info "Copying GTK themes and icons to /root/"
if [ -d "$THEMES_DIR" ]; then
    sudo mkdir -p /root/.themes
    sudo cp -r "$THEMES_DIR"/* /root/.themes/ 2>/dev/null || true
    success "Themes copied to root"
fi

if [ -d ~/.icons ]; then
    sudo mkdir -p /root/.icons
    sudo cp -r ~/.icons/* /root/.icons/ 2>/dev/null || true
    success "Icons copied to root"
fi

if [ -f "$GTK_CONFIG_DIR/settings.ini" ]; then
    sudo mkdir -p /root/.config/gtk-3.0
    sudo cp "$GTK_CONFIG_DIR/settings.ini" /root/.config/gtk-3.0/ || true
    success "GTK settings copied to root"
fi

# ---
# Font Installation
# ---

section "Installing JetBrains Mono Fonts"

cd ~/Desktop
FONT_INSTALL_DIR=jetbrains
mkdir -p "$FONT_INSTALL_DIR" && cd "$FONT_INSTALL_DIR"
FONT_ZIP=$(ls ~/Downloads/JetBrainsMono*.zip 2>/dev/null | head -n 1)

if [ -f "$FONT_ZIP" ]; then
    info "Unzipping and installing JetBrains Mono"
    unzip -o "$FONT_ZIP"
    sudo mkdir -p /usr/share/fonts/truetype/jetbrains-mono
    sudo mv fonts/ttf/* /usr/share/fonts/truetype/jetbrains-mono/ 2>/dev/null || true
    
    if command_exists fc-cache; then
        sudo fc-cache -f -v
        success "JetBrains Mono fonts installed and font cache updated"
    else
        success "JetBrains Mono fonts installed (font cache not updated)"
    fi
else
    warning "Could not find JetBrainsMono*.zip file in ~/Downloads. Skipping font install."
fi

# Cleanup
cd ~/Desktop
[ -d "$FONT_INSTALL_DIR" ] && rm -rf "$FONT_INSTALL_DIR"
info "Font installation cleanup completed"

# ---
# Execute Template Creation Script
# ---

section "Executing Template Creation Script"

TEMPLATE_SCRIPT=create_templates.sh
TEMPLATE_PATH=~/$TEMPLATE_SCRIPT

if [ -f "$TEMPLATE_PATH" ]; then
    info "Found template script, executing..."
    chmod +x "$TEMPLATE_PATH"
    "$TEMPLATE_PATH"
    success "Template creation script executed"
else
    error "$TEMPLATE_SCRIPT not found at $TEMPLATE_PATH. Skipping template creation."
    info "Please ensure the secondary script is created and placed in ~/"
fi

# ---
# Finalization
# ---

success "All configurations applied successfully!"
info "Please run the following command to apply ZSH configuration:"
echo -e "  source ~/.zshrc"
echo -e "System configuration complete"
