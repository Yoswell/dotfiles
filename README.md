<div align="center">

### Kali Linux Dotfiles
#### A collection of system configurations, tools, and custom scripts for a productive development environment

[![shell](https://img.shields.io/badge/SHELL%20ZSH-black)]()
[![Kitty](https://img.shields.io/badge/KITTY%20TERMINAL-black)]()
[![Micro](https://img.shields.io/badge/MICRO%20EDITOR-black)]()
[![Rofi](https://img.shields.io/badge/ROFI%20LAUNCHER-black)]()
[![XFCE4](https://img.shields.io/badge/XFCE4%20DESKTOP-black)]()

</div>

---

### Features

- **Terminal Setup**: Optimized Zsh configuration with custom aliases and functions
- **Terminal Emulator**: Kitty configuration for a beautiful and functional terminal
- **Text Editing**: Micro editor with custom theme and keybindings
- **Application Launcher**: Rofi configuration for quick app launching
- **CTF Tools**: Collection of useful tools for Capture The Flag competitions
- **System Configuration**: XFCE4 settings, power management, and keyboard shortcuts
- **Wallpapers**: Curated collection of desktop wallpapers

### Repository Structure

```
.
├── bin/                          # Custom scripts and utilities
│   └── config_cleanup.sh         # Script to clean up .config directory
├── ctftools/                     # CTF-related tools and scripts
│   └── ...
├── wallpapers/                   # Collection of desktop wallpapers
├── kitty.conf                    # Kitty terminal configuration
├── microTheme.micro              # Micro editor theme
├── rofiTheme.rasi                # Rofi launcher theme
├── setup.sh                      # Installation and setup script
├── tools.sh                      # Tool installation and configuration
├── vscodeConfig.json             # VS Code settings
├── xfce4-keyboard-shortcuts.xml  # Custom keyboard shortcuts
├── xfce4-power-manager.xml       # Power management settings
├── xfce4Settings.xml             # Xfce4 desktop settings
├── xorg.conf                     # X Server configuration
└── zshrc                         # Zsh configuration file
```

### Quick Start

**Clone the repository**:
```bash
git clone https://github.com/Yoswell/dotfiles.git ~/.dotfiles

cd ~/.dotfiles
```

**Run the setup script**:
```bash
chmod +x setup.sh
./setup.sh
```

### Included Tools

- **Kitty**: Fast, feature-rich terminal emulator
- **Micro**: Modern and intuitive terminal-based text editor
- **Rofi**: Window switcher and application launcher
- **Chisel**: Fast TCP/UDP tunnel over HTTP
- **Custom scripts**: Various utilities for system management and CTF challenges

### Customization

- Edit `zshrc` for shell customizations
- Modify `kitty.conf` for terminal appearance
- Adjust `rofiTheme.rasi` for launcher theming
- Add custom wallpapers to the `wallpapers/` directory

---

**_Made with love by Vishok 👾_**

_Built for the Attack/Defense CTF community_
