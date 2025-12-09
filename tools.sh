#!/bin/bash

# Create virtual environment in ~/ctf_py_packages
mkdir -p ~/ctf_py_packages
python3 -m venv ~/ctf_py_packages/ctf_env
source ~/ctf_py_packages/ctf_env/bin/activate

# Windsurf code editor
sudo apt-get install wget gpg -y
wget -qO- "https://windsurf-stable.codeiumdata.com/wVxQEIWkwPUEAGf3/windsurf.gpg" | gpg --dearmor > windsurf-stable.gpg
sudo install -D -o root -g root -m 644 windsurf-stable.gpg /etc/apt/keyrings/windsurf-stable.gpg
echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/windsurf-stable.gpg] https://windsurf-stable.codeiumdata.com/wVxQEIWkwPUEAGf3/apt stable main" | sudo tee /etc/apt/sources.list.d/windsurf.list > /dev/null
sudo rm -f windsurf-stable.gpg

# Micro editor
cd ~/tools
curl -s https://getmic.ro | bash
sudo cp ./micro /usr/bin
rm ./micro

micro -plugin install gotham-colors
micro -plugin install editorconfig
micro -plugin install nordcolors
micro -plugin install filemanager

# Gdb plugins binary analyzer
sudo apt install gdb-peda -y
curl -qsL 'https://install.pwndbg.re' | sh -s -- -t pwndbg-gdb
bash -c "$(curl -fsSL https://gef.blah.cat/sh)"

# Apt install tools
sudo apt update
sudo apt install rlwrap -y
sudo apt install remmina -y
sudo apt install caido -y
sudo apt install stegseek -y
sudo apt install pngcheck -y
sudo apt install sqlitebrowser -y
sudo apt install cmake -y
sudo apt install ghidra -y
sudo apt install checksec -y 
sudo apt install stegsnow -y
sudo apt install lxappearance -y
sudo apt install rofi -y
sudo apt install kitty -y
sudo apt install apt-transport-https -y
sudo apt install windsurf -y
sudo apt install bloodyad -y
sudo apt install certipy-ad -y
sudo apt install python3-impacket -y
sudo apt install impacket-scripts -y
sudo apt install ranger -y
sudo apt install flatpak -y
sudo apt install mono-devel -y
sudo apt install wine wine64 -y
sudo apt install feroxbuster

# PowerShell
sudo apt install powershell -y

# Formatting utilities
sudo apt install bat -y       # improved cat
sudo apt install fd-find -y   # improved find
sudo apt install fzf -y       # fuzzy search
sudo apt install ripgrep -y   # improved grep
sudo apt install jq -y        # process JSON
sudo apt install yq -y        # process YAML
sudo apt install hexyl -y     # hex viewer
sudo apt install ncdu -y      # disk usage
sudo apt install html2text -y # html viewer

# More CTF tools
sudo apt install binwalk -y
sudo apt install exiftool -y
sudo apt install foremost -y
sudo apt install sleuthkit -y
sudo apt install volatility -y
sudo apt install wireshark -y
sudo apt install tshark -y
sudo apt install tcpdump -y
sudo apt install nmap -y
sudo apt install nikto -y
sudo apt install gobuster -y
sudo apt install ffuf -y
sudo apt install seclists -y
sudo apt install wordlists -y
sudo apt install radare2 -y
sudo apt install strace -y
sudo apt install ltrace -y
sudo apt install neofetch -y
sudo apt install htop -y
sudo apt install tree -y

# CTF tools pip (installed in virtual environment)
pip install oletools
pip install stego-lsb
pip install pwntools
pip install pycryptodome
pip install decompyle3
pip install decompyle6
pip install ropper
pip install -U https://github.com/DissectMalware/pyOneNote/archive/master.zip --force
pip install pypykatz
pip install stegpy
pip install defaultcreds-cheat-sheet
pip install kerbrute
pip install stegoveritas
pip install angr
pip install capstone
pip install unicorn
pip install keystone-engine
pip install stegcracker
pip install xortool
pip3 install droopescan

stegoveritas_install_deps

# Exit virtual environment after pip installations
deactivate

# Flatpak utils
flatpak remote-add --user --if-not-exists flathub https://dl.flathub.org/repo/flathub.flatpakrepo
flatpak install --user flathub org.keepassxc.KeePassXC

# Sonic visualizer
mkdir -p ~/tools/ctftools
cd ~/tools/ctftools
curl -O https://code.soundsoftware.ac.uk/attachments/download/2880/SonicVisualiser-5.2.1-x86_64.AppImage
mv SonicVisualiser-5.2.1-x86_64.AppImage sonic.AppImage
chmod +x sonic.AppImage

# JdGui
curl -O https://github.com/java-decompiler/jd-gui/releases/download/v1.6.6/jd-gui-1.6.6.jar
mv jd-gui-1.6.6.jar jdGui.jar
chmod +x jdGui.jar

# Stegsolve
wget http://www.caesum.com/handbook/Stegsolve.jar -O stegsolve.jar
chmod +x stegsolve.jar

# Jsteg
sudo wget -O /usr/bin/jsteg https://github.com/lukechampine/jsteg/releases/download/v0.1.0/jsteg-linux-amd64
sudo chmod +x /usr/bin/jsteg

# Pdf cracker
cd ~/tools/ctftools
git clone https://github.com/MichaelSasser/pdfcrack-ng.git
cd pdfcrack-ng
mkdir build && cd build
cmake ..
make

# Stego
gem install zsteg

# Audio stego
sudo apt-get install libboost-all-dev -y
cd ~/tools/ctftools
git clone https://github.com/danielcardeenas/AudioStego.git
mv AudioStego audioStego && cd audioStego
mkdir build && cd build
cmake ..
make
sudo ln -sf ~/tools/ctftools/audioStego/build/hideme /usr/bin/hideme

# LSB Steganography
cd ~/tools/ctftools
git clone https://github.com/RobinDavid/LSB-Steganography.git
cd LSB-Steganography
# Activate environment temporarily for this installation
source ~/ctf_py_packages/ctf_env/bin/activate
pip install -r requirements.txt
deactivate

# Masscan
cd ~/tools/ctftools
git clone https://github.com/robertdavidgraham/masscan.git
cd masscan
make

# Pycdc
cd ~/tools/ctftools
git clone https://github.com/zrax/pycdc.git
cd pycdc
mkdir build && cd build
cmake ..
make

# Impacket
cd ~/tools/ctftools
git clone https://github.com/fortra/impacket.git
cd impacket
# Activate environment temporarily for this installation
source ~/ctf_py_packages/ctf_env/bin/activate
pip install .
deactivate
cd ../
sudo rm -rf impacket

# Docker Images
docker pull mcr.microsoft.com/dotnet/sdk:9.0 # Powershell

echo "All tools installed successfully"
echo "Virtual environment created at: ~/ctf_py_packages/ctf_env"
echo "To activate the environment, run: source ~/ctf_py_packages/ctf_env/bin/activate"
