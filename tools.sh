#!/bin/bash

# Windsurf editor de codigo
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

# Gdb plugins binary analizer
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

# PowerShell
sudo apt install powershell -y

# Utilidades de formateo 
# Utilidades
sudo apt install bat -y      # cat mejorado
sudo apt install fd-find -y  # find mejorado
sudo apt install fzf -y      # búsqueda fuzzy
sudo apt install ripgrep -y  # grep mejorado
sudo apt install jq -y       # procesar JSON
sudo apt install yq -y       # procesar YAML
sudo apt install hexyl -y    # hex viewer
sudo apt install ncdu -y     # disk usage

# Más herramientas CTF
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

# Ctf tools pip
pip install oletools --break-system-packages
pip install stego-lsb --break-system-packages
pip install pwntools --break-system-packages
pip install pycryptodome --break-system-packages
pip install decompyle3 --break-system-packages
pip install decompyle6 --break-system-packages
pip install ropper --break-system-packages
pip install -U https://github.com/DissectMalware/pyOneNote/archive/master.zip --force --break-system-packages
pip3 install pypykatz --break-system-packages
pip3 install stegpy --break-system-packages
pip3 install defaultcreds-cheat-sheet --break-system-packages
pip3 install kerbrute --break-system-packages
pip3 install stegoveritas --break-system-packages
pip install angr --break-system-packages
pip install capstone --break-system-packages
pip install unicorn --break-system-packages
pip install keystone-engine --break-system-packages
pip install stegcracker --break-system-packages
pip install xortool --break-system-packages
stegoveritas_install_deps

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

# LSB Steganografhy
cd ~/tools/ctftools
git clone https://github.com/RobinDavid/LSB-Steganography.git
cd LSB-Steganography
pip install -r requirements.txt --break-system-packages

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
python3 -m pipx install .
cd ../
sudo rm -rf impacket

# Docker Images
docker pull mcr.microsoft.com/dotnet/sdk:9.0 # Powershell

echo "Todas las herramientas instaladas correctamente"
