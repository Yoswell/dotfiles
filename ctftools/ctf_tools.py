#!/usr/bin/env python3
"""
CTF Tools - A collection of useful CTF utilities and quick links
"""
import webbrowser
from termcolor import colored

# CTF Tools organized by categories
CTF_CATEGORIES = {
    '1': {
        'name': 'All-in-One Tools',
        'tools': {
            '1': {
                'name': 'HackingTool (GitHub)',
                'url': 'https://github.com/Z4nzu/hackingtool',
                'description': 'All in One Hacking Tool For Hackers'
            },
            '2': {
                'name': '10015.io',
                'url': 'https://10015.io/',
                'description': 'All-in-one online toolbox for developers'
            },
            '3': {
                'name': 'Dencode',
                'url': 'https://dencode.com/',
                'description': 'All-in-one decoder/encoder'
            }
        }
    },
    '2': {
        'name': 'Web Site Tools',
        'tools': {
            '1': {
                'name': 'JavaScript Deobfuscator (de4js)',
                'url': 'https://lelinhtinh.github.io/de4js/'
            },
            '2': {
                'name': 'Boxentriq Cipher Identifier',
                'url': 'https://www.boxentriq.com/code-breaking/cipher-identifier'
            },
            '3': {
                'name': 'CrackStation',
                'url': 'https://crackstation.net/'
            },
            '4': {
                'name': 'Magic Eye Solver',
                'url': 'https://magiceye.ecksdee.co.uk/'
            },
            '5': {
                'name': 'Multi-tap ABC Cipher',
                'url': 'https://www.dcode.fr/multitap-abc-cipher'
            },
            '6': {
                'name': 'FactorDB (Integer Factorization)',
                'url': 'https://factordb.com/'
            },
            '7': {
                'name': 'dCode Cipher Identifier',
                'url': 'https://www.dcode.fr/cipher-identifier'
            },
            '8': {
                'name': 'PyLingual',
                'url': 'https://pylingual.io/',
                'description': 'Python (pyc) decompiler (use after pyinstxtractor)'
            },
            '9': {
                'name': 'Office Recovery File Repair',
                'url': 'https://online.officerecovery.com/filerepair/status',
                'description': 'Herramienta en línea para reparar documentos de Office dañados (png, doc, etc)'
            },
            '10': {
                'name': 'UTF-8 Character Table',
                'url': 'https://www.utf8-chartable.de/unicode-utf8-table.pl?start=8192&number=128',
                'description': 'Tabla completa de caracteres UTF-8 con códigos y representaciones'
            }
        }
    }
}

def print_banner():
    """Print the CTF Tools banner."""
    banner = """
     💀
    ≤))≥
    _|\\_ are u serious rn?
    """
    print(colored(banner, 'red'))

def open_tool(tool):
    """Open the specified tool's URL in the default web browser."""
    print("\n" + colored(f"[+] Tool: {tool['name']}", 'cyan', attrs=['bold']))
    if 'description' in tool:
        print(colored(f"   Description: {tool['description']}", 'yellow'))
    print(colored(f"   URL: {tool['url']}", 'green'))
    webbrowser.open(tool['url'])

def show_category_tools(category):
    """Display tools within a specific category and handle user selection."""
    while True:
        print("\n" + colored(f"{category['name']} Tools:", 'cyan', attrs=['bold']))
        for key, tool in category['tools'].items():
            print(colored(f"  [{key}] {tool['name']}", 'yellow'))
        print(colored("  [b] Back to Categories", 'blue'))
        print(colored("  [0] Exit", 'red'))
        
        choice = input("\nSelect an option: ").strip().lower()
        
        if choice == '0':
            print(colored("\nGoodbye!", 'red', attrs=['bold']))
            exit()
        elif choice == 'b':
            return
        elif choice in category['tools']:
            open_tool(category['tools'][choice])
        else:
            print(colored("\n[!] Invalid option. Please try again.", 'red'))

def show_categories():
    """Display available categories and handle user selection."""
    while True:
        print("\n" + colored("CTF Tools Categories:", 'cyan', attrs=['bold']))
        for key, category in CTF_CATEGORIES.items():
            print(colored(f"  [{key}] {category['name']} ({len(category['tools'])} tools)", 'yellow'))
        print(colored("  [0] Exit", 'red'))
        
        choice = input("\nSelect a category: ").strip()
        
        if choice == '0':
            print(colored("\nGoodbye!", 'red', attrs=['bold']))
            return
        elif choice in CTF_CATEGORIES:
            show_category_tools(CTF_CATEGORIES[choice])
        else:
            print(colored("\n[!] Invalid option. Please try again.", 'red'))

def main():
    """Main function to run the CTF Tools application."""
    print_banner()
    try:
        show_categories()
    except KeyboardInterrupt:
        print(colored("\n\n[!] Operation cancelled by user.", 'red'))
    except Exception as e:
        print(colored(f"\n[!] An error occurred: {str(e)}", 'red'))

if __name__ == "__main__":
    main()
