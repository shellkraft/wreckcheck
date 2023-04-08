import re
import sys
from colorama import Fore
import time

# banner
print(Fore.CYAN + '''
██╗    ██╗██████╗ ███████╗ ██████╗██╗  ██╗ ██████╗██╗  ██╗███████╗ ██████╗██╗  ██╗
██║    ██║██╔══██╗██╔════╝██╔════╝██║ ██╔╝██╔════╝██║  ██║██╔════╝██╔════╝██║ ██╔╝
██║ █╗ ██║██████╔╝█████╗  ██║     █████╔╝ ██║     ███████║█████╗  ██║     █████╔╝ 
██║███╗██║██╔══██╗██╔══╝  ██║     ██╔═██╗ ██║     ██╔══██║██╔══╝  ██║     ██╔═██╗ 
╚███╔███╔╝██║  ██║███████╗╚██████╗██║  ██╗╚██████╗██║  ██║███████╗╚██████╗██║  ██╗
 ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝                                                                
''' + Fore.MAGENTA + '''                            DEV: B4PH∅M3T | VER: 1.0
''')


def check_for_vulnerabilities(code):
    print('''[*] Checking code for vulnerabilities...
    ''')
    time.sleep(1)

    vulnerabilities = {
        "Input Validation": {
            "url": "https://cwe.mitre.org/data/definitions/20.html",
            "regex": r"[^a-zA-Z0-9\s]"
        },
        "Buffer Overflow": {
            "url": "https://owasp.org/www-community/vulnerabilities/Buffer_Overflow",
            "regex": r"(strcpy|strncpy|sprintf|vsprintf|memcpy|memmove|gets|scanf)\("
        },
        "Format String Attack": {
            "url": "https://owasp.org/www-community/attacks/Format_string_attack",
            "regex": r"%[0-9]*[a-z]"
        },
        "Command Injection": {
            "url": "https://owasp.org/www-community/attacks/Command_Injection",
            "regex": r"(\b((?:nc|ftp|sh|ssh|ping|telnet|ncat|nc.traditional|ncat.traditional|curl)\s.*[;&|]))"
        },
        "SQL Injection": {
            "url": "https://owasp.org/www-community/attacks/SQL_Injection",
            "regex": r"(execute|executemany|SELECT|INSERT INTO|UPDATE|DELETE FROM|WHERE|DROP TABLE|UNION|'OR'|\-\-)\("
        },
        "Cross-site Scripting (XSS)": {
            "url": "https://owasp.org/www-community/attacks/xss/",
            "regex": r"(<script|</script|document\.cookie|alert\()",
        },
        "Authentication": {
            "url": "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure",
            "regex": r"(password|secret|token)\s*=\s*[\"\'][a-zA-Z0-9]*[\"\']"
        }
    }

    with open(code, "r") as f:
        code = f.read()

    vulnerabilities_found = False

    for name, data in vulnerabilities.items():
        regex = data["regex"]
        url = data["url"]

        if re.search(regex, code):
            print(Fore.RED + f"\n[!] Potential {name} vulnerability found in code.")
            print(Fore.LIGHTYELLOW_EX + f"\tFor more information, see: {url}")
            lines = [i + 1 for i, x in enumerate(code.split("\n")) if re.search(regex, x)]
            print(Fore.RED + f"\t[!] Vulnerable line(s): {lines}")
            vulnerabilities_found = True
        else:
            print(Fore.LIGHTGREEN_EX + f"\n[+] No potential {name} vulnerabilities found in code.")
            print(Fore.LIGHTYELLOW_EX + f"\t[+] For more information, see: {url}")

    if not vulnerabilities_found:
        print(Fore.LIGHTGREEN_EX + "[+] No potential vulnerabilities found in code.")

    print(Fore.LIGHTCYAN_EX + "\n[*] Vulnerability scan complete.")


if __name__ == "__main__":
    while True:
        try:
            file_path = input(Fore.LIGHTCYAN_EX + "[*] Enter the file path of the code you want to check: ").strip('"')
            check_for_vulnerabilities(file_path)
            break
        except FileNotFoundError:
            print(Fore.RED + "[-] Error: File not found. Please enter a valid file path.")
        except Exception as e:
            print(Fore.RED + "[-] An error occurred while opening the file.:")
            print(e)
            print("[!] Make sure you are providing the correct file path.")
        except KeyboardInterrupt:
            print(Fore.RED + "\n[-] Keyboard interrupt detected. Exiting...")
            sys.exit(1)
