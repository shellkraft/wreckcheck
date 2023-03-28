import re

# Get file path from user input
file_path = input("Enter the file path of the code you want to check: ")

# Open the file and read the code
with open(file_path, 'r') as file:
    code = file.read()

def check_input_validation(code):
    regex = r"gets\("
    matches = re.finditer(regex, code)
    result = ""
    for match in matches:
        result += f"Potential input validation vulnerability found in line {code[:match.start()].count('\n')+1}: {match.group(0)}\n"
    if result:
        return result
    else:
        return "No potential input validation vulnerabilities found in code."


def check_buffer_overflow(code):
    regex = r"(strcpy|strcat|sprintf|vsprintf)\("
    matches = re.finditer(regex, code)
    result = ""
    for match in matches:
        result += f"Potential buffer overflow vulnerability found in line {code[:match.start()].count('\n')+1}: {match.group(0)}\n"
    if result:
        return result
    else:
        return "No potential buffer overflow vulnerabilities found in code."


def check_format_string(code):
    regex = r"printf\("
    matches = re.finditer(regex, code)
    result = ""
    for match in matches:
        result += f"Potential format string vulnerability found in line {code[:match.start()].count('\n')+1}: {match.group(0)}\n"
    if result:
        return result
    else:
        return "No potential format string vulnerabilities found in code."


def check_command_injection(code):
    regex = r"(popen|system|exec)\("
    matches = re.finditer(regex, code)
    result = ""
    for match in matches:
        result += f"Potential command injection vulnerability found in line {code[:match.start()].count('\n')+1}: {match.group(0)}\n"
    if result:
        return result
    else:
        return "No potential command injection vulnerabilities found in code."


def check_sql_injection(code):
    regex = r"(\.execute\(|\.executemany\(|SELECT\s.*WHERE\s.*=\s*[\"']?\+\s*)"
    matches = re.finditer(regex, code)
    result = ""
    for match in matches:
        result += f"Potential SQL injection vulnerability found in line {code[:match.start()].count('\n')+1}: {match.group(0)}\n"
    if result:
        return result
    else:
        return "No potential SQL injection vulnerabilities found in code."


def check_xss(code):
    regex = r"document\.write\(|innerHTML\s*=\s*|\".*?\";?\s*\+\s*.*?\s*\+\s*.*?\s*\+"
    matches = re.finditer(regex, code)
    result = ""
    for match in matches:
        result += f"Potential cross-site scripting (XSS) vulnerability found in line {code[:match.start()].count('\n')+1}: {match.group(0)}\n"
    if result:
        return result
    else:
        return "No potential cross-site scripting (XSS) vulnerabilities found in code."


def check_authentication(code):
    regex = r"(password|passwd|secret)\s*=\s*[\"'].*?[\"']"
    matches = re.finditer(regex, code)
    result = ""
    for match in matches:
        result += f"Potential authentication vulnerability found in line {code[:match.start()].count('\n')+1}: {match.group(0)}\n"
        if result:
        	return result
        	else:
        		return "No potential authentication vulnerability found in code. "
        		
def secure_code_check(file_path):
    with open(file_path, 'r') as f:
        code = f.read()

    print("Checking for potential vulnerabilities in file:", file_path)
    print("-" * 50)

    print(check_input_validation(code))
    print(check_buffer_overflow(code))
    print(check_format_string(code))
    print(check_command_injection(code))
    print(check_sql_injection(code))
    print(check_xss(code))
    print(check_authentication(code))
    print(check_crypto(code))
    print(check_error_handling(code))
    print(check_permissions(code))

    print("-" * 50)
    print("Secure coding guidelines check")


        	
