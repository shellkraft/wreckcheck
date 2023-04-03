import re

# Get file path from user input
file_path = input("Enter the file path of the code you want to check: ")

# Open the file and read the code
with open(file_path, 'r') as file:
    code = file.read()


# Function to check for vulnerabilities using a regular expression
def check_vulnerabilities(regex, message):
    matches = re.finditer(regex, code)
    result = ""
    for match in matches:
        line_number = code[:match.start()].count('\n') + 1
        result += f"Potential {message} vulnerability found in line {line_number}: {match.group(0)}\n"
    if result:
        return result
    else:
        return f"No potential {message} vulnerabilities found in code."


# Functions to check for specific vulnerabilities
def check_input_validation_vulnerability():
    regex = r"gets\("
    message = "input validation"
    return check_vulnerabilities(regex, message)


def check_buffer_overflow_vulnerability():
    regex = r"(strcpy|strcat|sprintf|vsprintf)\("
    message = "buffer overflow"
    return check_vulnerabilities(regex, message)


def check_format_string_vulnerability():
    regex = r"printf\("
    message = "format string"
    return check_vulnerabilities(regex, message)


def check_command_injection_vulnerability():
    regex = r"(popen|system|exec)\("
    message = "command injection"
    return check_vulnerabilities(regex, message)


def check_sql_injection_vulnerability():
    regex = r"(\.execute\(|\.executemany\(|SELECT\s.*WHERE\s.*=\s*[\"']?\+\s*)"
    message = "SQL injection"
    return check_vulnerabilities(regex, message)


def check_xss_vulnerability():
    regex = r"document\.write\(|innerHTML\s*=\s*|\".*?\";?\s*\+\s*.*?\s*\+\s*.*?\s*\+"
    message = "cross-site scripting (XSS)"
    return check_vulnerabilities(regex, message)


def check_authentication_vulnerability():
    regex = r"(password|passwd|secret)\s*=\s*[\"'].*?[\"']"
    message = "authentication"
    return check_vulnerabilities(regex, message)


# Call the vulnerability checking functions and print the results
print(check_input_validation_vulnerability())
print(check_buffer_overflow_vulnerability())
print(check_format_string_vulnerability())
print(check_command_injection_vulnerability())
print(check_sql_injection_vulnerability())
print(check_xss_vulnerability())
print(check_authentication_vulnerability())


        	
