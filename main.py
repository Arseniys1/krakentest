import base64
import re
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from bs4 import BeautifulSoup

kraken_address = "http://omgomgomgzdayo2ay7sexbbsaxwd6dxikiw3be6ed2aoe7juxvigdkad.onion"
proxies = {
    'http': 'socks5h://127.0.0.1:9050',
    'https': 'socks5h://127.0.0.1:9050'
}

headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
}

BASE64_PNG = ""

server_thread = None


def main():
    global BASE64_PNG

    resp_index = requests.get(kraken_address, proxies=proxies, headers=headers)
    resp_captcha = requests.get(f"{kraken_address}/captcha", cookies=resp_index.cookies.get_dict(), proxies=proxies,
                                headers=headers)
    BASE64_PNG = resp_captcha.text
    print("Капча обновлена")

    start_server_async()

    captcha = input("Enter Captcha Code: ")

    captcha_check_data = {
        "answer": captcha.upper()
    }

    captcha_check_cookies = resp_index.cookies.get_dict() | resp_captcha.cookies.get_dict()

    resp_captcha_check = requests.post(kraken_address,
                                       data=captcha_check_data,
                                       cookies=captcha_check_cookies,
                                       proxies=proxies, headers=headers)

    a, b, c = extract_variables_from_html(resp_captcha_check.text)
    hex_res, decrypted = extract_and_decrypt(a, b, c)

    index_tck_cookies = captcha_check_cookies | {
        "TCK": hex_res,
    }

    resp_index_tck = requests.get(f"{kraken_address}/?tck=2", cookies=index_tck_cookies, proxies=proxies, headers=headers)

    parsed_html = BeautifulSoup(resp_index_tck.text, "html.parser")
    captcha_base64 = parsed_html.find("img", attrs={"id": "captcha-img"})["src"]
    ref = parsed_html.find("input", attrs={"name": "ref"})["value"]
    user_id = parsed_html.find("input", attrs={"name": "userId"})["value"]
    fate = parsed_html.find("input", attrs={"name": "fate"})["value"]

    BASE64_PNG = captcha_base64
    print("Капча обновлена")

    captcha = input("Enter Captcha Code: ")

    captcha_check_data = captcha_check_data | {
        "answer": captcha.upper(),
        "ref": ref,
        "userId": user_id,
        "fate": fate,
    }

    captcha_check_cookies = index_tck_cookies | resp_index_tck.cookies.get_dict()

    resp_captcha_check = requests.post(kraken_address,
                                       data=captcha_check_data,
                                       cookies=captcha_check_cookies,
                                       proxies=proxies, headers=headers)

    print(resp_captcha_check.text)


def to_numbers(hex_string):
    """Аналог функции toNumbers из JavaScript"""
    result = []
    # ДОБАВЬ ЭТУ ПРОВЕРКУ
    if len(hex_string) % 2 != 0:
        hex_string = '0' + hex_string  # Добавляем ведущий ноль если необходимо
    for i in range(0, len(hex_string), 2):
        result.append(int(hex_string[i:i+2], 16))
    return result

def to_hex(numbers):
    """Аналог функции toHex из JavaScript"""
    result = ""
    for num in numbers:
        result += f"{num:02x}"
    return result


def extract_variables_from_html(html_content):
    """Извлекает переменные a, b, c из HTML кода"""

    # Ищем все три переменные в одной строке
    pattern = r'var a=toNumbers\("([0-9a-f]+)"\),b=toNumbers\("([0-9a-f]+)"\),c=toNumbers\("([0-9a-f]+)"\)'
    match = re.search(pattern, html_content)

    if match:
        a_hex = match.group(1)
        b_hex = match.group(2)
        c_hex = match.group(3)

        a = to_numbers(a_hex)
        b = to_numbers(b_hex)
        c = to_numbers(c_hex)

        print(f"Found variables:")
        print(f"a = {a_hex} -> {a}")
        print(f"b = {b_hex} -> {b}")
        print(f"c = {c_hex} -> {c}")

        return a, b, c
    else:
        print("Failed to extract variables from HTML")
        return None, None, None


def slow_aes_decrypt_python(ciphertext, key, iv):
    """
    Реализация AES дешифрования аналогичная slowAES.decrypt(c, 2, a, b)
    mode 2 = CBC mode
    """
    try:
        # ДОБАВЬ ЭТИ ПРОВЕРКИ
        print(f"Key length: {len(key)}, IV length: {len(iv)}, Ciphertext length: {len(ciphertext)}")

        # Если ciphertext короче 16 байт, дополняем нулями
        if len(ciphertext) < 16:
            ciphertext = ciphertext + [0] * (16 - len(ciphertext))
            print(f"Padded ciphertext to 16 bytes: {ciphertext}")

        # Создаем AES cipher в режиме CBC
        cipher = AES.new(bytes(key), AES.MODE_CBC, bytes(iv))

        # Дешифруем
        decrypted = cipher.decrypt(bytes(ciphertext))

        # ПРОБУЕМ убрать padding, но не падаем при ошибке
        try:
            decrypted = unpad(decrypted, AES.block_size)
            print("Padding removed successfully")
        except Exception as pad_error:
            print(f"Padding error (using raw): {pad_error}")
            # Используем как есть без padding

        return decrypted
    except Exception as e:
        print(f"Decryption error: {e}")
        return None


def extract_and_decrypt(a, b, c):
    """Извлекает данные из HTML и выполняет дешифрование"""

    # Выполняем дешифрование
    print("\nPerforming AES decryption...")
    decrypted = slow_aes_decrypt_python(
        c,  # ciphertext
        a,  # key
        b  # iv
    )

    if decrypted:
        hex_result = to_hex(decrypted)
        print(f"Decrypted result (hex): {hex_result}")

        # Пробуем декодировать как текст
        try:
            text_result = decrypted.decode('utf-8')
            print(f"Decrypted result (text): {text_result}")
        except:
            print("Decrypted result is not valid UTF-8 text")

        return hex_result, decrypted

    return None, None


class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        global BASE64_PNG

        BASE64_PNG = BASE64_PNG.replace("data:image/png;base64,  ", "")

        image_data = base64.b64decode(BASE64_PNG)

        if self.path == '/':
            # Отправляем заголовки
            self.send_response(200)
            self.send_header('Content-Type', 'image/png')
            self.send_header('Content-Length', str(len(image_data)))
            self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate, max-age=0')
            self.send_header('Pragma', 'no-cache')
            self.send_header('Expires', '0')
            self.end_headers()

            # Отправляем изображение
            self.wfile.write(image_data)
        else:
            self.send_error(404, "File not found")


def run_server(port=8000):
    server_address = ('', port)
    httpd = HTTPServer(server_address, SimpleHTTPRequestHandler)
    print(f"Server running on http://localhost:{port}")
    httpd.serve_forever()


def start_server_async(port=8000):
    """Запускает сервер в отдельном потоке"""
    global server_thread
    server_thread = threading.Thread(target=run_server, args=(port,))
    server_thread.daemon = True  # Поток завершится при завершении main потока
    server_thread.start()
    print(f"Server starting asynchronously on port {port}...")


if __name__ == '__main__':
    main()
