import base64
import re
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from bs4 import BeautifulSoup
from faker.proxy import Faker

kraken_address = "http://omgomgomgzdayo2ay7sexbbsaxwd6dxikiw3be6ed2aoe7juxvigdkad.onion"
proxies = {
    'http': 'socks5h://127.0.0.1:9050',
    'https': 'socks5h://127.0.0.1:9050'
}

headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
}

CAPTCHA_IMG = ""
CONTENT_TYPE_PNG = "image/png"
CONTENT_TYPE_JPEG = "image/jpeg"
CONTENT_TYPE = CONTENT_TYPE_PNG

server_thread = None

PNG_BASE64_PREFIX = "data:image/png;base64,  "
JPEG_BASE64_PREFIX = "data:image/jpeg;charset=utf-8;base64, "


def main():
    start_server_async()
    cookies, login_captcha, register_captcha = process_index_captcha_bypass()
    login, password, recovery_code, captcha = process_register(cookies, register_captcha)
    process_login(cookies, captcha, login, password, recovery_code)


def process_index_captcha_bypass():
    global CAPTCHA_IMG

    resp_index = requests.get(kraken_address, proxies=proxies, headers=headers)
    resp_captcha = requests.get(f"{kraken_address}/captcha", cookies=resp_index.cookies.get_dict(), proxies=proxies,
                                headers=headers)
    CAPTCHA_IMG = resp_captcha.text.replace(PNG_BASE64_PREFIX, "")
    print("Капча обновлена")

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

    resp_index_tck = requests.get(f"{kraken_address}/?tck=2", cookies=index_tck_cookies, proxies=proxies,
                                  headers=headers)

    parsed_html = BeautifulSoup(resp_index_tck.text, "html.parser")
    captcha_base64 = parsed_html.find("img", attrs={"id": "captcha-img"})["src"]
    ref = parsed_html.find("input", attrs={"name": "ref"})["value"]
    user_id = parsed_html.find("input", attrs={"name": "userId"})["value"]
    fate = parsed_html.find("input", attrs={"name": "fate"})["value"]

    CAPTCHA_IMG = captcha_base64.replace(PNG_BASE64_PREFIX, "")
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

    parsed_login_register_page = BeautifulSoup(resp_captcha_check.text, "html.parser")

    login_form = parsed_login_register_page.find("form", class_="authorization-block")
    register_form = parsed_login_register_page.find("form", class_="authorization-block register_form")

    login_captcha_img = login_form.find_all("img")
    register_captcha_img = register_form.find_all("img")
    login_captcha = login_captcha_img[0]["src"]
    register_captcha = register_captcha_img[0]["src"]
    login_captcha = login_captcha.replace(JPEG_BASE64_PREFIX, "")
    register_captcha = register_captcha.replace(JPEG_BASE64_PREFIX, "")

    return captcha_check_cookies, login_captcha, register_captcha


def process_register(cookies, register_captcha):
    global CAPTCHA_IMG, CONTENT_TYPE

    CAPTCHA_IMG = register_captcha
    CONTENT_TYPE = CONTENT_TYPE_JPEG
    print("Капча обновлена")
    captcha = input("Enter Captcha Code: ")

    fake = Faker("en")
    login = fake.pystr(min_chars=8, max_chars=20)
    display_name = fake.pystr(min_chars=8, max_chars=20)
    password = fake.password(length=15)

    register_payload = {
        "timezoneoffset": 0,
        "login": login,
        "display_name": display_name,
        "password1": password,
        "password2": password,
        "captcha": captcha.upper(),
    }

    register_resp = requests.post(f"{kraken_address}/entry/post/register", data=register_payload, cookies=cookies,
                                  proxies=proxies, headers=headers)

    recovery_page = BeautifulSoup(register_resp.text, "html.parser")
    recovery_div = recovery_page.find("div", class_="login-input login-input--read")
    recovery_code = recovery_div.get_text()

    select_city_payload = {
        "city": "fef154eb-5300-46d7-916e-f60e6a1d193e"  # Москва
    }

    select_city_resp = requests.post(f"{kraken_address}/select/city/", data=select_city_payload, cookies=cookies,
                                     proxies=proxies, headers=headers)

    print("Login: ", login, " Password: ", password, " Recovery Code: ", recovery_code)
    print("Cookies:", cookies)

    return login, password, recovery_code, captcha


def process_login(cookies, captcha, username, password, recovery_code):
    login_payload = {
        "login": username,
        "password": password,
        "captcha": captcha.upper(),
    }

    login_resp = requests.post(f"{kraken_address}/entry/post/login", data=login_payload, cookies=cookies,
                               proxies=proxies, headers=headers)

    if "Магазины" in login_resp.text:
        print("Авторизован")

    print("After login. Login: ", username, " Password: ", password, " Recovery Code: ", recovery_code)
    print("After login. Cookies:", cookies)


def to_numbers(hex_string):
    """Аналог функции toNumbers из JavaScript"""
    result = []
    # ДОБАВЬ ЭТУ ПРОВЕРКУ
    if len(hex_string) % 2 != 0:
        hex_string = '0' + hex_string  # Добавляем ведущий ноль если необходимо
    for i in range(0, len(hex_string), 2):
        result.append(int(hex_string[i:i + 2], 16))
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
        global CAPTCHA_IMG

        image_data = base64.b64decode(CAPTCHA_IMG)

        if self.path == '/':
            # Отправляем заголовки
            self.send_response(200)
            self.send_header('Content-Type', CONTENT_TYPE)
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
