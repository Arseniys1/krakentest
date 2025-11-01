import asyncio
import string
import sys
from logging import Logger

import aiofiles
import aiohttp
from aiohttp_socks import ProxyConnector
import logging

from bs4 import BeautifulSoup
from faker.generator import random

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

kraken_address = "http://omgomgomgzdayo2ay7sexbbsaxwd6dxikiw3be6ed2aoe7juxvigdkad.onion"

headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
}

cookies = {
    "scheck": "1",
    "ses": "kj4n84Yq9T00pkaMTS",
}


CONNECTOR = None

SAVE_DIR = "./pages"

urls_buffer = []


async def parse_worker(worker_id, queue, session):
    """Worker для парсинга страниц"""
    while True:
        try:
            # Получаем задание из очереди
            url = await queue.get()

            if ".onion" not in url:
                url = f"{kraken_address}{url}"

            logger.info(f"Worker {worker_id} обрабатывает: {url}")

            # Здесь ваш парсинг
            result = await parse_page(session, url)

            # Обработка результата
            await process_result(result, queue)

            # Помечаем задание как выполненное
            queue.task_done()

        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Worker {worker_id} ошибка: {e}")
            queue.task_done()


async def parse_page(session, url):
    """Парсинг конкретной страницы"""
    while True:
        async with session.get(url) as response:
            if response.status != 200 and response.status != 302:
                continue

            html = await response.text()

            html_page = BeautifulSoup(html, "html.parser")
            links = html_page.find_all("a")

            return {"url": url, "html": html, "links": links}


async def process_result(result, queue):
    """Обработка результатов парсинга"""
    # Здесь сохраняем данные в БД, файл и т.д.

    for link in result["links"]:
        if link["href"] not in urls_buffer:
            urls_buffer.append(link["href"])
            await queue.put(f"{link['href']}")

    logger.info(f"Url'ов в очереди: {queue.qsize()}")

    filename = "".join(random.choice(string.ascii_letters + string.digits) for _ in range(10))
    filename = filename + ".html"

    data = result["url"] + "\r\n" + result["html"]

    async with aiofiles.open(f"{SAVE_DIR}/{filename}", 'w', encoding='utf-8') as f:
        await f.write(data)

    logger.info(f"Обработан результат: {result['url']}")


async def start_parser(html, workers_count=10):
    """Запуск парсера с несколькими worker'ами"""

    # Создаем очередь для заданий
    queue = asyncio.Queue()

    await queue.put(kraken_address)

    # Создаем worker'ы
    workers = []
    async with aiohttp.ClientSession(connector=CONNECTOR, headers=headers, cookies=cookies) as session:
        for i in range(workers_count):
            worker = asyncio.create_task(parse_worker(i, queue, session))
            workers.append(worker)

        # Ждем завершения всех заданий
        await queue.join()

        # Отменяем worker'ы
        for worker in workers:
            worker.cancel()

        # Ждем завершения worker'ов
        await asyncio.gather(*workers, return_exceptions=True)


async def main():
    global CONNECTOR

    CONNECTOR = ProxyConnector.from_url("socks5://127.0.0.1:9050")

    async with aiohttp.ClientSession(connector=CONNECTOR, headers=headers, cookies=cookies) as session:
        async with session.get(kraken_address) as response:
            html = await response.text()
            if "Магазины" not in html:
                print("Не авторизован")
                sys.exit(-1)
            await start_parser(html, workers_count=10)


if __name__ == '__main__':
    asyncio.run(main())
