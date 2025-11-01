import asyncio
import sys
from asyncio import threads

import aiohttp
from aiohttp_socks import ProxyConnector

kraken_address = "http://omgomgomgzdayo2ay7sexbbsaxwd6dxikiw3be6ed2aoe7juxvigdkad.onion"

headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
}

cookies = {
    "scheck": "1",
    "ses": "kj4n84Yq9T00pkaMTS",
}

connector = ProxyConnector.from_url("socks5://127.0.0.1:9050")


async def start_parser(html, workers_count=10):
    pass


async def main():
    async with aiohttp.ClientSession(connector=connector, headers=headers, cookies=cookies) as session:
        async with session.get(kraken_address) as response:
            html = await response.text()
            if "Магазины" not in html:
                print("Не авторизован")
                sys.exit(-1)
            await start_parser(html)


if __name__ == '__main__':
    asyncio.run(main())