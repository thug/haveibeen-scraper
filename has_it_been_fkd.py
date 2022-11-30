from asyncio import gather, Semaphore, set_event_loop_policy, WindowsSelectorEventLoopPolicy, run
from os import listdir
from typing import Any
from aiohttp import ClientSession
from json import dumps, loads
from platform import system
from re import compile, finditer
from aiohttp_proxy import ProxyConnector
from rich.console import Console
import aiofiles

console: Console = Console()
breach_cache: dict[str: int] = {}


async def gather_tasks(max_workers: int, *tasks) -> gather:
    """
    Create semaphore for thread handling

    :param max_workers: (int) - Max workers for semaphore
    :param tasks: (coroutine) - Tasks to run through async semaphore
    :return: (asyncio.gather)
    """
    semaphore = Semaphore(max_workers)

    async def sem_task(task):
        async with semaphore:
            return await task

    return await gather(*(sem_task(task) for task in tasks))


async def count_breach(name) -> None:
    """
    Add a database & increment it in breach cache

    :param name: (str) - Database name
    :return: (None) -> None
    """
    try:
        breach_cache[name] += 1
    except KeyError:
        breach_cache[name] = 1


async def check_breaches(session: ClientSession, email_address: str) -> tuple[bool, list, int] | None:
    """
    Get a list of data breaches an email is involved in and then add them to the breach cache

    :param session: (ClientSession) - Session you're running the requests on
    :param email_address: (str) - email_address
    :return: (tuple[bool, list, int]) - Breached (bool), Breaches (list), Breaches found (int)
    """

    base_url: str = f"https://haveibeenpwned.com/unifiedsearch/{email_address.replace('@', '%40')}"
    headers: dict[str: str] = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:107.0) Gecko/20100101 Firefox/107.0",
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.5",
        "Referer": "https://haveibeenpwned.com/",
        "X-Requested-With": "XMLHttpRequest",
        "DNT": "1",
        "Connection": "keep-alive",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin",
        "Sec-GPC": "1"
    }

    async with session.get(url=base_url, headers=headers) as lookup:
        output_data: dict = {"email": email_address, "databases": None, "database_list": []}
        if ("Cloudflare to restrict access" in await lookup.text()) or (lookup.status == 433):
            console.log(f"[red bold]CLOUDFLARE! [white]Blocked [magenta bold]request [white]for [cyan]{email_address}")
            return await check_breaches(session, email_address)

        if lookup.status == 404:
            console.log(f"[red bold]NO BREACHES! [cyan]{email_address} [white]has not been found in any public data breaches.")
            return

        data = await lookup.json()
        data_breaches: str = data["Breaches"]

        [await count_breach(database["Name"]) for database in data_breaches]

        output_data["databases"] = len(data_breaches)
        output_data["database_list"] = [database["Name"] for database in data_breaches]

        console.log(f"[green bold]BREACHED! [cyan]{email_address} [white]has been found in [green bold]{output_data['databases']} databases[white]!")
        return True, [db['Name'] for db in data_breaches], len(data_breaches)


async def load_files() -> tuple[list[str], dict]:
    """
    Load config & emails and return them in a tuple to be used in execution.

    :return: (tuple[list[str], dict]]) - Lines to check (list[str]), configuration (dict)
    """

    console.rule("File Loader")

    config: dict = {'thread_count': 50, 'file_name': 'input_emails.txt', 'rotating_proxy': ''}
    config_name: str = "config.json"

    def create_file(file_name: str, file_contents: Any) -> None:
        open(file_name, "a").write(file_contents)
        console.log(f'[green bold]Created file "{file_name}"!')

    if config_name not in listdir(): create_file(config_name, dumps(config, indent=4))
    if config["file_name"] not in listdir(): create_file(config["file_name"], "")

    async with aiofiles.open(config["file_name"], "r") as file:
        email_regex = compile(r"([a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+\.[a-zA-Z0-9_-]+)")
        lines = [mail.group(0) for mail in finditer(email_regex, "\n".join(await file.readlines()))]

    console.log(f"[cyan]{len(lines)} emails [white]loaded from input file.")
    return lines, loads(open(config_name, "r").read())


async def execute() -> None:
    lines, configuration = await load_files()
    console.log(f"[white]Config loaded! [red bold]{configuration}")
    console.rule("Starting Checking Process...")

    connector = ProxyConnector.from_url(configuration["rotating_proxy"])
    async with ClientSession(connector=connector) as client_session:
        await gather_tasks(configuration["thread_count"], *[check_breaches(client_session, mail) for mail in lines])

    console.rule(title="Data Breach Stats")
    sorted_cache = {name: count for name, count in sorted(breach_cache.items(), key=lambda i: i[1], reverse=True)}

    console.print(sorted_cache)


if __name__ == "__main__":
    if system() == 'Windows':
        set_event_loop_policy(WindowsSelectorEventLoopPolicy())

    run(execute())
