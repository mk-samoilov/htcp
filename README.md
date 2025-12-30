# High TCP

я хочу что бы код приложения-сервера на этой библиотеке был примерно такой структуры
```
from htcp import Server, Config, Request

import logging


myconf = Config(
    host="0.0.0.0",
    port=9576,
    name="test_server", # имя шлюза отображается в логах и тд
    max_connections=100,
    handle_connections=90,
    logging=True,
    logging_level=logging.INFO
    dh_encryption=True # Шифрование на алгоритме Деффи Хелмена
    connect_passkey=False # если строка то доп проверка ключа-строки-этой при подключении
)

serv = Server(config=myconf)


@serv.rh.reg_handler(trans_code="get_my_ip")
def get_my_ip(request: Request) -> bytes:
    print(request.client.ip) # str
    print(request.client.port) # int
    print(request.data) # данные в байтах (пользовательские)
    print(request.package.from) # ip:port
    print(request.package.transaction) # str
    print(request.package.uuid) # str
    и тд

    return {"your_ip": request.client.ip}закодированная в json и в байты


@serv.rh.reg_handler(и тд много обработчиков транзакций)


serv.up()
```
с @serv.rh.reg_handler и serv.up и конфигом

а код клиента:
```
from htcp_client import Client, Response, Package


client = Client(host="localhost", port=9576, dh_encryption=True, passkey="-") # passkey сервер не проверяет тк False


pkg = Package(
    transaction = "get_my_ip",
    content=dict->json->bytes->мне лень тут писать это просто
)

response: Package = client.ask(package=pkg) аск отправляетс запрос и получает ответ
print декодировать принтануть ip
```
сделай кроме аск еще простые функции .send(package) .receive()

сервер и клиент на socket

придерживайся текущей структуре проекта
можно изменять структуру проекта: добавлять/удалять пару файлов

max_connections - максимальное кол-во подключений в раз
handle_connections - то сколько клиентов будет обрабатываться одновременно
сделай сервер асинхронным

logging на библиотеке logging
