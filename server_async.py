import asyncio
import socket  # Используется для констант сокетов, если понадобится

HOST = '127.0.0.1'  # Адрес для прослушивания сервером
PORT = 65432  # Порт для прослушивания сервером

# Словарь для хранения активных клиентов: {writer_объект: "IP:Port_клиента"}
connected_clients = {}


async def handle_client(reader, writer):
    """
    Асинхронно обрабатывает соединение с одним клиентом.
    Читает сообщения от клиента и рассылает их всем остальным.
    """
    peername = writer.get_extra_info('peername')
    client_addr_str = f"{peername[0]}:{peername[1]}"
    print(f"Новый клиент подключен: {client_addr_str}")

    # Добавляем нового клиента в общий список
    connected_clients[writer] = client_addr_str

    # Уведомляем всех о подключении нового клиента
    # Второй аргумент None означает, что сообщение будет разослано всем, включая нового клиента
    await broadcast_message_async(f"Клиент {client_addr_str} присоединился к чату.".encode('utf-8'), None)

    try:
        while True:
            # Асинхронное чтение данных от клиента (до 1024 байт)
            data = await reader.read(1024)
            if not data:
                # Если данных нет, клиент закрыл соединение корректно
                break

            message_text = data.decode('utf-8')
            print(f"Получено от {client_addr_str}: {message_text}")

            # Формируем сообщение для рассылки, добавляя информацию об отправителе
            full_message = f"[{client_addr_str}] {message_text}".encode('utf-8')

            # Рассылаем сообщение всем подключенным клиентам (включая отправителя)
            await broadcast_message_async(full_message, None)

    except asyncio.CancelledError:
        # Эта ошибка возникает, когда задача отменяется (например, при остановке сервера)
        print(f"Задача для клиента {client_addr_str} была отменена.")
    except ConnectionResetError:
        # Клиент оборвал соединение неожиданно
        print(f"Клиент {client_addr_str} резко оборвал соединение.")
    except Exception as e:
        # Ловим другие возможные ошибки при работе с клиентом
        print(f"Ошибка при обработке клиента {client_addr_str}: {e}")
    finally:
        # Этот блок выполняется всегда при выходе из try (нормальном или из-за ошибки)
        print(f"Клиент {client_addr_str} отключился.")

        # Удаляем клиента из словаря активных клиентов, если он там есть
        if writer in connected_clients:
            del connected_clients[writer]

        # Закрываем соединение с клиентом, если оно еще не закрыто
        if not writer.is_closing():
            writer.close()
            try:
                await writer.wait_closed()  # Ожидаем полного закрытия
            except Exception as e_close:
                print(f"Ошибка при ожидании закрытия writer для {client_addr_str}: {e_close}")

        # Уведомляем оставшихся клиентов об отключении
        await broadcast_message_async(f"Клиент {client_addr_str} покинул чат.".encode('utf-8'), None)


async def broadcast_message_async(message_bytes, exclude_writer=None):
    """
    Асинхронно рассылает сообщение (в байтах) всем подключенным клиентам,
    кроме указанного в exclude_writer (если он задан).
    """
    # Создаем копию ключей, так как словарь connected_clients может изменяться во время итерации
    # (например, если клиент отключается во время рассылки)
    current_writers = list(connected_clients.keys())

    for client_writer in current_writers:
        if client_writer == exclude_writer:
            continue  # Пропускаем отправителя, если нужно

        # Проверяем, не находится ли writer в процессе закрытия
        if client_writer.is_closing():
            # Если writer закрывается, но все еще в словаре, удаляем его
            if client_writer in connected_clients:
                print(f"Writer для {connected_clients[client_writer]} уже закрывается, удаляем из рассылки.")
                del connected_clients[client_writer]
            continue

        try:
            client_writer.write(message_bytes)  # Отправляем данные
            await client_writer.drain()  # Ждем, пока буфер очистится (данные реально отправлены)
        except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError) as e_send:
            # Эти ошибки означают, что соединение с клиентом потеряно или задача отменена
            addr_str_failed = connected_clients.get(client_writer, "Неизвестный клиент (уже удален)")
            print(
                f"Не удалось отправить сообщение клиенту {addr_str_failed} (ошибка: {type(e_send).__name__}). Удаляем.")
            if client_writer in connected_clients:
                del connected_clients[client_writer]
            if not client_writer.is_closing():
                client_writer.close()
                # Не ждем wait_closed() здесь, чтобы не блокировать рассылку другим
        except Exception as e_general_send:
            # Ловим другие возможные ошибки при отправке
            addr_str_failed = connected_clients.get(client_writer, "Неизвестный клиент (уже удален)")
            print(f"Общая ошибка при отправке сообщения клиенту {addr_str_failed}: {e_general_send}")


async def main_server_loop():
    """
    Основная функция для запуска сервера.
    """
    # Запускаем TCP сервер, который будет вызывать handle_client для каждого нового соединения
    server = await asyncio.start_server(
        handle_client, HOST, PORT
    )

    # Получаем информацию о том, на каком адресе и порту реально запустился сервер
    # (полезно, если HOST='0.0.0.0' или PORT=0)
    server_addr = server.sockets[0].getsockname()
    print(f'Сервер запущен на {server_addr[0]}:{server_addr[1]}')

    # Используем 'async with server:' для корректного управления ресурсами сервера
    async with server:
        # Запускаем сервер в бесконечном цикле для обработки соединений
        await server.serve_forever()


if __name__ == '__main__':
    try:
        # Запускаем основной цикл событий asyncio с нашей серверной функцией
        asyncio.run(main_server_loop())
    except KeyboardInterrupt:
        # Обработка прерывания с клавиатуры (Ctrl+C) для корректной остановки
        print("\nСервер остановлен вручную.")
    finally:
        print("Сервер завершает работу.")