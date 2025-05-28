import asyncio
import socket
import json  # Для работы с JSON сообщениями протокола
import sqlite3
import bcrypt  # Для хеширования паролей
import os  # Для проверки существования файла БД

HOST = '127.0.0.1'
PORT = 65432
DB_NAME = 'messenger_server.db'

# Словарь для хранения активных аутентифицированных клиентов:
# {writer_объект: {"username": username, "addr_str": "IP:Port"}}
connected_clients = {}


# --- Функции для работы с БД ---
def init_db():
    """Инициализирует базу данных и создает таблицу пользователей, если ее нет."""
    db_exists = os.path.exists(DB_NAME)
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    if not db_exists:
        print("Создание новой базы данных и таблицы 'users'...")
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL
            )
        ''')
    conn.commit()
    conn.close()
    if not db_exists:  # Сообщение выводим только если БД реально создавалась
        print("База данных успешно инициализирована.")
    else:
        print("База данных уже существует.")


def register_user_db(username, password):
    """Регистрирует нового пользователя. Возвращает True при успехе, False если пользователь существует."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    try:
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                       (username, hashed_password.decode('utf-8')))
        conn.commit()
        return True
    except sqlite3.IntegrityError:  # Возникает, если username не уникален
        return False
    finally:
        conn.close()


def login_user_db(username, password):
    """Проверяет логин пользователя. Возвращает True при успехе, False иначе."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()
    conn.close()
    if result:
        hashed_password_from_db = result[0].encode('utf-8')
        return bcrypt.checkpw(password.encode('utf-8'), hashed_password_from_db)
    return False


# --- Основная логика сервера ---
async def handle_client(reader, writer):
    peername = writer.get_extra_info('peername')
    client_addr_str = f"{peername[0]}:{peername[1]}"
    print(f"Новый клиент пытается подключиться: {client_addr_str}")

    authenticated_username = None

    try:
        # Цикл аутентификации
        while authenticated_username is None:
            # Читаем данные для аутентификации
            # Добавляем обработку случая, если клиент отключается во время чтения
            try:
                auth_data_bytes = await reader.readuntil(separator=b'\n')  # Читаем до разделителя \n
            except asyncio.IncompleteReadError:  # Если соединение закрыто до получения \n
                print(
                    f"Клиент {client_addr_str} отключился до завершения отправки запроса аутентификации (IncompleteReadError).")
                return
            except ConnectionResetError:
                print(f"Клиент {client_addr_str} сбросил соединение во время запроса аутентификации.")
                return

            if not auth_data_bytes.strip():  # Если пришли только \n или пустая строка после strip
                print(f"Клиент {client_addr_str} прислал пустой запрос аутентификации. Отключаем.")
                return

            try:
                auth_request_str = auth_data_bytes.decode('utf-8').strip()
                if not auth_request_str:  # Дополнительная проверка после strip
                    print(f"Клиент {client_addr_str} прислал пустой запрос аутентификации (после strip).")
                    continue  # Дадим еще попытку или можно отключить

                auth_request = json.loads(auth_request_str)
                req_type = auth_request.get('type')
                username = auth_request.get('username')
                password = auth_request.get('password')

                response = {"type": "auth_fail", "message": "Неизвестная ошибка аутентификации."}  # По умолчанию

                if req_type == 'register':
                    if username and password:
                        if register_user_db(username, password):
                            # При успешной регистрации не логиним сразу, а просим войти.
                            response = {"type": "auth_success", "subtype": "register",
                                        "message": "Регистрация успешна. Пожалуйста, войдите."}
                        else:
                            response = {"type": "auth_fail", "message": "Пользователь с таким именем уже существует."}
                    else:
                        response = {"type": "auth_fail",
                                    "message": "Имя пользователя и пароль не могут быть пустыми для регистрации."}

                elif req_type == 'login':
                    if username and password:
                        if login_user_db(username, password):
                            response = {"type": "auth_success", "subtype": "login", "username": username,
                                        "message": f"Добро пожаловать, {username}!"}
                            authenticated_username = username  # Устанавливаем имя после успешного логина
                        else:
                            response = {"type": "auth_fail", "message": "Неверное имя пользователя или пароль."}
                    else:
                        response = {"type": "auth_fail",
                                    "message": "Имя пользователя и пароль не могут быть пустыми для входа."}
                else:
                    response = {"type": "auth_fail",
                                "message": "Неверный тип запроса аутентификации (ожидался 'login' или 'register')."}

                writer.write(json.dumps(response).encode('utf-8') + b'\n')
                await writer.drain()

                if response["type"] == "auth_fail" and req_type not in ['register', 'login']:
                    print(f"Неверный тип запроса аутентификации от {client_addr_str}. Отключаем.")
                    return
                # Если аутентификация не удалась (auth_fail), но это был валидный запрос login/register,
                # цикл while продолжится, и клиент сможет попробовать снова.
                # Если authenticated_username установился (успешный login), цикл while прервется.

            except json.JSONDecodeError:
                print(f"Ошибка декодирования JSON от {client_addr_str} при аутентификации.")
                error_resp = {"type": "auth_fail", "message": "Неверный формат запроса (ожидался JSON)."}
                writer.write(json.dumps(error_resp).encode('utf-8') + b'\n')
                await writer.drain()
                continue
            except Exception as e_auth:
                print(f"Ошибка в процессе аутентификации для {client_addr_str}: {e_auth}")
                error_resp = {"type": "auth_fail", "message": f"Внутренняя ошибка сервера: {e_auth}"}
                writer.write(json.dumps(error_resp).encode('utf-8') + b'\n')
                await writer.drain()
                return

                # --- Если аутентификация прошла успешно ---
        print(f"Клиент {client_addr_str} аутентифицирован как {authenticated_username}")
        connected_clients[writer] = {"username": authenticated_username, "addr_str": client_addr_str}

        await broadcast_message_async(
            json.dumps({"type": "user_joined", "username": authenticated_username}).encode('utf-8') + b'\n',
            None
        )

        # --- Основной цикл обработки сообщений после аутентификации ---
        while True:
            try:
                message_data_bytes = await reader.readuntil(separator=b'\n')
            except asyncio.IncompleteReadError:
                print(
                    f"Клиент {authenticated_username} ({client_addr_str}) отключился не завершив сообщение (IncompleteReadError).")
                break
            except ConnectionResetError:
                print(f"Клиент {authenticated_username} ({client_addr_str}) сбросил соединение в чате.")
                break

            if not message_data_bytes.strip():
                print(f"Клиент {authenticated_username} ({client_addr_str}) прислал пустое сообщение в чате.")
                continue

            try:
                message_request_str = message_data_bytes.decode('utf-8').strip()
                if not message_request_str: continue

                message_request = json.loads(message_request_str)
                req_type = message_request.get("type")

                if req_type == "message":
                    message_text = message_request.get("text", "")
                    if not message_text.strip():
                        continue
                    print(f"Получено от {authenticated_username} ({client_addr_str}): {message_text}")
                    chat_message = {
                        "type": "new_message",
                        "sender": authenticated_username,
                        "text": message_text
                    }
                    await broadcast_message_async(json.dumps(chat_message).encode('utf-8') + b'\n', None)
                elif req_type in ["login", "register"]:
                    print(f"Аутентифицированный пользователь {authenticated_username} ({client_addr_str}) "
                          f"прислал неожиданный запрос типа '{req_type}'. Отправка ошибки.")
                    error_resp = {
                        "type": "protocol_error",
                        "message": f"Вы уже аутентифицированы как {authenticated_username}. Повторный '{req_type}' не допускается."
                    }
                    try:
                        writer.write(json.dumps(error_resp).encode('utf-8') + b'\n')
                        await writer.drain()
                    except Exception as e_err_send:
                        print(f"Ошибка отправки protocol_error клиенту {authenticated_username}: {e_err_send}")
                else:
                    print(
                        f"Получен неизвестный тип сообщения от {authenticated_username} ({client_addr_str}): {message_request}")

            except json.JSONDecodeError:
                print(f"Ошибка декодирования JSON от {authenticated_username} ({client_addr_str}) в основном цикле.")
                # Можно отправить ошибку клиенту, если это необходимо
            except Exception as e_msg:
                print(f"Ошибка при обработке сообщения от {authenticated_username} ({client_addr_str}): {e_msg}")

    except asyncio.CancelledError:
        print(
            f"Задача для клиента {client_addr_str} (юзер: {authenticated_username or 'не аутентифицирован'}) была отменена.")
    except ConnectionResetError:  # Эта ошибка может возникнуть, если клиент закрыл соединение на любом этапе до входа в finally
        print(
            f"Клиент {client_addr_str} (юзер: {authenticated_username or 'не аутентифицирован'}) резко оборвал соединение (обработано в try/except).")
    except Exception as e_outer:  # Ловим другие неожиданные ошибки на уровне handle_client
        print(
            f"Общая ошибка при обработке клиента {client_addr_str} (юзер: {authenticated_username or 'не аутентифицирован'}): {e_outer}")
    finally:
        print(
            f"Клиент {client_addr_str} (юзер: {authenticated_username or 'не аутентифицирован'}) окончательно отключается.")

        if writer in connected_clients:
            # Используем authenticated_username, если он был установлен, иначе из словаря (на случай если он не None, а в словаре уже другой)
            leaving_username = authenticated_username if authenticated_username else connected_clients[writer].get(
                "username", "Неизвестный")
            del connected_clients[writer]
            await broadcast_message_async(
                json.dumps({"type": "user_left", "username": leaving_username}).encode('utf-8') + b'\n',
                None
            )

        if not writer.is_closing():
            writer.close()
            try:
                await writer.wait_closed()
            except Exception as e_close:
                print(f"Ошибка при ожидании закрытия writer для {client_addr_str}: {e_close}")


async def broadcast_message_async(message_bytes_with_newline, exclude_writer=None):
    # Копируем writer'ы, чтобы избежать проблем при изменении словаря во время итерации
    # Также получаем username для логирования, если writer еще в словаре
    writers_to_broadcast = []
    for w in list(connected_clients.keys()):  # Итерируемся по копии ключей
        if w in connected_clients:  # Проверяем, не удален ли writer другим потоком
            writers_to_broadcast.append((w, connected_clients[w].get("username", "N/A")))

    for client_writer, client_username_for_log in writers_to_broadcast:
        if client_writer == exclude_writer:
            continue

        # Дополнительная проверка, т.к. состояние могло измениться
        if client_writer.is_closing() or client_writer not in connected_clients:
            if client_writer in connected_clients:  # Если закрывается, но еще в словаре
                print(f"Writer для {client_username_for_log} уже закрывается или удален, пропускаем рассылку.")
                # Не удаляем здесь, удаление должно быть в handle_client или если отправка не удалась
            continue

        try:
            client_writer.write(message_bytes_with_newline)
            await client_writer.drain()
        except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError) as e_send:
            print(
                f"Не удалось отправить сообщение клиенту {client_username_for_log} (ошибка: {type(e_send).__name__}). Удаляем из connected_clients.")
            if client_writer in connected_clients:
                del connected_clients[client_writer]
            if not client_writer.is_closing():  # Закрываем, если еще не закрыт
                client_writer.close()
        except Exception as e_general_send:
            print(f"Общая ошибка при отправке сообщения клиенту {client_username_for_log}: {e_general_send}")


async def main_server_loop():
    init_db()
    server = await asyncio.start_server(
        handle_client, HOST, PORT
    )
    server_addr = server.sockets[0].getsockname()
    print(f'Сервер запущен на {server_addr[0]}:{server_addr[1]}')
    async with server:
        await server.serve_forever()


if __name__ == '__main__':
    try:
        asyncio.run(main_server_loop())
    except KeyboardInterrupt:
        print("\nСервер остановлен вручную.")
    finally:
        print("Сервер завершает работу.")