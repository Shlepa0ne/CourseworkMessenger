import socket

HOST = '127.0.0.1'
PORT = 65432


def start_server():
    # Создаем объект сокета
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # Связываем сокет с адресом хоста и портом
        s.bind((HOST, PORT))

        # Начинаем прослушивать входящие соединения
        s.listen()
        print(f"Сервер запущен и слушает на {HOST}:{PORT}")

        # Когда клиент подключается, accept() возвращает две вещи:
        # conn - новый объект сокета, через который мы будем общаться с этим клиентом.
        # addr - адрес подключившегося клиента (IP и порт).
        conn, addr = s.accept()

        with conn:
            print(f"Подключен клиент: {addr}")
            # Бесконечный цикл для получения данных от клиента
            while True:
                data = conn.recv(1024)

                # Если recv() возвращает пустые байты (b''), это значит, что клиент закрыл соединение.
                if not data:
                    break

                message = data.decode('utf-8')
                print(f"Получено от клиента: {message}")

                # Отправляем ответ клиенту. Сообщение сначала кодируется обратно в байты.
                conn.sendall(f"Сервер получил: {message}".encode('utf-8'))

            print(f"Клиент {addr} отключился.")


if __name__ == "__main__":
    start_server()

import socket

HOST = '127.0.0.1'
PORT = 65432


def start_client():
    # Создаем объект сокета
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            # Пытаемся подключиться к серверу по указанному хосту и порту
            s.connect((HOST, PORT))
            print(f"Подключен к серверу {HOST}:{PORT}")

            # Бесконечный цикл для отправки сообщений
            while True:
                message_to_send = input("Введите сообщение для сервера (или 'exit' для выхода): ")

                # Если пользователь ввел 'exit', выходим из цикла
                if message_to_send.lower() == 'exit':
                    break

                # Кодируем сообщение в байты и отправляем на сервер
                s.sendall(message_to_send.encode('utf-8'))

                # Получаем ответ от сервера (до 1024 байт)
                data = s.recv(1024)
                print(f"Получено от сервера: {data.decode('utf-8')}")

        # Если сервер не запущен или недоступен, возникнет ошибка ConnectionRefusedError
        except ConnectionRefusedError:
            print(f"Не удалось подключиться к серверу {HOST}:{PORT}. Убедитесь, что сервер запущен.")
        # Ловим возможные ошибки
        except Exception as e:
            print(f"Произошла ошибка: {e}")
        finally:
            # Этот блок выполнится всегда, даже если были ошибки
            print("Соединение с сервером закрыто (или не было установлено).")


if __name__ == "__main__":
    start_client()