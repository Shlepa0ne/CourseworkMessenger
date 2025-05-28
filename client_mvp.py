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