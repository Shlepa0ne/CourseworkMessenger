import tkinter as tk
from tkinter import scrolledtext, messagebox
import socket
import threading
import queue  # Для потокобезопасной передачи сообщений в GUI

HOST = '127.0.0.1'  # Адрес сервера
PORT = 65432  # Порт сервера


class ChatClientGUI:
    def __init__(self, master_window):
        self.master = master_window
        master_window.title("Мессенджер")
        master_window.geometry("400x500")  # Устанавливаем начальный размер окна

        self.sock = None  # Объект сокета
        self.receive_thread = None  # Поток для получения сообщений
        self.message_queue = queue.Queue()  # Очередь для сообщений от потока к GUI

        # Текстовая область для отображения чата
        self.chat_area = scrolledtext.ScrolledText(master_window, wrap=tk.WORD, state='disabled', relief=tk.SUNKEN,
                                                   borderwidth=1)
        self.chat_area.pack(padx=10, pady=(10, 5), fill=tk.BOTH, expand=True)

        # Фрейм для поля ввода и кнопки, чтобы они были на одной линии
        input_frame = tk.Frame(master_window)
        input_frame.pack(padx=10, pady=(0, 10), fill=tk.X)

        # Поле для ввода сообщения
        self.msg_entry = tk.Entry(input_frame, relief=tk.SUNKEN, borderwidth=1)
        self.msg_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=2)  # ipady для небольшой высоты поля
        self.msg_entry.bind("<Return>", self.send_message_event)  # Отправка по нажатию Enter

        # Кнопка для отправки сообщения
        self.send_button = tk.Button(input_frame, text="Отправить", command=self.send_message_event, relief=tk.RAISED,
                                     borderwidth=1)
        self.send_button.pack(side=tk.RIGHT, padx=(5, 0))

        # Обработчик закрытия окна
        master_window.protocol("WM_DELETE_WINDOW", self.on_window_close)

        # Попытка подключения к серверу при запуске
        self.connect_to_server()

        # Запуск периодической проверки очереди сообщений для обновления GUI
        self.master.after(100, self.process_message_queue_from_thread)

    def process_message_queue_from_thread(self):
        """
        Обрабатывает сообщения из очереди в главном потоке GUI.
        Вызывается периодически через master.after().
        """
        try:
            # Обрабатываем все накопившиеся сообщения в очереди
            while True:
                message = self.message_queue.get_nowait()  # Неблокирующее чтение из очереди
                self._display_message_in_gui(message)
        except queue.Empty:
            pass  # Очередь пуста, это нормально
        finally:
            # Планируем следующий вызов этой функции
            self.master.after(100, self.process_message_queue_from_thread)

    def _display_message_in_gui(self, message_text):
        """
        Отображает одно сообщение в текстовой области чата.
        Этот метод должен вызываться только из главного потока GUI.
        """
        self.chat_area.configure(state='normal')  # Включаем редактирование для вставки
        self.chat_area.insert(tk.END, message_text + '\n')
        self.chat_area.configure(state='disabled')  # Выключаем редактирование
        self.chat_area.yview(tk.END)  # Автопрокрутка к последнему сообщению

    def _add_message_to_display_queue(self, message_text):
        """
        Добавляет сообщение в очередь для последующего отображения в GUI.
        Этот метод потокобезопасен и может вызываться из любого потока.
        """
        self.message_queue.put(message_text)

    def connect_to_server(self):
        """
        Устанавливает соединение с сервером и запускает поток для получения сообщений.
        """
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((HOST, PORT))
            self._add_message_to_display_queue(f"Подключен к серверу {HOST}:{PORT}")

            # Создаем и запускаем отдельный поток для получения сообщений от сервера
            self.receive_thread = threading.Thread(target=self._receive_messages_from_server_loop, daemon=True)
            # daemon=True означает, что поток автоматически завершится при выходе из основной программы
            self.receive_thread.start()

        except ConnectionRefusedError:
            messagebox.showerror("Ошибка подключения",
                                 f"Не удалось подключиться к серверу {HOST}:{PORT}. Убедитесь, что сервер запущен.")
            self.master.destroy()  # Закрываем окно, если подключение не удалось
        except Exception as e:
            messagebox.showerror("Ошибка подключения", f"Произошла неизвестная ошибка при подключении: {e}")
            self.master.destroy()

    def _receive_messages_from_server_loop(self):
        """
        Цикл, выполняющийся в отдельном потоке, для получения сообщений от сервера.
        """
        while True:
            try:
                data = self.sock.recv(1024)  # Блокирующая операция чтения из сокета
                if not data:
                    # Если данных нет, сервер закрыл соединение или соединение потеряно
                    self._add_message_to_display_queue("Соединение с сервером потеряно.")
                    if self.sock:
                        self.sock.close()  # Закрываем сокет на стороне клиента
                    break  # Выходим из цикла потока

                message = data.decode('utf-8')
                self._add_message_to_display_queue(message)  # Добавляем полученное сообщение в очередь для GUI

            except ConnectionResetError:
                self._add_message_to_display_queue("Соединение сброшено сервером.")
                if self.sock:
                    self.sock.close()
                break
            except OSError:
                # Может возникнуть, если сокет закрывается во время recv (например, при выходе)
                break
            except Exception as e:
                self._add_message_to_display_queue(f"Ошибка получения сообщения: {e}")
                if self.sock:
                    self.sock.close()
                break

    def send_message_event(self, event=None):  # event=None позволяет вызывать метод и по кнопке
        """
        Отправляет сообщение, введенное пользователем, на сервер.
        """
        message_text = self.msg_entry.get()
        if message_text and self.sock:  # Проверяем, что есть текст и есть активное соединение
            try:
                self.sock.sendall(message_text.encode('utf-8'))
                self.msg_entry.delete(0, tk.END)  # Очищаем поле ввода после отправки
            except Exception as e:
                self._add_message_to_display_queue(f"Ошибка отправки: {e}")
                messagebox.showerror("Ошибка отправки", f"Не удалось отправить сообщение: {e}")
        elif not self.sock:
            messagebox.showwarning("Нет подключения", "Отсутствует соединение с сервером.")

    def on_window_close(self):
        """
        Обработчик события закрытия окна приложения.
        Корректно закрывает сокет и уничтожает окно.
        """
        if self.sock:
            try:
                # Попытка корректно уведомить сервер о закрытии с нашей стороны
                # Хотя сервер и так определит разрыв при следующей попытке записи/чтения
                self.sock.shutdown(socket.SHUT_RDWR)
                self.sock.close()
            except OSError:
                # Может возникнуть, если сокет уже был закрыт или недоступен
                pass
            except Exception as e:
                print(f"Ошибка при закрытии сокета: {e}")

        self.master.destroy()  # Уничтожаем главное окно Tkinter


if __name__ == "__main__":
    main_window = tk.Tk()  # Создаем главное окно приложения
    chat_app = ChatClientGUI(main_window)  # Создаем экземпляр нашего чат-клиента
    main_window.mainloop()  # Запускаем главный цикл событий Tkinter