import tkinter as tk
from tkinter import scrolledtext, messagebox, simpledialog
import socket
import threading
import queue
import json
import time

HOST = '127.0.0.1'
PORT = 65432


class ChatClientGUI:
    def __init__(self, master_window):
        self.master = master_window
        master_window.title("Мессенджер")
        master_window.geometry("500x600")

        self.sock = None
        self.receive_thread = None  # Поток для получения сообщений
        self.message_queue = queue.Queue()  # Очередь для сообщений от сервера в GUI
        self.response_queue = queue.Queue()  # Для ответов на запросы login/register/logout в GUI
        self.username = None
        self.is_authenticated = False
        self.is_connecting_lock = threading.Lock()  # Блокировка для синхронизации доступа к self.sock и self.is_connecting_flag
        self.is_connecting_flag = False  # Флаг, указывающий, что процесс подключения уже идет
        self.is_request_in_progress = False  # Флаг для блокировки кнопок auth во время запроса

        # --- Виджеты ---
        self.top_frame = tk.Frame(master_window)
        self.top_frame.pack(pady=10, fill=tk.X, padx=10)

        self.auth_buttons_frame = tk.Frame(self.top_frame)
        self.auth_buttons_frame.pack(side=tk.LEFT)

        self.register_button = tk.Button(self.auth_buttons_frame, text="Регистрация", command=self.prompt_register)
        self.register_button.pack(side=tk.LEFT, padx=5)
        self.login_button = tk.Button(self.auth_buttons_frame, text="Вход", command=self.prompt_login)
        self.login_button.pack(side=tk.LEFT, padx=5)
        self.logout_button = tk.Button(self.auth_buttons_frame, text="Выход", command=self.prompt_logout,
                                       state=tk.DISABLED)
        self.logout_button.pack(side=tk.LEFT, padx=5)

        self.status_label = tk.Label(self.top_frame, text="Статус: Не подключен")
        self.status_label.pack(side=tk.RIGHT, padx=10)

        self.chat_main_frame = tk.Frame(master_window)

        self.chat_area = scrolledtext.ScrolledText(self.chat_main_frame, wrap=tk.WORD, state='disabled',
                                                   relief=tk.SUNKEN, borderwidth=1)
        self.chat_area.pack(padx=0, pady=(0, 5), fill=tk.BOTH, expand=True)

        input_frame = tk.Frame(self.chat_main_frame)
        input_frame.pack(fill=tk.X, padx=0, pady=0)

        self.msg_entry = tk.Entry(input_frame, relief=tk.SUNKEN, borderwidth=1)
        self.msg_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=2)
        self.msg_entry.bind("<Return>", self.send_message_event_gui)

        self.send_button = tk.Button(input_frame, text="Отправить", command=self.send_message_event_gui,
                                     relief=tk.RAISED, borderwidth=1)
        self.send_button.pack(side=tk.RIGHT, padx=(5, 0))

        master_window.protocol("WM_DELETE_WINDOW", self.on_window_close)

        self.master.after(100, self.process_message_queue_from_thread)
        self.master.after(100, self.process_response_queue_from_thread)
        self._update_ui_for_auth_state()

    def _update_ui_for_auth_state(self):
        if self.is_authenticated:
            if not self.chat_main_frame.winfo_ismapped():
                self.chat_main_frame.pack(padx=10, pady=(0, 10), fill=tk.BOTH, expand=True)
            self.master.title(f"Мессенджер - {self.username}")
            self.status_label.config(text=f"Пользователь: {self.username}")
            self.register_button.config(state=tk.DISABLED)
            self.login_button.config(state=tk.DISABLED)
            self.logout_button.config(state=tk.NORMAL)
            self.msg_entry.config(state=tk.NORMAL)
            self.send_button.config(state=tk.NORMAL)
        else:
            if self.chat_main_frame.winfo_ismapped():
                self.chat_main_frame.pack_forget()
            self.master.title("Мессенджер (Аутентификация)")
            self.status_label.config(text="Статус: Требуется вход/регистрация")
            self.register_button.config(state=tk.NORMAL if not self.is_request_in_progress else tk.DISABLED)
            self.login_button.config(state=tk.NORMAL if not self.is_request_in_progress else tk.DISABLED)
            self.logout_button.config(state=tk.DISABLED)
            self.msg_entry.config(state=tk.DISABLED)
            self.send_button.config(state=tk.DISABLED)
            self.chat_area.configure(state='normal')
            self.chat_area.delete('1.0', tk.END)
            self.chat_area.configure(state='disabled')

    def _set_auth_request_in_progress(self, in_progress):
        self.is_request_in_progress = in_progress
        if not self.is_authenticated:
            self.register_button.config(state=tk.DISABLED if in_progress else tk.NORMAL)
            self.login_button.config(state=tk.DISABLED if in_progress else tk.NORMAL)

    def _ensure_connection(self):
        with self.is_connecting_lock:
            if self.is_connecting_flag:
                print("DEBUG: _ensure_connection: Другой поток уже подключается, ожидание...")
                lock_acquired = self.is_connecting_lock.acquire(timeout=5.0)
                if lock_acquired:
                    self.is_connecting_lock.release()
                else:
                    print("DEBUG: _ensure_connection: Таймаут ожидания снятия флага is_connecting_flag.")
                    return None

                if self.sock and self.sock.fileno() != -1:
                    return self.sock
                else:
                    return None

            if self.sock and self.sock.fileno() != -1:
                return self.sock

            self.is_connecting_flag = True

        local_sock = None
        try:
            print("DEBUG: _ensure_connection: Попытка нового подключения...")
            self._add_message_to_display_queue("Подключение к серверу...")
            local_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            local_sock.settimeout(10.0)
            local_sock.connect((HOST, PORT))

            with self.is_connecting_lock:
                self.sock = local_sock
            self._add_message_to_display_queue(f"Подключен к серверу {HOST}:{PORT}")


            with self.is_connecting_lock:
                self.is_connecting_flag = False
            return self.sock
        except (socket.timeout, ConnectionRefusedError) as e:
            self._add_message_to_display_queue(f"Ошибка подключения: {e}")
            if local_sock: local_sock.close()
            with self.is_connecting_lock:
                self.sock = None; self.is_connecting_flag = False
            return None
        except Exception as e_conn:
            self._add_message_to_display_queue(f"Неизвестная ошибка при подключении: {e_conn}")
            if local_sock: local_sock.close()
            with self.is_connecting_lock:
                self.sock = None; self.is_connecting_flag = False
            return None

    def _send_json_request_threaded(self, request_data, callback_name):
        if self.is_request_in_progress:
            messagebox.showinfo("Запрос выполняется", "Пожалуйста, подождите завершения предыдущего запроса.")
            return

        self._set_auth_request_in_progress(True)

        def threaded_task():
            active_socket = self._ensure_connection()
            response = None

            if active_socket is None or active_socket.fileno() == -1:
                response = {"type": "internal_error",
                            "message": "Не удалось установить соединение с сервером для запроса."}
            else:
                try:
                    active_socket.sendall(json.dumps(request_data).encode('utf-8') + b'\n')
                    buffer = b""
                    while True:
                        try:
                            chunk = active_socket.recv(4096)
                            if not chunk:
                                response = {"type": "error",
                                            "message": "Сервер разорвал соединение (ответ не получен)."}
                                break
                            buffer += chunk
                            if b'\n' in buffer:
                                message_bytes, buffer = buffer.split(b'\n', 1)
                                response_str = message_bytes.decode('utf-8').strip()
                                response = json.loads(response_str)
                                break
                        except socket.timeout:
                            response = {"type": "error", "message": "Таймаут ожидания ответа от сервера."}
                            break
                except (socket.error, json.JSONDecodeError, ConnectionResetError) as e:
                    response = {"type": "error", "message": f"Ошибка сети/протокола при запросе: {e}"}
                except Exception as e_gen:
                    response = {"type": "error", "message": f"Неизвестная ошибка при выполнении запроса: {e_gen}"}

            self.response_queue.put((callback_name, response))

        thread = threading.Thread(target=threaded_task, daemon=True)
        thread.start()

    def process_response_queue_from_thread(self):
        try:
            while True:
                callback_name, response_data = self.response_queue.get_nowait()

                self._set_auth_request_in_progress(False)

                if response_data is None:
                    response_data = {"type": "error", "message": "Ошибка соединения с сервером (нет ответа)."}

                if callback_name == "handle_register_response":
                    self.handle_register_response(response_data)
                elif callback_name == "handle_login_response":
                    self.handle_login_response(response_data)

                if response_data.get("type") == "error" or response_data.get("type") == "internal_error":
                    if "соединение" in response_data.get("message", "").lower() or \
                            "разорвал" in response_data.get("message", "").lower() or \
                            "timeout" in response_data.get("message", "").lower() or \
                            "socket" in response_data.get("message", "").lower():
                        print("DEBUG: Обнаружена ошибка соединения в ответе, сброс аутентификации и сокета.")
                        self.is_authenticated = False
                        with self.is_connecting_lock:
                            if self.sock and self.sock.fileno() != -1:
                                try:
                                    self.sock.close()
                                except:
                                    pass
                            self.sock = None

                self._update_ui_for_auth_state()

        except queue.Empty:
            pass
        finally:
            self.master.after(100, self.process_response_queue_from_thread)

    def prompt_register(self):
        if self.is_request_in_progress: return
        username = simpledialog.askstring("Регистрация", "Введите имя пользователя:", parent=self.master)
        if not username: return
        password = simpledialog.askstring("Регистрация", "Введите пароль:", show='*', parent=self.master)
        if not password: return
        request = {"type": "register", "username": username, "password": password}
        self._add_message_to_display_queue(f"Попытка регистрации пользователя {username}...")
        self._send_json_request_threaded(request, "handle_register_response")

    def handle_register_response(self, response):
        self._add_message_to_display_queue(f"Ответ на регистрацию: {response}")
        if response:
            if response.get("type") == "auth_success":
                messagebox.showinfo("Регистрация", response.get("message", "Успешно! Теперь войдите."))
            elif response.get("type") == "error" or response.get("type") == "internal_error":
                messagebox.showerror("Ошибка", response.get("message", "Неизвестная ошибка при регистрации."))
            else:
                messagebox.showerror("Регистрация", response.get("message", "Ошибка регистрации."))
        else:
            messagebox.showerror("Ошибка", "Нет ответа от сервера на запрос регистрации.")

    def prompt_login(self):
        if self.is_request_in_progress: return
        username_val = simpledialog.askstring("Вход", "Введите имя пользователя:", parent=self.master)
        if not username_val: return
        password_val = simpledialog.askstring("Вход", "Введите пароль:", show='*', parent=self.master)
        if not password_val: return
        request = {"type": "login", "username": username_val, "password": password_val}
        self._add_message_to_display_queue(f"Попытка входа пользователя {username_val}...")
        self._send_json_request_threaded(request, "handle_login_response")

    def handle_login_response(self, response):
        self._add_message_to_display_queue(f"Ответ на вход: {response}")
        if response:
            if response.get("type") == "auth_success":
                self.username = response.get("username")
                self.is_authenticated = True

                # Запускаем поток получения сообщений только после успешного логина
                # и если сокет существует и поток еще не запущен
                with self.is_connecting_lock:  # Нужен доступ к self.sock
                    sock_is_valid = self.sock and self.sock.fileno() != -1

                if sock_is_valid:
                    if self.receive_thread is None or not self.receive_thread.is_alive():
                        self.receive_thread = threading.Thread(target=self._receive_messages_from_server_loop,
                                                               daemon=True)
                        self.receive_thread.start()
                        print("DEBUG: Поток _receive_messages_from_server_loop ЗАПУЩЕН после успешного логина.")
                    else:
                        print("DEBUG: Поток _receive_messages_from_server_loop уже был активен.")
                else:
                    self._add_message_to_display_queue(
                        "Ошибка: Сокет не валиден после логина для запуска потока сообщений.")
                    self.is_authenticated = False  # Откатываем, если сокет внезапно невалиден

            elif response.get("type") == "error" or response.get("type") == "internal_error":
                messagebox.showerror("Ошибка", response.get("message", "Неизвестная ошибка при входе."))
                self.is_authenticated = False
            else:
                messagebox.showerror("Вход", response.get("message", "Ошибка входа."))
                self.is_authenticated = False
        else:
            messagebox.showerror("Ошибка", "Нет ответа от сервера на запрос входа.")
            self.is_authenticated = False

        # _update_ui_for_auth_state() вызывается из process_response_queue_from_thread

    def prompt_logout(self):
        if not self.is_authenticated: return

        self._add_message_to_display_queue(f"Пользователь {self.username} выходит...")
        self.is_authenticated = False  # Важно для остановки потока receive_loop

        # Ожидаем завершения потока receive_thread, если он был активен
        if self.receive_thread and self.receive_thread.is_alive():
            print("DEBUG: Logout: Ожидание завершения receive_thread...")
            self.receive_thread.join(timeout=1.0)  # Даем секунду на завершение
            if self.receive_thread.is_alive():
                print("DEBUG: Logout: receive_thread не завершился вовремя.")
            else:
                print("DEBUG: Logout: receive_thread успешно завершен.")
        self.receive_thread = None  # Сбрасываем ссылку на поток

        socket_to_close = None
        with self.is_connecting_lock:
            if self.sock and self.sock.fileno() != -1:
                socket_to_close = self.sock
                self.sock = None

        if socket_to_close:
            try:
                # Можно попытаться отправить logout сообщение серверу здесь, если протокол это поддерживает
                # socket_to_close.sendall(json.dumps({"type":"logout"}).encode('utf-8') + b'\n')
                socket_to_close.shutdown(socket.SHUT_RDWR)  # Попытка корректного закрытия
                socket_to_close.close()
                print("DEBUG: Logout: Сокет закрыт.")
            except:
                print("DEBUG: Logout: Ошибка при закрытии сокета.")
                pass

        self.username = None  # Обнуляем имя пользователя
        self._update_ui_for_auth_state()

    def process_message_queue_from_thread(self):
        try:
            while True:
                message_data = self.message_queue.get_nowait()
                if isinstance(message_data, str):
                    self._display_message_in_gui(message_data)
                elif isinstance(message_data, dict):
                    msg_type = message_data.get("type")
                    if msg_type == "new_message":
                        self._display_message_in_gui(
                            f"[{message_data.get('sender', 'Unknown')}] {message_data.get('text', '')}")
                    elif msg_type == "user_joined":
                        self._display_message_in_gui(
                            f"Пользователь {message_data.get('username', 'Кто-то')} присоединился к чату.")
                    elif msg_type == "user_left":
                        self._display_message_in_gui(
                            f"Пользователь {message_data.get('username', 'Кто-то')} покинул чат.")
                    elif msg_type == "protocol_error":  # Если сервер прислал ошибку протокола
                        self._display_message_in_gui(
                            f"[СЕРВЕР-ОШИБКА]: {message_data.get('message', 'Неизвестная ошибка протокола')}")
        except queue.Empty:
            pass
        finally:
            self.master.after(100, self.process_message_queue_from_thread)

    def _display_message_in_gui(self, message_text):
        # Показываем сообщения, если UI чата активен, или это важные системные/отладочные сообщения
        # которые нужно видеть всегда (например, при подключении или ошибках).
        # Флаг ismapped() может быть не всегда надежен, если pack_forget() только что вызван.
        # Поэтому ориентируемся также на то, какие сообщения нужно показывать.
        show_always_keywords = ["Подключен к серверу", "Попытка", "Ответ на", "Ошибка", "Вы вышли", "Статус:",
                                "СЕРВЕР-ОШИБКА"]

        if self.is_authenticated or any(keyword in message_text for keyword in show_always_keywords):
            # Убедимся, что chat_area существует, прежде чем писать в нее (на случай очень ранних сообщений)
            if hasattr(self, 'chat_area') and self.chat_area:
                self.chat_area.configure(state='normal')
                self.chat_area.insert(tk.END, message_text + '\n')
                self.chat_area.configure(state='disabled')
                self.chat_area.yview(tk.END)
            else:  # Если chat_area еще нет, выводим в консоль
                print(f"[DEBUG_QUEUE_NO_CHAT_AREA]: {message_text}")
        else:
            print(f"[DEBUG_QUEUE_NOT_AUTHED_DISPLAY]: {message_text}")

    def _add_message_to_display_queue(self, data_to_display):
        self.message_queue.put(data_to_display)

    def _receive_messages_from_server_loop(self):
        buffer = b""
        print(f"DEBUG: Поток _receive_messages_from_server_loop НАЧАЛСЯ (is_auth: {self.is_authenticated})")

        while self.is_authenticated:
            current_sock_for_recv = None
            with self.is_connecting_lock:
                if self.sock and self.sock.fileno() != -1:
                    current_sock_for_recv = self.sock

            if not current_sock_for_recv:
                if self.is_authenticated:
                    self._add_message_to_display_queue(
                        "Ошибка: Потеряно соединение (внутренняя ошибка сокета в receive_loop).")
                break

            try:
                data_chunk = current_sock_for_recv.recv(4096)
                if not data_chunk:
                    self._add_message_to_display_queue("Соединение с сервером потеряно (сервер закрыл или recv 0).")
                    break

                buffer += data_chunk
                while b'\n' in buffer:
                    message_bytes, buffer = buffer.split(b'\n', 1)
                    try:
                        message_dict = json.loads(message_bytes.decode('utf-8'))
                        self._add_message_to_display_queue(message_dict)
                    except json.JSONDecodeError:
                        print(f"Ошибка декодирования JSON от сервера: {message_bytes.decode('utf-8', errors='ignore')}")

            except socket.timeout:
                continue
            except (ConnectionResetError, BrokenPipeError, OSError) as e_sock_err:
                self._add_message_to_display_queue(f"Сетевая ошибка в потоке слушателя: {e_sock_err}")
                break
            except Exception as e_recv:
                self._add_message_to_display_queue(f"Неизвестная ошибка в потоке слушателя: {e_recv}")
                break

        print(
            f"DEBUG: Поток _receive_messages_from_server_loop ЗАВЕРШАЕТСЯ (is_auth: {self.is_authenticated}, был {self.username}).")
        self.is_authenticated = False
        with self.is_connecting_lock:
            if self.sock and self.sock.fileno() != -1:
                try:
                    self.sock.close()
                except:
                    pass
            self.sock = None

        # Вызываем обновление UI из главного потока, если это еще не было сделано через logout
        # Это на случай, если соединение просто оборвалось
        self.master.after(0, self._update_ui_for_auth_state)

    def send_message_event_gui(self, event=None):
        if not self.is_authenticated:
            messagebox.showwarning("Не аутентифицирован", "Пожалуйста, сначала войдите в систему.")
            return

        message_text = self.msg_entry.get()
        if message_text.strip():
            current_sock_for_send = None
            with self.is_connecting_lock:
                if self.sock and self.sock.fileno() != -1:
                    current_sock_for_send = self.sock

            if current_sock_for_send:
                request = {"type": "message", "text": message_text}
                try:
                    current_sock_for_send.sendall(json.dumps(request).encode('utf-8') + b'\n')
                    self.msg_entry.delete(0, tk.END)
                except (socket.error, ConnectionResetError) as e:
                    self._add_message_to_display_queue(f"Ошибка отправки (соединение потеряно?): {e}")
                    messagebox.showerror("Ошибка отправки", f"Не удалось отправить сообщение: {e}")
                    self.is_authenticated = False
                    with self.is_connecting_lock:
                        if self.sock: self.sock.close(); self.sock = None
                    self._update_ui_for_auth_state()
                except Exception as e_gen:
                    self._add_message_to_display_queue(f"Неизвестная ошибка отправки: {e_gen}")
                    messagebox.showerror("Ошибка отправки", f"Произошла неизвестная ошибка: {e_gen}")
            else:
                messagebox.showerror("Ошибка отправки", "Соединение с сервером отсутствует.")
                self.is_authenticated = False
                self._update_ui_for_auth_state()

    def on_window_close(self):
        print("DEBUG: Закрытие окна...")
        # Устанавливаем is_authenticated в False, чтобы остановить цикл в _receive_messages_from_server_loop
        self.is_authenticated = False

        # Даем немного времени потоку на естественное завершение
        if self.receive_thread and self.receive_thread.is_alive():
            print("DEBUG: on_window_close: Ожидание завершения receive_thread...")
            self.receive_thread.join(timeout=0.2)  # Короткий таймаут
            if self.receive_thread.is_alive():
                print("DEBUG: on_window_close: receive_thread не завершился вовремя.")
        self.receive_thread = None  # Сбрасываем ссылку

        socket_to_close = None
        with self.is_connecting_lock:
            if self.sock:  # Проверяем только на существование, fileno может быть уже -1
                socket_to_close = self.sock
                self.sock = None

        if socket_to_close:
            print(f"DEBUG: on_window_close: Закрываем сокет {socket_to_close}")
            try:
                # Не используем shutdown, просто закрываем
                socket_to_close.close()
            except Exception as e:
                print(f"Ошибка при явном закрытии сокета при выходе: {e}")

        self.master.destroy()


if __name__ == "__main__":
    main_window = tk.Tk()
    chat_app = ChatClientGUI(main_window)
    main_window.mainloop()