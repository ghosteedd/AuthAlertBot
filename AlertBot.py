#! /usr/bin/env python
# -*- coding: utf-8 -*-

from string import ascii_lowercase
from random import choice
from time import sleep
import configparser
import subprocess
import threading
import datetime
import argparse
import logging
import logging.handlers
import json
import sys
import os
import re

try:
    import requests
except ModuleNotFoundError:
    print('Module requests not found!')
    sys.exit(-1)
try:
    import socket
    import socks
except ModuleNotFoundError:
    print('Module PySocks not found!')
    sys.exit(-1)


PROJECT_NAME = 'AuthAlertBot'
CONFIG_PATH = f'{PROJECT_NAME}.conf'
STICKER_FOR_UNKNOWN_CHAT = 'CAADAgADlgMAApE3IwyxsiOd7mQmMQI'
STICKER_FOR_UNKNOWN_USER = 'CAADAgADaAMAApE3Iwzn219CQCZ68AI'

# Shared variables
_syslog = False
_token = None
_chat_id = None
_prefix = None

# Variables for threads
_threads_dict = dict()
_dead_threads = list()

# Use for stop threads
_run_threads = True


def log(string):
    """
    Print or save to syslog a string. Edit (bool) _syslog for change mode
    :param string: (str) String for print/syslog
    """
    if not isinstance(string, str):
        return None
    if _syslog:
        logger = logging.getLogger(PROJECT_NAME)
        logger.setLevel(logging.INFO)
        handler = logging.handlers.SysLogHandler(address='/dev/log')
        formatter = logging.Formatter(f'{PROJECT_NAME}: %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.info(string)
    else:
        print(string)


def load_config():
    """
    Loading configuration for telegram bot
    :return: None or ('token', chat_id, 'prefix', 'syslog', 'proxy' = None or ['address', port, 'username', 'password'])
    """
    if not os.path.exists(CONFIG_PATH):
        return None
    config = configparser.ConfigParser()
    config.read(CONFIG_PATH)
    try:
        token = config.get('Settings', 'token')
        chat_id = int(config.get('Settings', 'chat_id'))
        prefix = config.get('Settings', 'prefix')
        syslog = config.get('Settings', 'syslog')
    except configparser.NoOptionError:
        return None
    except configparser.NoSectionError:
        return None
    except ValueError:
        return None
    proxy = list()
    try:
        proxy.append(config.get('Proxy', 'address'))
        proxy.append(int(config.get('Proxy', 'port')))
        proxy.append(config.get('Proxy', 'username'))
        proxy.append(config.get('Proxy', 'password'))
    except configparser.NoOptionError:
        proxy = None
    except configparser.NoSectionError:
        proxy = None
    except ValueError:
        proxy = None
    return token, chat_id, prefix, syslog, proxy


def save_config(token, chat_id, prefix, syslog, proxy):
    """
    Saving configuration for telegram bot and other
    :param token: (str) Bot token
    :param chat_id: (int) Work chat id
    :param prefix: (str) Prefix for this script
    :param syslog: (bool) Saving output to syslog
    :param proxy: (list or tuple or None) Proxy for connect to api.telegram.org
    """
    if not isinstance(token, str) or not isinstance(chat_id, int) or not isinstance(prefix, str) or \
       not isinstance(syslog, bool) or not (isinstance(proxy, list) or isinstance(proxy, tuple) or proxy is None):
        log('Error saving configuration (args) (0)')
        return None
    config = configparser.ConfigParser()
    config.add_section('Settings')
    config.set('Settings', 'token', str(token))
    config.set('Settings', 'chat_id', str(chat_id))
    config.set('Settings', 'prefix', str(prefix))
    if syslog:
        config.set('Settings', 'syslog', '1')
    else:
        config.set('Settings', 'syslog', '0')
    if proxy:
        config.add_section('Proxy')
        config.set('Proxy', 'address', str(proxy[0]))
        config.set('Proxy', 'port', str(proxy[1]))
        config.set('Proxy', 'username', str(proxy[2]))
        config.set('Proxy', 'password', str(proxy[3]))
    try:
        with open(CONFIG_PATH, "w") as config_file:
            config.write(config_file)
    except:
        log('Error saving configuration (1)')
        sys.exit(1)


def set_proxy(address, port, username, password):
    """
    Setup proxy for connect to api.telegram.org
    :param address: (str) Proxy address
    :param port: (int) Proxy port
    :param username: (str) Proxy username
    :param password: (str) Proxy password
    """
    if not isinstance(address, str) or not isinstance(port, int) or not isinstance(username, str) or \
       not isinstance(password, str):
        log('Error in setup proxy (args) (2)')
        return None
    try:
        socks.set_default_proxy(socks.SOCKS5, address, port=port, username=username, password=password)
        socket.socket = socks.socksocket
    except:
        log('Error in setup proxy (3)')


def connection_check(token=None):
    """
    Check connect to api.telegram.org
    :param token: (optional) (str) Bot token
    :return: True - connection success. False - connection fail
    """
    if token is not None and not isinstance(token, str):
        log('Error checking connect to api.telegram.org (args) (4)')
        return False
    try:
        if token:
            r = requests.get(f'https://api.telegram.org/bot{token}/getMe').json()
            if r.get('ok', False):
                return True
            else:
                return False
        else:
            r = requests.get('https://api.telegram.org/bot/getMe').json()
            if r.get('ok', 1) == 1:
                return False
            else:
                return True
    except requests.exceptions.ConnectionError:
        return False
    except json.decoder.JSONDecodeError:
        return False


def start_check(check_sudo=True):
    """
    Checking python version, platform and (optional) sudo rights
    :param check_sudo: (optional) (bool) check sudo rights
    """
    # Check python version
    if sys.version_info < (3, 6):
        log('Your python version < 3.6. Please install python 3.6 or later')
        exit(-1)
    # Check platform
    if sys.platform != 'linux':
        log('Your platform not supported')
        sys.exit(-1)
    # Check sudo
    if check_sudo and os.getuid() != 0:
        log('You don\'t have sudo rights')
        exit(-1)


def setup_dialog():
    """
    Setup dialog for get settings
    """

    def get_proxy():
        print('Use proxy for connect to api.telegram.org? (Y/n)')
        while True:
            answer = input()
            if answer.lower() == 'n':
                return None
            elif answer.lower() == 'y':
                break
            else:
                print('Error in your answer. Please retype again')
        print('Warning! We use SOCKS5 only')
        print('Hint: you can use TOR for connect to api.telegram.org')
        print('Standard address for TOR proxy: 127.0.0.1, port: 9050')
        print('Enter address or ip')
        while True:
            address = input()
            if address == '':
                print('Error in proxy address. Please retype again')
            else:
                break
        print('Enter SOCKS5 port')
        while True:
            port = input()
            if port == '':
                print('Error in proxy port. Please retype again')
            else:
                try:
                    port = int(port)
                    if port < 1:
                        print('Error in proxy port. Please retype again')
                    else:
                        break
                except ValueError:
                    print('Error in proxy port. Please retype again')
        print('Enter username (use \'enter\' for skip)')
        username = input()
        password = ''
        if username:
            print('Enter password (use \'enter\' for skip)')
            password = input()
        socks.set_default_proxy(socks.SOCKS5, address, port=port, username=username, password=password)
        socket.socket = socks.socksocket
        print('Checking connection to api.telegram.org')
        if not connection_check():
            print('Error in connection to api.telegram.org (5)')
            exit(2)
        else:
            print('Connection success')
        return address, port, username, password

    def get_token():
        print('Enter your bot token:')
        while True:
            bot_token = input()
            url = f'https://api.telegram.org/bot{bot_token}/getMe'
            try:
                data = requests.get(url).json()
            except requests.exceptions.ConnectionError:
                print('Error in connection to api.telegram.org (6)')
                return None
            if data.get('ok'):
                break
            else:
                print('Error in bot token. Please retype token')
        return bot_token

    def get_chat_id(bot_token):
        access_message = ''.join(choice(ascii_lowercase) for _ in range(5))
        print('Please send next message to bot from your telegram account')
        print(f'message: {access_message}')
        while True:
            url = f'https://api.telegram.org/bot{bot_token}/getUpdates'
            try:
                data = requests.get(url).json()
            except requests.exceptions.ConnectionError:
                print('Error in connection to api.telegram.org (7)')
                sleep(5)
                continue
            except json.decoder.JSONDecodeError:
                print('Error in connection to api.telegram.org (8)')
                continue
            if not data.get('ok'):
                sleep(5)
                continue
            for update in data.get('result', list()):
                update_id = update.get('update_id', -1) + 1
                message = update.get('message', {}).get('text', '')
                chat_id = int(update.get('message', {}).get('chat', {}).get('id', 0))
                try:
                    requests.post(url, data={'offset': update_id})
                except requests.exceptions.ConnectionError:
                    print('Error in connection to api.telegram.org (9)')
                except json.decoder.JSONDecodeError:
                    print('Error in connection to api.telegram.org (10)')
                if message.lower() == access_message:
                    url = f'https://api.telegram.org/bot{bot_token}/sendMessage'
                    try:
                        requests.post(url, data={'text': f'✅ Thanks.\nYour chat id: {chat_id}', 'chat_id': chat_id})
                    except requests.exceptions.ConnectionError:
                        print('Error in connection to api.telegram.org (11)')
                    except json.decoder.JSONDecodeError:
                        print('Error in connection to api.telegram.org (12)')
                    print(f'Ok. Your chat id: {chat_id}')
                    return chat_id
            sleep(2)

    def select_log_output():
        print('Use syslog for save script log (Y/n)')
        while True:
            answer = input()
            if answer.lower() == 'y':
                return True
            elif answer.lower() == 'n':
                return False
            else:
                print('Error in your answer. Please retype again')

    def get_prefix():
        print('Enter message prefix (click \'enter\' for skip )')
        while True:
            answer = input()
            if answer == '':
                return answer
            if ' ' in answer or '/' in answer:
                print('Please don\'t use / and \' \' in prefix\n Retype prefix again')
            else:
                return answer

    start_check()
    print(f'Welcome to {PROJECT_NAME}!')
    proxy = get_proxy()
    token = get_token()
    if not token:
        return None
    target_chat_id = get_chat_id(token)
    prefix = get_prefix()
    syslog = select_log_output()
    save_config(token, target_chat_id, prefix, syslog, proxy)
    print('Good. Please restart script from sudo user or launch as daemon')
    sleep(2)


def send_message(message, reply_to_id=0, buttons=None):
    """
    Sending message by telegram bot
    :param message: (str) Message for chat
    :param reply_to_id: (optional) (int) If the message is a reply, ID of the original message
    :param buttons: (optional)(list of lists) Reply buttons
    Example: [['line 1_1', 'line 1_2'], ['line 2_1', {'text': 'line 2_2'}]]
    :return: (bool) True - success of sending message. False - error
    """
    if not isinstance(message, str) or not isinstance(reply_to_id, int):
        log('Error sending message (args) (13)')
        return False

    def markup():
        hide_keyboard = json.dumps({'hide_keyboard': True})
        if not buttons or not isinstance(buttons, list):
            return hide_keyboard
        for line in buttons:
            if not isinstance(line, list):
                return hide_keyboard
            for button in line:
                if not isinstance(button, str):
                    if not isinstance(button, dict):
                        return hide_keyboard
                    else:
                        if button.get('text', -1) == -1:
                            return hide_keyboard
        return json.dumps({
                            'resize_keyboard': True,
                            'keyboard': buttons
                          })

    url = f'https://api.telegram.org/bot{_token}/sendMessage'
    if _prefix:
        text = f'<b>[{_prefix}]</b>\n{message}'
    else:
        text = message
    data = \
        {
            'chat_id': _chat_id,
            'text': text,
            'parse_mode': 'html',
            'reply_to_message_id': reply_to_id,
            'reply_markup': markup()
        }
    try_num = 0
    while True:
        if try_num == 10:
            log('Break sending message (14)')
            log(f'Message: {text}')
            return False
        try:
            r = requests.post(url, data=data).json()
            if r.get('ok'):
                break
            else:
                log('Error sending message (15)')
                sleep(5)
                try_num += 1
        except requests.exceptions.ConnectionError:
            log('Error in connection to api.telegram.org (16)')
            try_num += 1
        except json.decoder.JSONDecodeError:
            print('Error in connection to api.telegram.org (17)')
            try_num += 1
    return True


def message_receiver(message, message_id, username=None, is_group=False):
    """
    Message handling
    :param message: (str) Target message
    :param message_id: (int) message_id for reply
    :param username: (optional)(str) Telegram username
    :param is_group: (optional)(bool) Target chat is group/supergroup?
    """
    if not isinstance(message, str) or not isinstance(message_id, int) or \
       not (username is None or isinstance(username, str)) or not (is_group is None or isinstance(is_group, bool)):
        log('Error in message receiver (args) (18)')
        return None
    command_args = message.split()
    global _run_threads
    if len(command_args) > 0:
        # /start
        if message.lower() == '/start':
            if username:
                send_message(f'👋 Hello, @{username}')
            else:
                send_message(f'👋 Welcome to {PROJECT_NAME}, %username%')
        # /status
        elif message.lower() == '/status':
            status = threads_status()
            if status != '':
                status = '<b>Threads status:</b>\n\n' + status
                send_message(status)
            else:
                send_message('❌ Status request error')
        # /kill_bot
        elif message.lower() == '/kill_bot':
            kill_message = ''.join(choice(ascii_lowercase) for _ in range(5))
            if send_message(f'Please send \'<code>{kill_message}</code>\' for stopping threads'):
                _run_threads = kill_message
        # /lock
        elif command_args[0].lower() == '/lock':
            if len(command_args) > 3 or len(command_args) == 1:
                send_message('❌ Error in command.\nUse \'/lock [prefix] ip\' for lock ip', message_id)
            elif len(command_args) == 2:
                if check_ip(command_args[1]):
                    if lock_ip(command_args[1]):
                        if is_group and username:
                            msg = f' by @{username}'
                        else:
                            msg = ''
                        send_message(f'✅ {command_args[1]} locked{msg}')
                    else:
                        send_message(f'❌ Error locking ip: {command_args[1]}')
                else:
                    send_message('❌ Error in command.\nCheck ip address', message_id)
            elif len(command_args) == 3:
                if command_args[1] != _prefix:
                    return None
                else:
                    if check_ip(command_args[2]):
                        if lock_ip(command_args[2]):
                            if is_group and username:
                                msg = f' by @{username}'
                            else:
                                msg = ''
                            send_message(f'✅ {command_args[2]} locked{msg}')
                        else:
                            send_message(f'❌ Error locking ip: {command_args[2]}')
                    else:
                        send_message('❌ Error in command.\nCheck ip address', message_id)
        # /unlock
        elif command_args[0].lower() == '/unlock':
            if len(command_args) > 3 or len(command_args) == 1:
                send_message('❌ Error in command.\nUse \'/unlock [prefix] ip\' for unlock ip', message_id)
            elif len(command_args) == 2:
                if check_ip(command_args[1]):
                    if unlock_ip(command_args[1]):
                        if is_group and username:
                            msg = f' by @{username}'
                        else:
                            msg = ''
                        send_message(f'✅ {command_args[1]} unlocked{msg}')
                    else:
                        send_message(f'❌ Error unlocking ip: {command_args[1]}')
                else:
                    send_message('❌ Error in command.\nCheck ip address', message_id)
            elif len(command_args) == 3:
                if command_args[1] != _prefix:
                    return None
                else:
                    if check_ip(command_args[2]):
                        if unlock_ip(command_args[2]):
                            if is_group and username:
                                msg = f' by @{username}'
                            else:
                                msg = ''
                            send_message(f'✅ {command_args[2]} unlocked{msg}')
                        else:
                            send_message(f'❌ Error unlocking ip: {command_args[2]}')
                    else:
                        send_message('❌ Error in command.\nCheck ip address')
        else:
            if message.lower() == _run_threads:
                send_message('✅ Stopping threads')
                _run_threads = False
            elif not is_group:
                send_message('❌️ Unknown command', message_id)


def bot_polling(interval=5):
    """
    Polling the Telegram servers for new messages
    :param interval: (optional) (int) The interval between polling requests
    """
    if not isinstance(interval, int):
        log('Error in interval bot polling (args) (19)')
        return None
    url = f'https://api.telegram.org/bot{_token}/getUpdates'
    while True:
        if not _run_threads:
            exit()
        try:
            data = requests.get(url).json()
        except requests.exceptions.ConnectionError:
            log('Error in connection to api.telegram.org (20)')
            sleep(interval)
            continue
        except json.decoder.JSONDecodeError:
            log('Error in connection to api.telegram.org (21)')
            sleep(interval)
            continue
        if not data.get('ok'):
            sleep(interval)
            continue
        for update in data.get('result', list()):
            update_id = int(update.get('update_id', -1))
            message = update.get('message', {}).get('text', '')
            message_id = int(update.get('message', {}).get('message_id', -1))
            username = update.get('message', {}).get('from', {}).get('username', '')
            chat_id = int(update.get('message', {}).get('chat', {}).get('id', -1))
            chat_type = update.get('message', {}).get('chat', {}).get('type', '')
            try:
                requests.post(url, data={'offset': update_id + 1})
            except requests.exceptions.ConnectionError:
                log('Error in connection to api.telegram.org (22)')
                sleep(interval)
                continue
            except json.decoder.JSONDecodeError:
                log('Error in connection to api.telegram.org (23)')
                sleep(interval)
                continue
            if message == '':
                continue
            if _chat_id != chat_id:
                if not (chat_type == 'group' or chat_type == 'supergroup'):
                    tmp_url = f'https://api.telegram.org/bot{_token}/sendSticker'
                    try:
                        requests.post(tmp_url, data={'chat_id': chat_id, 'sticker': STICKER_FOR_UNKNOWN_USER})
                        log(f'User @{username} send \'{message}\' to bot')
                    except requests.exceptions.ConnectionError:
                        log('Error sending answer to unknown user (24)')
                    except json.decoder.JSONDecodeError:
                        log('Error sending answer to unknown user (25)')
                    continue
                else:
                    log(f'User @{username} send \'{message}\' to chat with bot')
                    msg_url = f'https://api.telegram.org/bot{_token}/sendSticker'
                    leave_url = f'https://api.telegram.org/bot{_token}/leaveChat'
                    try:
                        requests.post(msg_url, data={'chat_id': chat_id, 'sticker': STICKER_FOR_UNKNOWN_CHAT})
                        requests.post(leave_url, data={'chat_id': chat_id})
                    except requests.exceptions.ConnectionError:
                        log('Error leaving from unknown chat (26)')
                    except json.decoder.JSONDecodeError:
                        log('Error leaving from unknown chat (27)')
                    continue
            if chat_type == 'group' or chat_type == 'supergroup':
                is_group = True
            else:
                is_group = False
            message_receiver(message, message_id, username, is_group)
        sleep(interval)


def check_ip(potential_ip):
    """
    :param potential_ip: (str) IP
    :return: True - potential_ip is IP, False - potential_ip is not IP
    """
    if not isinstance(potential_ip, str):
        return False
    ip_reg_ex = r'^\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}$'
    if re.search(ip_reg_ex, potential_ip):
        parts_ip = re.findall(r'\d{1,3}', potential_ip)
        for part_ip in parts_ip:
            if int(part_ip) > 255 or int(part_ip) < 0:
                return False
        return True
    else:
        return False


def check_ip_in_iptables(ip):
    """
    Check the number of locks
    :param ip: (str) IP address
    :return: (int) Number of locks. None if error
    """
    if not isinstance(ip, str):
        log('Error locking ip (args) (28)')
        return None
    try:
        process = subprocess.Popen(['iptables', '-S'], stdout=subprocess.PIPE)
        data = process.communicate()
        # May be sudo error?
        if not data[0]:
            return None
        data = data[0].decode()
        data_list = data.split('\n')
        lock_rules = 0
        for line in data_list:
            if ip in line and 'DROP' in line:
                lock_rules += 1
        return lock_rules
    except:
        log('Error checking IP (29)')
        return None


def lock_ip(ip):
    """
    Lock IP address with iptables
    :param ip: (str) IP address
    :return: (bool) True - success lock. False - fail
    """
    if not isinstance(ip, str):
        log('Error locking ip (args) (30)')
        return False
    try:
        subprocess.call(['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'], stdout=subprocess.PIPE)
        if check_ip_in_iptables(ip):
            return True
        else:
            return False
    except Exception as e:
        log('Error locking IP (31)')
        send_message('⚠️ Error:\n' + str(e))
        return False


def unlock_ip(ip):
    """
    Unlock IP address with iptables
    :param ip: (bool) True - success unlock. False - fail
    :return:
    """
    if not isinstance(ip, str):
        log('Error unlocking ip (args) (32)')
        return False
    try:
        num_lock_rules = check_ip_in_iptables(ip)
        if num_lock_rules is None:
            return False
        for _ in range(num_lock_rules):
            subprocess.call(['iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'], stdout=subprocess.PIPE)
        num_lock_rules = check_ip_in_iptables(ip)
        if num_lock_rules == 0:
            return True
        else:
            return False
    except Exception as e:
        log('Error unlocking IP (33)')
        send_message('⚠️ Error:\n' + str(e))
        return False


def check_auth_log():
    """
    Checking auth.log for new login
    :return: {'Date', 'Username', 'IP'}. None if not exists new logins
    """

    def convert_date_str_to_datetime(string_date):
        """
        Convert syslog/auth.log date to datatime object
        :param string_date: (str) Date from syslog/auth.log
        :return: (datetime) Datetime object or None if error
        """
        if not isinstance(string_date, str):
            return None
        try:
            result = datetime.datetime.strptime(string_date, "%b %d %H:%M:%S")
            if result.now().month >= result.month:
                result = result.replace(year=result.now().year)
            else:
                result = result.replace(year=result.now().year - 1)
        except ValueError:
            return None
        return result

    def load_last_date():
        """
        Loading last login date from configuration file
        :return: (datetime) Last notified login
        """
        if not os.path.exists(CONFIG_PATH):
            save_last_date(datetime.datetime.now())
            return datetime.datetime.now()
        config = configparser.ConfigParser()
        config.read(CONFIG_PATH)
        try:
            date = config.get('AuthLog', 'date')
            if date:
                return convert_date_str_to_datetime(date)
            else:
                save_last_date(datetime.datetime.now())
                return datetime.datetime.now()
        except configparser.NoOptionError:
            save_last_date(datetime.datetime.now())
            return datetime.datetime.now()
        except configparser.NoSectionError:
            save_last_date(datetime.datetime.now())
            return datetime.datetime.now()
        except ValueError:
            save_last_date(datetime.datetime.now())
            return datetime.datetime.now()

    def save_last_date(date):
        """
        Save last notified login date to configuration file
        :param date: (datetime) Target date for save
        """
        if not isinstance(date, datetime.datetime):
            return None
        str_date = datetime.datetime.strftime(date, "%b %d %H:%M:%S")
        config = configparser.ConfigParser()
        config.read(CONFIG_PATH)
        try:
            config.add_section('AuthLog')
        except configparser.DuplicateSectionError:
            pass
        config.set('AuthLog', 'date', str_date)
        try:
            with open(CONFIG_PATH, "w") as date_file:
                config.write(date_file)
        except FileNotFoundError:
            log('Error saving configuration (34)')
        except PermissionError:
            log('Error saving configuration (35)')

    auth_log_path = '/var/log/auth.log'
    reg_exp = re.compile(r'(?P<Date>\S{3}\s+\d{1,2}\s+\d{1,2}:\d{2}:\d{2})\s+[^/ ]+\s+sshd\s*\[\d+\]:\s+Accepted\s+'
                         r'password\s+for\s+(?P<Username>[^/ ]+)\s+from\s+(?P<IP>\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})')
    login_list = list()
    try:
        with open(auth_log_path, 'r') as auth_log:
            line = auth_log.readline()
            while line:
                search = reg_exp.search(line)
                if search:
                    login_list.append(search.groupdict())
                line = auth_log.readline()
    except FileNotFoundError:
        log('Error saving configuration (36)')
    except PermissionError:
        log('Error saving configuration (37)')
    if not len(login_list):
        return None
    last_date = load_last_date()
    for auth in login_list:
        auth_date = convert_date_str_to_datetime(auth.get('Date', 0))
        if last_date < auth_date:
            save_last_date(auth_date)
            return auth
    return None


def auth_polling(interval=10):
    """
    Polling auth.log for new login into your system
    :param interval: (optional) (int) The interval between read auth.log
    """
    if not isinstance(interval, int):
        log('Error in interval auth polling (args) (38)')
        return None
    while True:
        if not _run_threads:
            exit()
        connect_info = check_auth_log()
        if connect_info:
            message = '<b>WARNING! Detected new login!</b>\n\n'
            for k, v in connect_info.items():
                message += f'<b>{k}</b>: {v}\n'
            if connect_info.get('IP', -1) != -1:
                if _prefix != '':
                    button = '/lock {} {}'.format(_prefix, connect_info.get('IP'))
                else:
                    button = '/lock {}'.format(connect_info.get('IP'))
            else:
                button = None
            send_message(message, buttons=[[button]])
        sleep(interval)


def init_thread(func, thread_args=None):
    """
    Initialization thread
    :param func: Target function for thread
    :param thread_args: (optional) (list or tuple) Arguments for function in thread
    :return: (bool) Thread alive status
    """
    global _threads_dict
    thread_args = thread_args or list()
    try:
        func_name = func.__name__
    except AttributeError:
        log('Error initialization thread (args) (39)')
        return False
    if not isinstance(thread_args, list) and isinstance(thread_args, tuple):
        log('Error initialization thread (args) (40)')
        return False
    thread = threading.Thread(target=func, args=thread_args)
    _threads_dict[func_name] = thread
    thread.daemon = True
    thread.start()
    return thread.is_alive()


def threads_status():
    """
    Request status of threads
    :return: (str) Threads status. '' - No threads or error
    """
    result = ''
    for name, thread in _threads_dict.items():
        if not isinstance(thread, threading.Thread):
            continue
        if thread.is_alive():
            result += '<b>' + name + '</b>' + ': ✅ Alive\n'
        else:
            result += '<b>' + name + '</b>' + ': 🚫 Dead\n'

    return result


def threads_wait():
    """
    Waiting end of threads (sending notification if thread is dead) and exit
    """
    global _threads_dict
    global _dead_threads
    while True:
        for name, thread in _threads_dict.items():
            if not thread.is_alive() and name not in _dead_threads:
                send_message(f'❌ Thread <b>{name}</b> is dead')
                log(f'Thread {name} is dead (41)')
                _dead_threads.append(name)
        if len(_threads_dict) == len(_dead_threads):
            send_message('❌ <b>Main</b> thread is dead')
            log('All threads is dead')
            exit()
        sleep(15)


def main():
    global _token
    global _chat_id
    global _prefix
    global _syslog

    start_check()
    settings = load_config()
    if not settings:
        print('Error in loading config (42)')
        return None

    if settings[3] == '1':
        _syslog = True
    else:
        _syslog = False

    if settings[4]:
        set_proxy(*settings[4])

    if not connection_check(settings[0]):
        log('Error in connection to api.telegram.org (43)')
        exit(43)

    _token = settings[0]
    _chat_id = settings[1]
    _prefix = settings[2]

    init_thread(bot_polling)
    init_thread(auth_polling)

    send_message(f'🏁 {PROJECT_NAME} started!')

    threads_wait()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-setup', action='store_const', const=True, default=False, help='Enter to setup menu and exit')
    args = parser.parse_args()
    try:
        if args.setup or not os.path.exists(CONFIG_PATH):
            setup_dialog()
        else:
            main()
    except KeyboardInterrupt:
        exit()
