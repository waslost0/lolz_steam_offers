# -*- coding: utf-8 -*-
import datetime
import json
import os
import re
import time
from datetime import datetime

import requests
import urllib3
from bs4 import BeautifulSoup
from fake_useragent import UserAgent
from loguru import logger
from requests import RequestException
from requests.packages.urllib3.exceptions import SSLError, InsecureRequestWarning
from steampy.client import SteamClient, Asset
from steampy.utils import GameOptions
from telethon.sync import TelegramClient

# logger.add('logs.log', format="{time} {level} {message}", colorize=True)
logger.add("logs.log", backtrace=True, diagnose=True)

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
requests.packages.urllib3.disable_warnings(SSLError)
requests.packages.urllib3.disable_warnings(ConnectionResetError)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

RETRIES = 10


def load_data_from_file():
    try:
        if not os.path.exists('data.json'):
            with open('data.json', 'w', encoding="utf-8") as f:
                data = {
                    "theme_url": "https://lolz.guru/threads/id",
                    "message": "@",
                    "minimum_user_likes": 20,
                    "user_timeout_to_send_trade_offer_in_minutes": 500,
                    "user": {
                        "username": "",
                        "password": ""
                    },
                    "rucaptcha_token": "RUCAPTCHA_TOKEN",
                    "sleep_time": 30,
                    "telegram": {
                        "telegram_id": "",
                        "info_mode": "False",
                        "error_mode": "False"
                    },
                    "steam": {
                        "app_id": "753",
                        "items_count": 1,
                        "api_key": "",
                        "username": "",
                        "password": "",
                        "steam_guard": "Steamguard.txt"
                    },
                    "proxy": {
                        "account_proxy": "",
                        "proxy_type": "https"
                    }
                }
                f.write(json.dumps(data, indent=4))
            logger.info('Edit data.txt')
            exit()

        with open('data.json', 'r', encoding="utf-8") as f:
            data = json.load(f)

    except KeyError as error:
        logger.error('Cannot find: %s', error.args[0])
    else:
        return data


def get_tg_code():
    api_id = DATA_JSON['telegram']['api_id']
    api_hash = DATA_JSON['telegram']['api_hash']
    session = "session"
    with TelegramClient(session, api_id, api_hash) as client:
        client.start()
        channel_username = 'lolzteam_alert_bot'
        time.sleep(5)
        message = client.get_messages(channel_username, limit=1)[0]
        message = message.message.split('\n')
        logger.info(message)
        return message[1]


def get_current_time():
    return ':'.join(datetime.now().strftime("%H:%M:%S").split(':'))


def telegram_bot_send_text(bot_message, is_silent=False):
    bot_token = 'BOTTOKEN'
    bot_chat_id = DATA_JSON['telegram']['telegram_id']
    if is_silent:
        send_text = 'https://api.telegram.org/bot' + bot_token + '/sendMessage?chat_id=' + str(
            bot_chat_id) + '&disable_notification=true&text=' + bot_message
    else:
        send_text = 'https://api.telegram.org/bot' + bot_token + '/sendMessage?chat_id=' + str(
            bot_chat_id) + '&text=' + bot_message
    logger.info(requests.get(send_text).json())


class LolzWorker:
    """
    Lolz worker.
    """

    def __init__(self, user_data):
        """
        Constructor.
        """
        self.ua = UserAgent(verify_ssl=False)
        self.session = requests.Session()
        self.session.headers.update({'user-agent': self.ua.random})
        self.domain_name = 'lolz.guru'
        self.session.verify = False
        self.user_data = user_data
        self.theme_url = user_data['theme_url']
        if not os.path.exists('replied_users.json'):
            with open('replied_users.json', 'w', encoding="utf-8") as f:
                data = {}
                f.write(json.dumps(data, indent=4))
        if os.path.exists('replied_users.json'):
            with open('replied_users.json', 'r', encoding="utf-8") as f:
                self.replied_users = json.load(f)

        self.items_count = user_data['steam']['items_count']
        self.is_proxy = False
        self.is_telegram_info_mode = False
        self.is_telegram_debug_mode = False
        self.token = None

        if self.user_data['telegram']['telegram_id'] != '':
            self.is_telegram_info_mode = eval(self.user_data['telegram']['info_mod'])
            self.is_telegram_debug_mode = eval(self.user_data['telegram']['error_mod'])

        if self.user_data['proxy']['account_proxy'] != '':
            self.is_proxy = True
            logger.info(self.user_data["proxy"])
            self.set_proxy()
            if not self.proxy_check():
                logger.info('Proxy set error')
                if self.is_telegram_debug_mode:
                    telegram_bot_send_text('Proxy set error', is_silent=False)
                exit()

        if not os.path.isfile('cookie.txt'):
            with open('cookie.txt', 'w') as f:
                f.write('{}')
        else:
            self.cookie_load()

        self.sent_items = {}
        if os.path.exists('sent_items.json'):
            with open('sent_items.json', 'r', encoding="utf-8") as f:
                self.sent_items = json.load(f)
        else:
            with open('sent_items.json', 'w', encoding="utf-8") as f:
                data = {"sent_items": []}
                f.write(json.dumps(data, indent=4))

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.is_telegram_debug_mode:
            telegram_bot_send_text(f'{str(exc_val)}', is_silent=False)
        logger.error('exit exception text: %s' % exc_val)

    def set_proxy(self):
        proxy_type = self.user_data['proxy']['proxy_type']
        if 'http' in proxy_type:
            proxy_type = 'http'
        proxy = {
            'http': f"{proxy_type}://{self.user_data['proxy']['account_proxy']}",
            'https': f"{proxy_type}://{self.user_data['proxy']['account_proxy']}",
        }
        self.session.proxies.update(proxy)

    def proxy_check(self):
        try:
            try:
                response_no_proxy = requests.get('https://api.myip.com').json()
                response_with_proxy = self.session.get('https://api.myip.com').json()
            except RequestException as e:
                response_no_proxy = requests.get('https://api.my-ip.io/ip.json').json()
                response_with_proxy = self.session.get('https://api.my-ip.io/ip.json').json()
            logger.info(f'Your ip : {response_no_proxy}')
            logger.info(f'Ip with proxy : {response_with_proxy}')

            if response_with_proxy['ip'] == response_no_proxy['ip']:
                return False
            else:
                return True
        except (IndexError, RequestException) as error:
            logger.info(error)
            logger.info('Proxy set error!')
            if self.is_telegram_debug_mode:
                telegram_bot_send_text(f'Proxy set error!\n{error}', is_silent=False)
            exit()

    def is_login(self):
        """
        Check is user login
        :return:
        """
        try:
            response = self.session.get(f'https://lolz.guru/')
            req_bs = BeautifulSoup(response.text, 'lxml')
            logger.debug(req_bs.select_one('img[class="navTab--visitorAvatar"]'))
            if not req_bs.select_one('img[class="navTab--visitorAvatar"]'):
                return False
            return True
        except Exception as error:
            logger.error(error)

    def two_step(self) -> bool:
        provider = ["telegram", "email", "backup", "totp"]
        if self.is_telegram_info_mode or self.is_telegram_debug_mode:
            telegram_bot_send_text(f'2fa')
        if (self.user_data['telegram']['api_id'] and self.user_data['telegram']['api_hash']) != '':
            two_step = get_tg_code()
            provider_id = 1
        else:
            two_step = input("Code>")
            logger.info("Authorize methods\n1.Telegram\n2.Email\n3.Backup code\n4.Google")
            provider_id = int(input("[1-4]>"))

        logger.info(two_step)
        data_two_step = {
            'code': two_step,
            'trust': 1,
            'provider': provider[provider_id - 1],
            '_xfConfirm': 1,
            '_xfToken': '',
            'remember': 1,
            'save': 'Подтвердить',
            'redirect': f'https://{self.domain_name}/',
            '_xfNoRedirect': 1,
            '_xfResponseType': 'json'
        }
        two = self.session.post(f'https://{self.domain_name}/login/two-step', data=data_two_step).json()
        try:
            if two['_redirectStatus'] == 'ok':
                logger.info('Success')
                return self.is_login()
            else:
                logger.info('Error')
                logger.info(two)
                if self.is_telegram_debug_mode:
                    telegram_bot_send_text(str(f'Error\n{two}'))
                return False
        except Exception as error:
            if self.is_telegram_debug_mode:
                telegram_bot_send_text(f'{str(error)}')
            logger.error(error)
            return False

    def solve_captcha(self):
        try:
            send_captcha = requests.get(
                f'https://rucaptcha.com/in.php?key={self.user_data["rucaptcha_token"]}&method'
                f'=userrecaptcha&googlekey=6LdAh8YUAAAAACraj__ZkvtB6l3ZDpa0AUNgaOLj&pageurl'
                f'=https://lolz.guru/login&json=1&invisible=1')
        except (RequestException, ConnectionError):
            return None

        self.received_captcha_id = send_captcha.json()['request']
        if 'ERROR_NO_SLOT_AVAILABLE' in self.received_captcha_id:
            return None

        retries = 0
        while True:
            if retries > 20:
                return None
            time.sleep(10)
            try:
                received_captcha = requests.get(
                    "https://rucaptcha.com/res.php?key=" + self.user_data[
                        'rucaptcha_token'] + "&action=get&id=" + self.received_captcha_id + "&json=1",
                    timeout=20)
                logger.info(f'{received_captcha.json()}')
            except (RequestException, ConnectionError):
                retries += 1
                logger.info(f'[Retries: {retries}')
                continue
            if received_captcha.json()["request"] == "ERROR_CAPTCHA_UNSOLVABLE":
                return None

            if received_captcha.json()['status'] == 1:
                return received_captcha.json()['request']

    def login(self, username, password):
        """
        Login lolz
        :return:
        """
        try:
            recaptcha = self.solve_captcha()
            data = {
                'login': username,
                'password': password,
                'remember': 1,
                'g-recaptcha-response': str(recaptcha),
                'stop1fuckingbrute1337': 1,
                'cookie_check': 1,
                '_xfToken': '',
                'redirect': f'https://{self.domain_name}/'
            }

            req = self.session.post(f'https://{self.domain_name}/login/login', data=data)
            if req.url.startswith(f'https://{self.domain_name}/login/two-step'):
                return self.two_step()

            soup = BeautifulSoup(req.content, 'lxml')
            try:
                captcha = soup.select_one('div[class="loginForm--errors"]').text
                logger.info(captcha.strip())
                if 'CAPTCHA' in captcha:
                    self.session.post(
                        f'http://rucaptcha.com/res.php?key={self.user_data["rucaptcha_token"]}&action=reportbad&id={self.received_captcha_id}')
                    logger.info('reportbad')
            except Exception:
                self.session.post(
                    f'http://rucaptcha.com/res.php?key={self.user_data["rucaptcha_token"]}&action=reportgood&id={self.received_captcha_id}')
                logger.info('reportgood')

            return self.is_login()
        except RequestException as e:
            raise e

    def get_xftoken(self) -> str:
        """
        Parse page and get xfToken
        """
        try:
            response = self.session.get(f'https://{self.domain_name}/')
            token_bs = BeautifulSoup(response.content, 'lxml')
            token = token_bs.find('input', {'name': '_xfToken'})['value']
            self.token = token
        except RequestException as e:
            if self.is_telegram_debug_mode:
                telegram_bot_send_text(str(e))
            raise e
        else:
            return token

    @staticmethod
    def get_last_date(soup_content):
        try:
            last_date = soup_content.select_one('input[name="last_date"]').get('value')
            return last_date
        except Exception as e:
            raise e

    @staticmethod
    def get_last_known_date(soup_content):
        try:
            last_known_date = soup_content.select_one('input[name="last_known_date"]').get('value')
            return last_known_date
        except Exception as e:
            logger.error(e)
            return False

    @staticmethod
    def get_last_theme_page(soup_content):
        try:
            last_theme_data = soup_content.select_one('div[class="PageNav"]').get('data-last')
            return last_theme_data
        except Exception as e:
            logger.error(e)
            return None

    def cookie_load(self):
        if not os.path.isfile('cookie.txt'):
            with open('cookie.txt', 'w') as f:
                f.write('{}')
            logger.info('Edit cookie.txt')
            exit()
        with open('cookie.txt') as f:
            try:
                cookies_lines = json.load(f)
                for line in cookies_lines:
                    if 'name' in line:
                        # set session cookie if cookie name not `df_id`
                        if line['name'] != 'df_id':
                            self.session.cookies[line['name']] = line['value']

                for line in cookies_lines:
                    if ('name' or 'value' or 'hostOnly' or 'domain') in line:
                        break
                    if line != 'df_id':
                        self.session.cookies[line] = cookies_lines[line]
            except Exception as error:
                if self.is_telegram_debug_mode:
                    telegram_bot_send_text(error, is_silent=False)
                logger.error(error)

    def setup_data_to_reply(self):
        data = {
            'message_html': '',
            '_xfRelativeResolver': '',
            'last_date': '',
            'last_known_date': '',
            '_xfToken': self.token,
            '_xfRequestUri': '',
            '_xfNoRedirect': 1,
            '_xfResponseType': 'json',
        }

        try:
            response = self.session.get(f'{self.theme_url}page-999999')
            soup = BeautifulSoup(response.text, 'lxml')
            last_known_date = self.get_last_known_date(soup)
            last_date = self.get_last_date(soup)
            data['last_date'] = last_date
            data['last_known_date'] = last_known_date
            _xf_request_uri = response.url.replace('https://lolz.guru/', '')
            data['_xfRequestUri'] = _xf_request_uri
            data['message_html'] = f'<p>{self.user_data["message"]}</p>'
            data['_xfRelativeResolver'] = self.theme_url
            return data
        except Exception as error:
            logger.error(error)
            return data

    def get_username_from_token(self) -> str:
        return self.token.split(',')[0]

    @logger.catch()
    def replier(self):
        """
        Participate in contests.
        Get urls from page than open one by one.
        """
        cookies = self.session.cookies.get_dict()
        self.token = self.get_xftoken()
        with open('cookie.txt', 'w') as f:
            f.write(json.dumps(cookies))

        users_to_reply = []
        with SteamClient(
                api_key=self.user_data['steam']['api_key'],
                username=self.user_data['steam']['username'],
                password=self.user_data['steam']['password'],
                steam_guard=self.user_data['steam']['steam_guard']) as steam_client:

            sent_items = []
            if self.user_data['steam']['app_id'] == '753':
                context_id = '6'
            else:
                context_id = '2'
            game = GameOptions(app_id=self.user_data['steam']['app_id'], context_id=context_id)
            inventory = steam_client.get_my_inventory(game)
            time_sleep = self.user_data['sleep_time']
            while True:
                # get users to send trade offer
                if not users_to_reply:
                    users_to_reply = self.get_users_to_reply()
                print(self.is_login())
                # check is steam session is alive
                is_session_alive = steam_client.is_session_alive()
                logger.info(f'is_session_alive: {is_session_alive}')

                if not is_session_alive:
                    # update steam session
                    steam_client = SteamClient(api_key=self.user_data['steam']['api_key'])
                    steam_client.login(
                        username=self.user_data['steam']['username'],
                        password=self.user_data['steam']['password'],
                        steam_guard=self.user_data['steam']['steam_guard'])

                for user in users_to_reply:
                    items_to_trade_offer = []
                    if not user:
                        continue
                    if user[1] in self.replied_users:
                        if user[0] in self.replied_users[user[1]]:
                            continue
                        else:
                            user_timestamp = list(self.replied_users[user[1]].values())[-1]
                            user_date = datetime.fromtimestamp(user_timestamp)
                            now = datetime.now()
                            diff = now - user_date
                            minutes = diff.total_seconds() / 60
                            if minutes > self.user_data['user_timeout_to_send_trade_offer_in_minutes']:
                                if user[1] in self.replied_users:
                                    del self.replied_users[user[1]]
                            else:
                                time_left = self.user_data['user_timeout_to_send_trade_offer_in_minutes'] - minutes
                                data = self.setup_data_to_reply()
                                data['message_html'] = f'<p>Подождите {round(time_left)} мин.<p>'
                                try:
                                    response = self.session.post(
                                        f'https://{self.domain_name}/posts/{user[0].split("-")[1]}/comment',
                                        data=data).json()
                                except Exception as error:
                                    logger.error(error)
                                    continue
                                logger.info(data['message_html'])

                    if user[1] not in self.replied_users:
                        i = 0
                        items_to_trade_offer = self.setup_items_to_trade_offer(inventory, game)
                        logger.info(user)
                        try:
                            result = steam_client.make_offer_with_url(
                                trade_offer_url=user[2],
                                items_from_me=items_to_trade_offer,
                                items_from_them=[],
                            )
                        except Exception as error:
                            if self.is_telegram_debug_mode:
                                telegram_bot_send_text(error, is_silent=False)
                            if user[1] in self.replied_users:
                                del self.replied_users[user[1]]
                            logger.error(error)
                            continue

                        now = datetime.now()
                        data_now = datetime.timestamp(now)
                        self.replied_users[user[1]] = {}
                        self.replied_users[user[1]][user[0]] = data_now
                        logger.info(result)

                        if 'success' in result:
                            if result['success'] is True:
                                # update `replied_users.json`
                                with open('replied_users.json', 'w', encoding="utf-8") as f:
                                    f.write(json.dumps(self.replied_users, indent=4))

                                with open('sent_items.json', 'w', encoding="utf-8") as f:
                                    f.write(json.dumps(self.sent_items, indent=4))

                                if self.is_telegram_info_mode:
                                    telegram_bot_send_text(f'Трейд отправлен: {user[1]}', is_silent=False)
                                try:
                                    data = self.setup_data_to_reply()
                                    self.session.post(
                                        f'https://{self.domain_name}/posts/{user[0].split("-")[1]}/comment',
                                        data=data).json()
                                except Exception as error:
                                    logger.error(error)
                                    data = self.setup_data_to_reply()
                                    self.session.post(
                                        f'https://{self.domain_name}/posts/{user[0].split("-")[1]}/comment',
                                        data=data).json()
                                logger.info(f'Трейд отправлен: {user[1]}')
                        elif 'strError' in result:
                            data = self.setup_data_to_reply()
                            # if error, tell user that error occurred when sending trade offer
                            # delete from `send_items` last added item
                            if user[1] in self.replied_users:
                                del self.replied_users[user[1]]
                            data['message_html'] = f'<p>{result["strError"]}</p>'
                            try:
                                response = self.session.post(
                                    f'https://{self.domain_name}/posts/{user[0].split("-")[1]}/comment',
                                    data=data).json()
                            except Exception as error:
                                logger.error(error)
                            logger.info(response)
                            if self.sent_items['sent_items']:
                                for i in range(0, self.items_count + 1):
                                    self.sent_items['sent_items'].pop()
                    time.sleep(20)
                users_to_reply = []
                time.sleep(time_sleep)

    @logger.catch()
    def get_data_to_reply(self, reply):
        id_reply = reply.get('id')
        data_author = reply.get('data-author')
        if id_reply not in self.replied_users:
            link = self.parse_trade_url(str(reply))
            return [id_reply, data_author, link]

    @staticmethod
    def parse_trade_url(reply):
        try:
            result = re.search(r'\?partner=\d+&amp;token=([A-z]|[0-9]|-|_)+',
                               reply)
            if result:
                result = result.group(0).replace('amp;', '')
                result = 'https://steamcommunity.com/tradeoffer/new/' + result
                return result
            else:
                return None
        except Exception as error:
            logger.error(error)
            return None

    @logger.catch()
    def parse_users_to_reply(self, soup) -> list:
        users_to_reply = []
        for reply in soup:
            users_likes_count = reply.select_one('span[class="userCounter item muted"]').text.strip().replace(' ', '')
            if int(users_likes_count) >= self.user_data['minimum_user_likes']:
                comments = reply.select('div[class="commentContent"]')
                data_author = reply.get('data-author').strip()
                if not comments and data_author not in users_to_reply:
                    users_to_reply.append(self.get_data_to_reply(reply))
        return users_to_reply

    @logger.catch()
    def get_users_to_reply(self) -> list:
        users_to_reply = []
        # get the last page
        try:
            html_source_page = self.session.get(self.theme_url)
        except Exception as error:
            logger.error(error)
            return []
        soup = BeautifulSoup(html_source_page.content, 'lxml')
        last_page = self.get_last_theme_page(soup)
        first_page = 1
        if not last_page:
            last_page = 9999999
            first_page = 9999999

        if last_page != 9999999 and int(last_page) > 5:
            first_page = int(last_page) - 1
        html_source_page = ''

        for i in range(first_page, int(last_page) + 1):
            try:
                html_source_page = html_source_page + self.session.get(
                    f'{self.theme_url}page-' + str(i)).text
            except Exception as error:
                logger.error(error)
                return users_to_reply
            time.sleep(0.5)

        soup = BeautifulSoup(html_source_page, 'lxml')
        users_to_reply_soup = soup.select('li[class="message"]')
        # parse comments
        users_to_reply = self.parse_users_to_reply(users_to_reply_soup)
        return users_to_reply

    def setup_items_to_trade_offer(self, inventory, game):
        i = 0
        items_to_trade_offer = []
        for item in inventory.values():
            if item['tradable'] == 1 and item['name'] != 'Gems':
                if item['id'] not in self.sent_items['sent_items']:
                    if int(item['amount']) == 1:
                        self.sent_items['sent_items'].append(item['id'])
                        items_to_trade_offer.append(Asset(item['id'], game))
                        i += 1
                    elif int(item['amount']) > 1:
                        items_amount = int(item['amount'])
                        if items_amount >= (self.items_count - i):
                            items_to_trade_offer.append(
                                Asset(item['id'], game, amount=self.items_count - i))
                            i += self.items_count - i
                        else:
                            self.sent_items['sent_items'].append(item['id'])
                            items_to_trade_offer.append(Asset(item['id'], game, amount=items_amount))
                            i += items_amount
                if i == self.items_count:
                    break
        return items_to_trade_offer


if __name__ == '__main__':
    DATA_JSON = load_data_from_file()

    with LolzWorker(DATA_JSON) as lolz:
        if lolz.is_login():
            logger.info('Login successful')
            lolz.replier()
        else:
            logger.info('Login fail')
            if not lolz.login(DATA_JSON['user']['username'], DATA_JSON['user']['password']):
                logger.info("Login fail")
            else:
                logger.info('Login successful')
                lolz.replier()
