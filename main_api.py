# -*- coding: utf-8 -*-
import datetime
import json
import os
import re
import time
from datetime import datetime
from typing import Union

import requests
from loguru import logger
from requests import RequestException
from steampy.client import SteamClient, Asset
from steampy.utils import GameOptions
from telethon.sync import TelegramClient

# https://lolz.guru/api/index.php?oauth/authorize&response_type=token&client_id=CLIENT_ID&scope=read+post+usercp+conversate
logger.add("logs.log", encoding="utf8", backtrace=True, diagnose=True)

RETRIES = 10


def load_data_from_file() -> dict:
    try:
        if not os.path.exists('data.json'):
            with open('data.json', 'w', encoding="utf-8") as f:
                data = {
                    "theme_url": "https://lolz.guru/threads/id",
                    "message": "@",
                    "minimum_user_likes": 20,
                    "user_timeout_to_send_trade_offer_in_minutes": 500,
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


def get_tg_code() -> str:
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


def get_current_time() -> str:
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

    def __init__(self, user_data):
        """
        Constructor.
        """
        self.user_id = None
        self.thread_id = None
        self.username = None
        self.items_count = user_data['steam']['items_count']
        self.is_proxy = False
        self.is_telegram_info_mode = False
        self.is_telegram_debug_mode = False
        self.sent_items = {}

        self.session = requests.Session()
        self.domain_name = 'lolz.guru'
        self.user_data = user_data
        self.session.headers['Authorization'] = 'Bearer ' + self.user_data["lolz_api_key"]
        self.theme_url = user_data['theme_url']

        if not os.path.exists('sent_items.json'):
            with open('sent_items.json', 'w', encoding="utf-8") as f:
                data = {'sent_items': []}
                f.write(json.dumps(data, indent=4))
        if os.path.exists('sent_items.json'):
            with open('sent_items.json', 'r', encoding="utf-8") as f:
                self.sent_items = json.load(f)

        if os.path.exists('replied_users.json'):
            with open('replied_users.json', 'r', encoding="utf-8") as f:
                self.replied_users = json.load(f)
        if not os.path.exists('replied_users.json'):
            with open('replied_users.json', 'w', encoding="utf-8") as f:
                data = {}
                f.write(json.dumps(data, indent=4))

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
        self.session.post('https://lolz.guru/api/index.php?me')

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

    def send_trade_offer(self, steam_client: SteamClient, inventory, game: GameOptions, trade_url: str) -> dict:
        items_to_trade_offer = self.setup_items_to_trade_offer(inventory, game)
        result = {'strError': 'Error occurred'}
        try:
            result = steam_client.make_offer_with_url(
                trade_offer_url=trade_url,
                items_from_me=items_to_trade_offer,
                items_from_them=[],
            )
        except (KeyError, AttributeError) as error:
            if self.is_telegram_debug_mode:
                telegram_bot_send_text(str(error), is_silent=False)
            logger.error(error)
            return result
        logger.info(result)
        return result

    def reply_user_info(self, result: dict, user: str, users_to_reply: dict):
        if 'success' in result:
            if result['success'] is True:
                now = datetime.now()
                data_now = datetime.timestamp(now)
                self.replied_users[user]['posts'][users_to_reply[user]['post_id']] = data_now

                # update `replied_users.json`
                with open('replied_users.json', 'w', encoding="utf-8") as f:
                    f.write(json.dumps(self.replied_users, indent=4))

                with open('sent_items.json', 'w', encoding="utf-8") as f:
                    f.write(json.dumps(self.sent_items, indent=4))

                if self.is_telegram_info_mode:
                    telegram_bot_send_text(f'Трейд отправлен: {user[1]}', is_silent=False)
                data = {
                    'thread_id': self.thread_id,
                    'quote_post_id': users_to_reply[user]['post_id'],
                    'post_body': f'@{users_to_reply[user]["poster_username"]}, {self.user_data["message"]}'
                }
                response = self.session.post('https://lolz.guru/api/index.php?posts', data=data).json()
                logger.info(response)

                logger.info(f'Трейд отправлен: {users_to_reply[user]["poster_username"]}')
        elif 'strError' in result:
            if '(26)' in result['strError'] or '(15)' in result['strError']:
                telegram_bot_send_text(str(result['strError']))
                exit()
            # if error, tell user that error occurred when sending trade offer
            data = {
                'thread_id': self.thread_id,
                'quote_post_id': users_to_reply[user]['post_id'],
                'post_body': result['strError']
            }
            response = self.session.post('https://lolz.guru/api/index.php?posts',
                                         data=data).json()
            logger.info(response)
            if self.sent_items['sent_items']:
                for i in range(0, self.items_count + 1):
                    self.sent_items['sent_items'].pop()

    @logger.catch()
    def reply(self):
        """
        """
        users_to_reply = None
        self.thread_id = self.get_thread_id()
        if self.thread_id == '':
            logger.info('Wrong theme, cant\'t parse url')
        user = self.get_user_me()
        self.user_id = self.get_user_id(user)

        with SteamClient(
                api_key=self.user_data['steam']['api_key'],
                username=self.user_data['steam']['username'],
                password=self.user_data['steam']['password'],
                steam_guard=self.user_data['steam']['steam_guard']) as steam_client:

            if self.user_data['steam']['app_id'] == '753':
                context_id = '6'
            else:
                context_id = '2'
            game = GameOptions(app_id=self.user_data['steam']['app_id'], context_id=context_id)
            inventory = steam_client.get_my_inventory(game)
            i = 0
            while True:
                i += 1
                time_sleep = self.user_data['sleep_time']

                # check is steam session is alive
                if i == 3:
                    is_session_alive = steam_client.is_session_alive()
                    logger.info(f'is_session_alive: {is_session_alive}')
                    i = 0

                # get users to send trade offer
                if not users_to_reply:
                    users_to_reply = self.get_users_to_reply()

                if not is_session_alive:
                    # update steam session
                    steam_client.login(
                        username=self.user_data['steam']['username'],
                        password=self.user_data['steam']['password'],
                        steam_guard=self.user_data['steam']['steam_guard'])
                    is_session_alive = steam_client.is_session_alive()

                if users_to_reply:
                    for user in users_to_reply.keys():
                        items_to_trade_offer = []

                        if user in self.replied_users:
                            if users_to_reply[user]['post_id'] in self.replied_users[user]['posts']:
                                continue
                            else:
                                user_timestamp = list(self.replied_users[user]['posts'].values())[-1]
                                user_date = datetime.fromtimestamp(user_timestamp)
                                now = datetime.now()
                                diff = now - user_date
                                minutes = diff.total_seconds() / 60

                                if minutes > self.user_data['user_timeout_to_send_trade_offer_in_minutes']:
                                    logger.info(users_to_reply[user])
                                    result = self.send_trade_offer(steam_client, inventory, game,
                                                                   users_to_reply[user]['trade_url'])
                                    self.reply_user_info(result, user, users_to_reply)
                                else:
                                    now = datetime.now()
                                    data_now = datetime.timestamp(now)
                                    self.replied_users[user]['posts'][users_to_reply[user]['post_id']] = data_now
                                    continue
                        elif user not in self.replied_users:

                            logger.info(users_to_reply[user])
                            now = datetime.now()
                            data_now = datetime.timestamp(now)
                            self.replied_users[user] = {
                                'posts': {
                                    users_to_reply[user]['post_id']: data_now
                                },
                                "poster_username": users_to_reply[user]['poster_username'],
                                "trade_url": users_to_reply[user]['trade_url']
                            }
                            result = self.send_trade_offer(steam_client, inventory, game,
                                                           users_to_reply[user]['trade_url'])
                            self.reply_user_info(result, user, users_to_reply)

                        time.sleep(15)
                users_to_reply = []
                time.sleep(time_sleep)

    @logger.catch()
    def get_last_page(self) -> int:
        try:
            response = self.session.get(
                f'https://{self.domain_name}/api/index.php?posts/&thread_id={self.thread_id}').json()
            if 'links' in response:
                last_page = response['links']['pages']
            else:
                last_page = 1
            return last_page
        except Exception as error:
            logger.error(error)
            return 1

    @logger.catch()
    def get_users_to_reply(self) -> dict:
        users_to_reply = {}
        last_page = self.get_last_page()
        first_page = 1
        if int(last_page) > 1:
            first_page = int(last_page) - 1

        for i in range(first_page, int(last_page) + 1):
            try:
                response = self.session.get(
                    f'https://{self.domain_name}/api/index.php?posts/&thread_id={self.thread_id}&page={i}').json()
                logger.info(response.status_code)
            except Exception as error:
                logger.error(error)
                return users_to_reply

            for post in response['posts']:
                if str(post['poster_user_id']) in self.replied_users:
                    if str(post['post_id']) in self.replied_users[str(post['poster_user_id'])]['posts']:
                        continue
                if not post['post_is_first_post'] and str(post['poster_user_id']) != self.user_id:
                    user_likes = self.get_user_likes(post['poster_user_id'])

                    if user_likes != -1 and user_likes >= self.user_data['minimum_user_likes']:
                        trade_url = self.parse_trade_url(post['post_body_html'])
                        if trade_url != '':
                            users_to_reply[str(post['poster_user_id'])] = {
                                'post_id': str(post['post_id']),
                                'poster_username': post['poster_username'],
                                'trade_url': trade_url
                            }
        return users_to_reply

    @logger.catch()
    def setup_items_to_trade_offer(self, inventory: dict, game: GameOptions) -> list:
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

    def get_user_me(self) -> dict:
        response: dict = {}
        try:
            response = self.session.get('https://lolz.guru/api/index.php?/users/me').json()
        except (RequestException, json.decoder.JSONDecodeError) as error:
            logger.error(error)
            return response
        return response

    def get_thread_id(self):
        thread_id: str = ''
        try:
            result = re.search(r'\d+', self.theme_url)
            if result:
                thread_id = result.group(0)
        except TypeError as error:
            logger.error(error)
            return thread_id
        return thread_id

    @staticmethod
    @logger.catch()
    def get_username(user: dict) -> Union[dict, None]:
        try:
            if 'user' in user:
                return user['user']['username']
        except KeyError as error:
            logger.error(error)
            return None
        else:
            return user['user']['username']

    @staticmethod
    @logger.catch()
    def get_user_id(user: dict) -> str:
        user_id: str = ''
        try:
            if 'user' in user:
                user_id = str(user['user']['user_id'])
        except KeyError as error:
            logger.error(error)
            return user_id
        return user_id

    @staticmethod
    def parse_trade_url(post_body_html: str) -> str:
        trade_url: str = ''
        try:
            result = re.search(r'\?partner=\d+&(amp;)?token=([A-z]|[0-9]|-|_)+', post_body_html)
            if result:
                result = result.group(0).replace('amp;', '')
                trade_url = 'https://steamcommunity.com/tradeoffer/new/' + result
                return trade_url
        except TypeError as error:
            logger.error(error)
        return trade_url

    def get_user_likes(self, user_id: str) -> int:
        user_like_count: int = -1
        try:
            response = self.session.get(f'https://lolz.guru/api/index.php?/users/{user_id}').json()
            if 'user' in response:
                user_like_count = response['user']['user_like_count']
        except (RequestException, json.decoder.JSONDecodeError) as error:
            logger.error(error)
            return user_like_count
        return user_like_count


if __name__ == '__main__':
    DATA_JSON = load_data_from_file()

    with LolzWorker(DATA_JSON) as lolz:
        lolz.reply()
