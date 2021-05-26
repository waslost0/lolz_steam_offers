# lolz_steam_autosend_trade_offers

Автоматизированная раздача вещей стим на сайте lolz.guru

## Requirements

- python 3.8
- Steam maFile
- Unlimited steam account

## Config

1) **Steamguard.txt**

Открыть maFile в текстовом редакторе, найти нужные переменные, заполнить Steamguard.txt

```json
    {
        "steamid": "",
        "shared_secret": "",
        "identity_secret": ""
    }
```


2) **data.json**

```json
{
    "theme_url": "",
    "message": "",
    "minimum_user_likes": 20,
    "user_timeout_to_send_trade_offer_in_minutes": 100,
    "lolz_api_key": "",
    "rucaptcha_token": "RUCAPTCHA_TOKEN",
    "sleep_time": 20,
    "telegram": {
        "telegram_id": "",
        "info_mode": "False",
        "error_mode": "True",
        "api_id": "",
        "api_hash": ""
    },
    "steam": {
        "app_id": "APP_ID",
        "items_count": 1,
        "api_key": "STEAM_API_KEY",
        "username": "USERNAME",
        "password": "PASSWORD",
        "steam_guard": "Steamguard.txt"
    },
    "proxy": {
        "account_proxy": "user:pass@ip:port",
        "proxy_type": "https"
    }
}
```

| Param        | Meaning           
| ------------ |:-------------|
| theme_url    |ссылка на тему |
|message       | сообщение, что будет отправлено в тему|
|minimum_user_likes | количество лайков пользователя|
|user_timeout_to_send_trade_offer_in_minutes | Через какое время отправить повторно трейд одному человеку|
|lolz_api_key  | Api ключ лолза, получить по этой [ссылке](https://lolz.guru/api/index.php?oauth/authorize&response_type=token&client_id=CLIENT_ID&scope=read+post+usercp+conversate)|
|sleep_time | задержка перед проверкой новых сообщений в теме|
|telegram_id | id телеги, для уведомлений|
|info_mode | информация об отправленных трейдах <blockquote><img src="https://i.imgur.com/0m5aE9w.png"></blockquote>|
|error_mode | информация об ошибках <blockquote><img src="https://i.imgur.com/70RTqGV.png"></blockquote>|
|app_id| https://steamdb.info/search/|
|items_count| количество предметов что будет отправлено|
|api_key| steam api key - https://steamcommunity.com/dev/apikey|
|username| steam username|
|password| steam password|
|account_proxy| прокси для лолза вида user:pass@ip:port|

## Installation 

```
git clone https://github.com/waslost0/lolz_steam_autosend_trade_offers
cd lolz_steam_autosend_trade_offers
pip install -r requirements.txt
```

## Run

<blockquote> py main_api.py </blockquote>

## Buy me a coffee
<a href="https://www.buymeacoffee.com/waslost" target="_blank"><img src="https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png" alt="Buy Me A Coffee"></a>

<a href="https://qiwi.com/n/WASLOST" target="_blank"><img width="70" src="https://i.imgur.com/jomb5KW.png" alt="Buy Me A Coffee"></a>


 
