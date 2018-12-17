
# AuthAlertBot

![](https://img.shields.io/appveyor/ci/gruntjs/grunt.svg)![](https://img.shields.io/badge/platform-linux-lightgrey.svg)![](https://img.shields.io/badge/python-3.6%20%7C%203.7-blue.svg)![](https://img.shields.io/badge/version-1.0-yellow.svg)![](https://img.shields.io/badge/license-MIT-orange.svg)

## About AuthAlertBot 

AuthAlertBot is telegram bot intended for notification of new connections via ssh. For get information about connections bot uses file /var/log/auth.log. Also, using this bot, you can easily lock / unlock (with iptables) access to computer on linux. This bot will be useful for those who want to know about who connect to his system. Supported work in chat groups for multiple access. 

## System requirements

For correct work required:
 - Python 3.6 or latter
 - iptables
 
Required modules python:
 - Requests
 - PySocks

**ATTENTION:** This bot requires superuser rights.

Tested working on Ubuntu 18.04 LTS.

## Configuration

### Configuration bot

If not exists configuration file in script folder just run script and follow instructions. For reconfigure bot run script with argument '-setup':

    python3 AlertBot.py -setup

P.S. If you want to use multiple bots in a group chat **MANDATORY** enter prefix. It will serve as bot ID.

### Configuration bot as daemon

#### For configure bot as daemon required install systemd

    apt-get install systemd

#### Next, you need to create a service file

File path: 

    /etc/systemd/system/AuthAlertBot.service

File example:

    [Unit]
    Description=AuthAlertBot
    After=syslog.target
    After=network.target
    
    [Service]
    Type=simple
    User=root
    WorkingDirectory=/root/AuthAlertBot
    ExecStart=/usr/bin/python3 /root/AuthAlertBot/AlertBot.py
    RestartSec=10
    Restart=always
     
    [Install]
    WantedBy=default.target

#### After creating service enable and start its 

    systemctl daemon-reload
    systemctl enable AuthAlertBot
    systemctl start AuthAlertBot
    systemctl status AuthAlertBot

#### If successful, you will see next text
![Daemon status](https://i.imgur.com/iW240Zc.jpg)

![Telegram message](https://i.imgur.com/FERTsMK.jpg)

## Commands

Available commands:

    /status - Threads status
    /kill_bot - Stopping all threads
    /lock [prefix] X.X.X.X - IP blocking
    /unlock [prefix] X.X.X.X - IP unblocking

## Sharing use

For collective use of a bot / bots by several users, it is necessary to create a group / supergroup and add bots to it, as well other users. After creating the group, you need to **change the privacy mode** of bot to **disabled**. Otherwise, bot will not be able to get chat_id. After completing these steps, you can start setting up the back end of bot.

When using a bot / bots in groups, you can use bot prefix (for execute in target bot). Otherwise, the command will be executed by all bots.

**ATTENTION:** When converting a group into a supergroup, the chat_id changes, which requires a new scan of the chat_id.

## Access protection

For protect access to bot management during initial configuration, you must send a randomly generated string to the chat with bot. This is necessary to determine the chat_id, in other words, the chat that will have access to bot commands. All other chats will be ignored by bot.
This bot does not send any information to its creator and stores all data locally.

## License

AuthAlertBot is open-sourced software licensed under the [MIT license](https://opensource.org/licenses/MIT).

(C) Nikolay Sysoev, ghosteedd, 2018.
