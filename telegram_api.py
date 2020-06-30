import requests
import os
import json
import sys
import time

whitelist = os.listdir('whitelist/')

# telegram contacts/groups to send the anomaly detection results, if silent no notification will show when sent
def sendTelegramMessage(message, silent = False, chat_id = False):
    with open('database/telegram_ids') as f:
        lines = f.readlines()
    chat_ids = json.loads(lines[0])
    bot_id = json.loads(lines[1])

    chat_ids = ({'chat_id': chat_id} if chat_id else chat_ids)
    silent = ('true' if silent else 'false')
    for chat_id in list(chat_ids.values()):
        bot_init = 'https://api.telegram.org/%(bot_id)s/sendMessage?chat_id=%(chat_id)s&text=%(message)s&parse_mode=HTML&disable_web_page_preview=true&disable_notification=%(silent)s' % {'silent':str(silent), 'bot_id':bot_id['@anomaly_detect_bot'], 'chat_id': str(chat_id), 'message':message}
        print(requests.get(bot_init))

def receiveMessage():
    with open('database/telegram_ids') as f:
        lines = f.readlines()
    bot_id = json.loads(lines[1])
    try:
        with open('database/old_update_ids', 'r') as f:
            old_ids = f.readlines()
            old_ids = [int(line.strip()) for line in old_ids]
            last_id = old_ids[-1]
    except Exception as e:
        last_id = 1
        old_ids =[]

    bot_init1 = 'https://api.telegram.org/%(bot_id)s/getupdates?allowed_updates=["message"]?offset=%(last_id)s'%{'last_id': str(last_id),'bot_id': bot_id['@anomaly_detect_bot']}
    messages = requests.get(bot_init1).json()
    if not messages: return None

    all_ids = [str(conversation['update_id']) + '\n' for conversation in messages['result']]
    important_updates = []
    for conversation in messages['result']:
        if conversation['update_id'] not in old_ids and 'message' in list(conversation):
            if 'text' in list(conversation['message']) and 'chat' in list(conversation['message']):
                important_updates.append({'chat_id':conversation['message']['chat']['id'], 'text':conversation['message']['text']})

    with open('database/old_update_ids', 'w') as f:
        f.writelines(all_ids)

    for message_info in important_updates:
        try:
            message = message_info['text']
            chat_id = message_info['chat_id']
            file_name = [file_name for file_name in whitelist if file_name in message]
            if not len(file_name) == 1:
                raise Exception('Missing or incorrect file name')
            else:
                split_message = message.split(file_name[0])[1].strip()
                split_message =[word.strip() for word in split_message.split(',')]
                request_type = ''
                site_name = ''
                ip = ''
                response = ''
                for part in split_message:
                    if 'request:'in part:
                        request_type = part.split('request:')[1].strip()

                    if 'site:' in part:
                        site_name = part.split('site:')[1].strip()

                    if 'ip:' in part:
                        ip = part.split('ip:')[1].strip()

                    if 'response:' in part:
                        response = part.split('response:')[1].strip()

                if 'sample_site' in request_type:
                    sendTelegramMessage('<b>The site should be in the site field and the request should be in the request field</b>, ignoring whitelist attempt', chat_id)
                    return False


                if any([True for val in [request_type, site_name, ip,response] if ' ' in val]) or not any([ip,site_name,request_type, response]):
                    raise Exception('Missing information or formatting is incorrect')
                else:
                    with open('whitelist/'+ file_name[0], 'a') as f:
                        f.write(request_type + ','+ site_name + ',' + ip + ',' + response  +'\n')
                        send_message = ''
                        for key, value in {'request':request_type, 'site':site_name, 'ip':ip, 'response':response}.items():
                            if value:
                                send_message = send_message + key + ' ' + value + ' '
                        send_message =send_message+ 'added to '+ file_name[0]
                        sendTelegramMessage(send_message, chat_id = chat_id)

        except Exception as e:
            sendTelegramMessage('Incorrect format. Available files are <b> whitelist_5xx, whitelist_4xx, whitelist_below_400</b>, available fields are <b>response, site, request, ip</b>. Site, response and ip fields will only identify exact string match (80.10.10.10 not 80.10), request field will identify partial string match (sample-dir/favicon.ico or favicon.ico).  Example usage/format: \n/anomaly_detect whitelist_5xx request:favicon.ico, ip: 10.10.10.10, response:404\n/anomaly_detect whitelist_below_400 request: /apple/carrot, site: sample_site\n/anomaly_detect whitelist_5xx site: sample_site', chat_id = chat_id)

def main():
    sendTelegramMessage('text',chat_id = 'test')
    receiveMessage()

if __name__ == '__main__':
    main()
