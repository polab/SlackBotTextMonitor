#!/usr/bin/eny python
import time
import argparse
import re
from slackclient import SlackClient

def main(conf, sc):
    """ main loop """
    # this will wait for events
    events = sc.rtm_read()
    for event in events:
        event_processor(conf, sc, event)

def event_processor(conf, sc, event):
    """ Event processor """
    # Looking only for message events and only if I didnt send it myself, to prevent loop
    if (
        'channel' in event and
        'text' in event and
        event.get('type') == 'message'
        and event['user'] != conf['me']['user_id']
    ):
        # first filter messages of interest
        text = event['text']
        channel = event['channel']

        match = False
        for regexp in conf['regexp']:
            if (regexp.match(text)):
                match = True
        if not match:
            return

        # send notifications
        notify_users(sc, channel, conf['user'])

def notify_users(sc, channel, users_list):
    """ Notify users from list by mentioning them in the channel """
    message = ':point_up:'
    for user in users_list:
        message += ' @{}'.format(user)
    # post message
    sc.api_call(
        'chat.postMessage',
        channel=channel,
        text=message,
        as_user=1,
        link_names=1
    )

def configure():
    """
    Configuration routine. Takes config from CLI args or environment.
    """
    conf = dict()

    parser = argparse.ArgumentParser(description='Slack Notifications bot.')
    # xxoxb-244592051105-4CRZX1SJOE0pObTk4cLGXg1t
    parser.add_argument('-t', '--token', nargs=1, required=True,
        help='Slack token to use.')
    parser.add_argument('-u', '--user', action='append',
        help='User to notify. May be used multiple times.')
    parser.add_argument('-r', '--regexp', action='append',
        help='Regexp to look for in messages. May be specified multiple times.')
    parser.add_argument('-i', '--interval', type=int, nargs=1, default=1,
        help='Interval to check for messages in seconds. Defaults to 1')
    args = parser.parse_args()

    conf['token'] = args.token
    conf['user'] = args.user
    conf['interval'] = args.interval
    # precompile regexps
    conf['regexp'] = []

    print("Users: %s" % (args.user[0]) )
    print("regexp: %s" % (args.regexp[0]) )

    for regexp_string in args.regexp:
        conf['regexp'].append(re.compile(regexp_string))
    
    return conf

if __name__ == '__main__':
    conf = configure()
    
    # connect
    slack_client = SlackClient(conf['token'])
    if not slack_client.rtm_connect():
        print('Connection error. Check token and network.')
    
    # get self info
    my_info = slack_client.api_call('auth.test')
    if not my_info['ok']:
        raise Exception('Cannot get info about myself: {}'.format(my_info))
    conf['me'] = my_info

    if len(conf['user']) == 0:
        raise Exception('No user IDs found')

    # main event loop
    while True:
        main(conf, slack_client)
        time.sleep(conf['interval'])
