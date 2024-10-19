#!/usr/bin/env python3
"""
aiobotocore SQS Producer Example
"""

import asyncio
import random
import sys

import botocore.exceptions

from aiobotocore.session import get_session

QUEUE_NAME = 'test_queue12'


async def go():
    # Boto should get credentials from ~/.aws/credentials or the environment
    session = get_session()
    async with session.create_client('sqs', region_name='us-west-2') as client:
        try:
            response = await client.get_queue_url(QueueName=QUEUE_NAME)
        except botocore.exceptions.ClientError as err:
            if (
                err.response['Error']['Code']
                == 'AWS.SimpleQueueService.NonExistentQueue'
            ):
                print(f"Queue {QUEUE_NAME} does not exist")
                sys.exit(1)
            else:
                raise

        queue_url = response['QueueUrl']

        print('Putting messages on the queue')

        msg_no = 1
        while True:
            try:
                msg_body = f'Message #{msg_no}'
                await client.send_message(
                    QueueUrl=queue_url, MessageBody=msg_body
                )
                msg_no += 1

                print(f'Pushed "{msg_body}" to queue')

                await asyncio.sleep(random.randint(1, 4))
            except KeyboardInterrupt:
                break

        print('Finished')


def main():
    try:
        loop = asyncio.get_event_loop()
        loop.run_until_complete(go())
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
