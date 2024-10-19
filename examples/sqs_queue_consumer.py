#!/usr/bin/env python3
"""
aiobotocore SQS Consumer Example
"""

import asyncio
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

        print('Pulling messages off the queue')

        while True:
            try:
                # This loop wont spin really fast as there is
                # essentially a sleep in the receive_message call
                response = await client.receive_message(
                    QueueUrl=queue_url,
                    WaitTimeSeconds=2,
                )

                if 'Messages' in response:
                    for msg in response['Messages']:
                        print(f'Got msg "{msg["Body"]}"')
                        # Need to remove msg from queue or else it'll reappear
                        await client.delete_message(
                            QueueUrl=queue_url,
                            ReceiptHandle=msg['ReceiptHandle'],
                        )
                else:
                    print('No messages in queue')
            except KeyboardInterrupt:
                break

        print('Finished')


if __name__ == '__main__':
    asyncio.run(go())
