import asyncio

import pytest

import aiobotocore.session
from aiobotocore.httpsession import HttpxSession
from tests._helpers import AsyncExitStack


@pytest.mark.asyncio
async def test_kinesis_stream_json_parser(request, exit_stack: AsyncExitStack):
    # unfortunately moto doesn't support kinesis register_stream_consumer +
    # subscribe_to_shard yet
    stream_name = "my_stream"
    stream_arn = consumer_arn = None
    consumer_name = 'consumer'

    for mark in request.node.iter_markers("config_kwargs"):
        assert len(mark.args) == 1
        assert isinstance(mark.args[0], dict)
        http_session_cls = mark.args[0].get('http_session_cls')
        if http_session_cls is HttpxSession:
            session = HttpxSession()
            break
    else:
        session = aiobotocore.session.AioSession()

    kinesis_client = await exit_stack.enter_async_context(
        session.create_client('kinesis')
    )
    await kinesis_client.create_stream(StreamName=stream_name, ShardCount=1)

    while (
        describe_response := (
            await kinesis_client.describe_stream(  # noqa: E231, E999, E251, E501
                StreamName=stream_name
            )
        )
    ) and describe_response['StreamDescription']['StreamStatus'] == 'CREATING':
        print("Waiting for stream creation")
        await asyncio.sleep(1)

    shard_id = describe_response["StreamDescription"]["Shards"][0]["ShardId"]
    stream_arn = describe_response["StreamDescription"]["StreamARN"]

    try:
        # Create some data
        keys = [str(i) for i in range(1, 5)]
        for k in keys:
            await kinesis_client.put_record(
                StreamName=stream_name, Data=k, PartitionKey=k
            )

        register_response = await kinesis_client.register_stream_consumer(
            StreamARN=stream_arn, ConsumerName=consumer_name
        )
        consumer_arn = register_response['Consumer']['ConsumerARN']

        while (
            describe_response := (
                await kinesis_client.describe_stream_consumer(  # noqa: E231, E999, E251, E501
                    StreamARN=stream_arn,
                    ConsumerName=consumer_name,
                    ConsumerARN=consumer_arn,
                )
            )
        ) and describe_response['ConsumerDescription'][
            'ConsumerStatus'
        ] == 'CREATING':
            print("Waiting for stream consumer creation")
            await asyncio.sleep(1)

        starting_position = {'Type': 'LATEST'}
        subscribe_response = await kinesis_client.subscribe_to_shard(
            ConsumerARN=consumer_arn,
            ShardId=shard_id,
            StartingPosition=starting_position,
        )
        async for event in subscribe_response['EventStream']:
            assert event['SubscribeToShardEvent']['Records'] == []
            break
    finally:
        if consumer_arn:
            await kinesis_client.deregister_stream_consumer(
                StreamARN=stream_arn,
                ConsumerName=consumer_name,
                ConsumerARN=consumer_arn,
            )

        await kinesis_client.delete_stream(StreamName=stream_name)
