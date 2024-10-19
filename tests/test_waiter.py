import asyncio

import pytest

from aiobotocore.waiter import (
    AIOWaiter,
    WaiterModel,
    create_waiter_with_client,
)


@pytest.fixture
def cloudformation_waiter_model(cloudformation_client):
    config = cloudformation_client._get_waiter_config()
    return WaiterModel(config)


@pytest.mark.moto
def test_create_waiter_with_client(
    cloudformation_client, cloudformation_waiter_model
):
    waiter = create_waiter_with_client(
        'StackCreateComplete',
        cloudformation_waiter_model,
        cloudformation_client,
    )
    assert isinstance(waiter, AIOWaiter)
    assert asyncio.iscoroutinefunction(waiter.wait)


@pytest.mark.moto
@pytest.mark.asyncio
async def test_sqs(cloudformation_client, current_http_backend: str):
    stack_name = 'my-stack-{current_http_backend}'
    cloudformation_template = """{
      "AWSTemplateFormatVersion": "2010-09-09",
      "Resources": {
        "queue1": {
          "Type": "AWS::SQS::Queue",
          "Properties": {
            "QueueName": "my-queue"
          }
        }
      }
    }"""

    # Create stack
    resp = await cloudformation_client.create_stack(
        StackName=stack_name, TemplateBody=cloudformation_template
    )

    assert resp['ResponseMetadata']['HTTPStatusCode'] == 200

    # wait for complete
    waiter = cloudformation_client.get_waiter('stack_create_complete')
    await waiter.wait(StackName=stack_name)

    await cloudformation_client.delete_stack(StackName=stack_name)
