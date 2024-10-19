import pytest
from botocore.exceptions import OperationNotPageableError


@pytest.mark.moto
def test_get_paginator_not_supported_by_service(sns_client):
    operation_name = 'list_tags_for_resource'
    with pytest.raises(OperationNotPageableError):
        sns_client.get_paginator(operation_name)


@pytest.mark.moto
def test_get_waiter_not_supported_by_service(sns_client):
    waiter_name = 'sns_does_not_support_waiters'
    with pytest.raises(
        ValueError, match=f'Waiter does not exist: {waiter_name}'
    ):
        sns_client.get_waiter(waiter_name)


@pytest.mark.moto
def test_get_waiter_invalid_waiter_name(cloudformation_client):
    waiter_name = 'this_name_is_invalid'
    with pytest.raises(
        ValueError, match=f'Waiter does not exist: {waiter_name}'
    ):
        cloudformation_client.get_waiter(waiter_name)
