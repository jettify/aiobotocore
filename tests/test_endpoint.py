import pytest


@pytest.mark.moto
@pytest.mark.asyncio
async def test_invalid_endpoint_url(session, region):
    endpoint_url = 'invalid_url'
    with pytest.raises(ValueError, match=f'Invalid endpoint: {endpoint_url}'):
        async with session.create_client(
            'ec2', region_name=region, endpoint_url=endpoint_url
        ):
            # should not succeed in entering client context
            assert False  # pragma: no cover
