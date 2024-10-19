import pytest

from aiobotocore.session import AioSession


@pytest.mark.parametrize(
    'defaults_mode,retry_mode',
    [('legacy', 'legacy'), ('standard', 'standard'), ('auto', 'standard')],
)
@pytest.mark.moto
@pytest.mark.asyncio
async def test_defaults_mode(monkeypatch, defaults_mode, retry_mode):
    monkeypatch.setenv('AWS_DEFAULTS_MODE', defaults_mode)

    session = AioSession()

    assert session.get_config_variable('defaults_mode') == defaults_mode

    async with session.create_client('s3') as client:
        assert client.meta.config.retries['mode'] == retry_mode
