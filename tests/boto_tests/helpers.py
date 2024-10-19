from contextlib import AsyncExitStack, asynccontextmanager

from botocore.stub import Stubber

import aiobotocore.session


class StubbedSession(aiobotocore.session.AioSession):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._cached_clients = {}
        self._client_stubs = {}

    @asynccontextmanager
    async def create_client(self, service_name, *args, **kwargs):
        async with AsyncExitStack() as es:
            es: AsyncExitStack
            if service_name not in self._cached_clients:
                client = await es.enter_async_context(
                    self._create_stubbed_client(service_name, *args, **kwargs)
                )
                self._cached_clients[service_name] = client
            yield self._cached_clients[service_name]

    @asynccontextmanager
    async def _create_stubbed_client(self, service_name, *args, **kwargs):
        async with AsyncExitStack() as es:
            es: AsyncExitStack
            client = await es.enter_async_context(
                super().create_client(service_name, *args, **kwargs)
            )
            stubber = Stubber(client)
            self._client_stubs[service_name] = stubber
            yield client

    @asynccontextmanager
    async def stub(self, service_name, *args, **kwargs):
        async with AsyncExitStack() as es:
            es: AsyncExitStack
            if service_name not in self._client_stubs:
                await es.enter_async_context(
                    self.create_client(service_name, *args, **kwargs)
                )
            yield self._client_stubs[service_name]

    def activate_stubs(self):
        for stub in self._client_stubs.values():
            stub.activate()

    def verify_stubs(self):
        for stub in self._client_stubs.values():
            stub.assert_no_pending_responses()
