import asyncio
import functools
import logging
import os
import socket
import threading
import time

# Third Party
import aiohttp
import moto.server
import werkzeug.serving

host = '127.0.0.1'

_PYCHARM_HOSTED = os.environ.get('PYCHARM_HOSTED') == '1'
_CONNECT_TIMEOUT = 90 if _PYCHARM_HOSTED else 10


def get_free_tcp_port(release_socket: bool = False):
    sckt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sckt.bind((host, 0))
    addr, port = sckt.getsockname()
    if release_socket:
        sckt.close()
        return port

    return sckt, port


class MotoService:
    """Will Create MotoService.
    Service is ref-counted so there will only be one per process. Real Service will
    be returned by `__aenter__`."""

    _services = dict()  # {name: instance}

    def __init__(self, service_name: str, port: int = None, ssl: bool = False):
        self._service_name = service_name

        if port:
            self._socket = None
            self._port = port
        else:
            self._socket, self._port = get_free_tcp_port()

        self._thread = None
        self._logger = logging.getLogger('MotoService')
        self._refcount = None
        self._ip_address = host
        self._server = None
        self._ssl_ctx = (
            werkzeug.serving.generate_adhoc_ssl_context() if ssl else None
        )
        self._schema = 'http' if not self._ssl_ctx else 'https'

    @property
    def endpoint_url(self):
        return f'{self._schema}://{self._ip_address}:{self._port}'

    def __call__(self, func):
        async def wrapper(*args, **kwargs):
            await self._start()
            try:
                result = await func(*args, **kwargs)
            finally:
                await self._stop()
            return result

        functools.update_wrapper(wrapper, func)
        wrapper.__wrapped__ = func
        return wrapper

    async def __aenter__(self):
        svc = self._services.get(self._service_name)
        if svc is None:
            self._services[self._service_name] = self
            self._refcount = 1
            await self._start()
            return self
        else:
            svc._refcount += 1
            return svc

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        self._refcount -= 1

        if self._socket:
            self._socket.close()
            self._socket = None

        if self._refcount == 0:
            del self._services[self._service_name]
            await self._stop()

    def _server_entry(self):
        self._main_app = moto.server.DomainDispatcherApplication(
            moto.server.create_backend_app, service=self._service_name
        )
        self._main_app.debug = True

        if self._socket:
            self._socket.close()  # release right before we use it
            self._socket = None

        self._server = werkzeug.serving.make_server(
            self._ip_address,
            self._port,
            self._main_app,
            True,
            ssl_context=self._ssl_ctx,
        )
        self._server.serve_forever()

    async def _start(self):
        self._thread = threading.Thread(target=self._server_entry, daemon=True)
        self._thread.start()

        async with aiohttp.ClientSession() as session:
            start = time.time()

            while time.time() - start < 20:
                if not self._thread.is_alive():
                    break

                try:
                    # we need to bypass the proxies due to monkeypatches
                    async with session.get(
                        self.endpoint_url + '/static',
                        timeout=_CONNECT_TIMEOUT,
                        ssl=False,
                    ):
                        pass
                    break
                except (asyncio.TimeoutError, aiohttp.ClientConnectionError):
                    await asyncio.sleep(0.5)
            else:
                await self._stop()  # pytest.fail doesn't call stop_process
                raise Exception(f"Can not start service: {self._service_name}")

    async def _stop(self):
        if self._server:
            self._server.shutdown()

        self._thread.join()
