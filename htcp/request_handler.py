import logging
import asyncio

from typing import Callable, Dict
from .classes import Request


class RequestHandler:
    def __init__(self):
        self._handlers: Dict[str, Callable] = {}
        self.logger = logging.getLogger("htcp.handlers")

    def reg_handler(self, trans_code: str):
        def decorator(func: Callable):
            if trans_code in self._handlers:
                self.logger.warning(
                    f"Overwriting handler for transaction: {trans_code}"
                )

            self._handlers[trans_code] = func
            # self.logger.debug(
            #     f"Registered handler: {trans_code} -> {func.__name__}"
            # )
            return func

        return decorator

    async def handle(self, request: Request) -> bytes:
        trans_code = request.package.transaction

        if trans_code not in self._handlers:
            self.logger.error(f"No handler for transaction: {trans_code}")
            raise ValueError(f"Unknown transaction: {trans_code}")

        handler = self._handlers[trans_code]

        try:
            if asyncio.iscoroutinefunction(handler):
                result = await handler(request)
            else:
                result = handler(request)
        except Exception as e:
            self.logger.error(
                f"Handler {handler.__name__} raised exception: {e}",
                exc_info=True
            )
            raise

        if not isinstance(result, bytes):
            raise TypeError(
                f"Handler {handler.__name__} must return bytes, got {type(result).__name__}"
            )

        return result

    def get_handlers(self) -> Dict[str, Callable]:
        return self._handlers.copy()

    def has_handler(self, trans_code: str) -> bool:
        return trans_code in self._handlers
