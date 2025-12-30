"""
HTCP Request Handler Registry

Decorator-based system for registering transaction handlers.
"""

import logging
import asyncio
from typing import Callable, Dict
from htcp.classes import Request


class RequestHandler:
    """
    Registry for transaction handlers

    Provides decorator for registering handlers and dispatcher for executing them.
    """

    def __init__(self):
        """Initialize handler registry"""
        self._handlers: Dict[str, Callable] = {}
        self.logger = logging.getLogger("htcp.handlers")

    def reg_handler(self, trans_code: str):
        """
        Decorator to register a handler function

        Usage:
            @server.rh.reg_handler(trans_code="my_transaction")
            def my_handler(request: Request) -> Union[dict, str, bytes]:
                return {"result": "success"}

        Args:
            trans_code: Transaction code to handle

        Returns:
            Decorator function
        """
        def decorator(func: Callable):
            if trans_code in self._handlers:
                self.logger.warning(
                    f"Overwriting handler for transaction: {trans_code}"
                )

            self._handlers[trans_code] = func
            self.logger.debug(
                f"Registered handler: {trans_code} -> {func.__name__}"
            )
            return func

        return decorator

    async def handle(self, request: Request) -> bytes:
        """
        Execute handler for a request

        Supports both sync and async handlers.
        Handler must return bytes.

        Args:
            request: Request object with package and client info

        Returns:
            Handler result as bytes

        Raises:
            ValueError: If no handler registered for transaction
            TypeError: If handler doesn't return bytes
            Exception: Any exception raised by handler
        """
        trans_code = request.package.transaction

        # Check if handler exists
        if trans_code not in self._handlers:
            self.logger.error(f"No handler for transaction: {trans_code}")
            raise ValueError(f"Unknown transaction: {trans_code}")

        handler = self._handlers[trans_code]

        # Execute handler (may be sync or async)
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

        # Verify result is bytes
        if not isinstance(result, bytes):
            raise TypeError(
                f"Handler {handler.__name__} must return bytes, got {type(result).__name__}"
            )

        return result

    def get_handlers(self) -> Dict[str, Callable]:
        """
        Get all registered handlers

        Returns:
            Dictionary of transaction codes to handler functions
        """
        return self._handlers.copy()

    def has_handler(self, trans_code: str) -> bool:
        """
        Check if handler is registered for transaction

        Args:
            trans_code: Transaction code

        Returns:
            True if handler exists
        """
        return trans_code in self._handlers
