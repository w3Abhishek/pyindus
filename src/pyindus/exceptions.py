"""Custom exceptions for PyIndus."""


class IndusError(Exception):
    """Base exception for all PyIndus errors."""

    pass


class AuthenticationError(IndusError):
    """Raised when authentication fails."""

    pass


class SessionError(IndusError):
    """Raised when session operations fail."""

    pass


class APIError(IndusError):
    """Raised when an API call returns an unexpected error."""

    def __init__(self, message: str, status_code: int | None = None, response_body: str | None = None):
        self.status_code = status_code
        self.response_body = response_body
        super().__init__(message)
