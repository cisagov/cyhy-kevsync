# Standard Python Libraries
import copy
import logging
import re
from typing import Literal


class RedactPasswordFilter(logging.Filter):
    """
    A logging filter that redacts passwords from URLs in log messages.

    This filter scans log messages for URLs and redacts any passwords found in the userinfo part of the URL.
    It ensures that sensitive information is not logged in plain text.

    Attributes:
        url_pattern (re.Pattern): A compiled regular expression pattern to match URLs.
    """

    url_pattern = re.compile(
        r"(?P<scheme>[a-zA-Z][a-zA-Z0-9+.-]*://)"
        r"(?P<userinfo>[^@]+@)?"
        r"(?P<host>[^:/]+)"
        r"(?P<port>:\d+)?"
        r"(?P<path>/[^ ]*)?"
    )

    def filter(self, record: logging.LogRecord) -> logging.LogRecord | Literal[True]:
        """
        Filter the log record to redact passwords from URLs.

        This method is called by the logging framework to filter log records.
        It redacts passwords from any URLs found in the log message.

        Args:
            record (logging.LogRecord): The log record to be filtered.

        Returns:
            logging.LogRecord: A new log record with redacted passwords.
            bool: True if the record does not need to be modified.
        """
        # Ensure the message is safely formatted before modifying
        formatted_message = record.getMessage()

        # Check if the message contains a password (match the userinfo part)
        if not self.url_pattern.search(formatted_message):
            # No need to modify the record, return the original
            return True

        # Redact passwords
        new_message = self.redact_passwords(formatted_message)

        # Create a shallow copy of the record only if modification is needed
        new_record = copy.copy(record)

        # Update the message and clear args since we are directly setting the final message
        new_record.msg = new_message
        new_record.args = None

        return new_record

    def redact_passwords(self, message: str) -> str:
        """
        Redact passwords from URLs in the given message.

        This method scans the message for URLs and replaces any passwords in the userinfo part with '****'.

        Args:
            message (str): The log message to be processed.

        Returns:
            str: The log message with redacted passwords.
        """

        def replace(match):
            userinfo = match.group("userinfo")
            if userinfo:
                userinfo = re.sub(r":[^@]*", ":****", userinfo)
            return f"{match.group('scheme')}{userinfo or ''}{match.group('host')}{match.group('port') or ''}{match.group('path') or ''}"

        return self.url_pattern.sub(replace, message)
