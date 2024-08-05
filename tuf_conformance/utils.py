# Copyright 2020, TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""
<Program Name>
  utils.py

<Started>
  August 3, 2020.

<Author>
  Jussi Kukkonen

<Copyright>
  See LICENSE-MIT OR LICENSE for licensing information.

<Purpose>
  Provide common utilities for TUF tests
"""

import datetime
import errno
import logging
import os
import queue
import socket
import subprocess
import sys
import threading
import time
from datetime import timezone
from typing import IO, Optional

logger = logging.getLogger(__name__)

# May be used to reliably read other files in tests dir regardless of cwd
TESTS_DIR = os.path.dirname(os.path.realpath(__file__))

# Used when forming URLs on the client side
TEST_HOST_ADDRESS = "127.0.0.1"


class TestTarget:
    path: str
    content: bytes
    encoded_path: str


class TestServerProcessError(Exception):
    def __init__(self, value: str = "TestServerProcess") -> None:
        super().__init__()
        self.value = value

    def __str__(self) -> str:
        return repr(self.value)


# Wait until host:port accepts connections.
# Raises TimeoutError if this does not happen within timeout seconds
# There are major differences between operating systems on how this works
# but the current blocking connect() seems to work fast on Linux and seems
# to at least work on Windows (ECONNREFUSED unfortunately has a 2 second
# timeout on Windows)
def wait_for_server(host: str, server: str, port: int, timeout: int = 10) -> None:
    """Wait for server start until timeout is reached or server has started"""
    start = time.time()
    remaining_timeout = timeout
    succeeded = False
    while not succeeded and remaining_timeout > 0:
        try:
            sock: Optional[socket.socket] = socket.socket(
                socket.AF_INET, socket.SOCK_STREAM
            )
            assert sock is not None
            sock.settimeout(remaining_timeout)
            sock.connect((host, port))
            succeeded = True
        except socket.timeout:
            pass
        except OSError as e:
            # ECONNREFUSED is expected while the server is not started
            if e.errno not in [errno.ECONNREFUSED]:
                logger.warning("Unexpected error while waiting for server: %s", str(e))
            # Avoid pegging a core just for this
            time.sleep(0.01)
        finally:
            if sock:
                sock.close()
                sock = None
            remaining_timeout = int(timeout - (time.time() - start))

    if not succeeded:
        raise TimeoutError(
            "Could not connect to the " + server + " on port " + str(port) + "!"
        )


def get_date_n_days_in_past(days: int) -> datetime.datetime:
    return datetime.datetime.now(timezone.utc).replace(
        microsecond=0
    ) - datetime.timedelta(days=days)


def get_date_n_days_in_future(days: int) -> datetime.datetime:
    return datetime.datetime.now(timezone.utc).replace(
        microsecond=0
    ) + datetime.timedelta(days=days)


class TestServerProcess:
    """Helper class used to create a child process with the subprocess.Popen
    object and use a thread-safe Queue structure for logging.

     Args:
        log: Logger which will be used for logging.
        server: Path to the server to run in the subprocess.
        timeout: Time in seconds in which the server should start or otherwise
            TimeoutError error will be raised.
        popen_cwd: Current working directory used when instancing a
          subprocess.Popen object.
        extra_cmd_args: Additional arguments for the command which will start
            the subprocess. More precisely:
            "python -u <path_to_server> <port> <extra_cmd_args>".
            If no list is provided, an empty list ("[]") will be assigned to it.
    """

    def __init__(
        self,
        log: logging.Logger,
        server: str = os.path.join(TESTS_DIR, "simple_server.py"),
        timeout: int = 10,
        popen_cwd: str = ".",
        extra_cmd_args: Optional[list[str]] = None,
    ):
        self.server = server
        self.__logger = log
        # Stores popped messages from the queue.
        self.__logged_messages: list[str] = []
        self.__server_process: Optional[subprocess.Popen] = None
        self._log_queue: Optional[queue.Queue] = None
        self.port = -1
        if extra_cmd_args is None:
            extra_cmd_args = []

        try:
            self._start_server(timeout, extra_cmd_args, popen_cwd)
            wait_for_server("localhost", self.server, self.port, timeout)
        except Exception as e:
            # Clean the resources and log the server errors if any exists.
            self.clean()
            raise e

    def _start_server(
        self, timeout: int, extra_cmd_args: list[str], popen_cwd: str
    ) -> None:
        """
        Start the server subprocess and a thread
        responsible to redirect stdout/stderr to the Queue.
        Waits for the port message maximum timeout seconds.
        """

        self._start_process(extra_cmd_args, popen_cwd)
        self._start_redirect_thread()

        self._wait_for_port(timeout)

        self.__logger.info("%s serving on %d", self.server, self.port)

    def _start_process(self, extra_cmd_args: list[str], popen_cwd: str) -> None:
        """Starts the process running the server."""

        # The "-u" option forces stdin, stdout and stderr to be unbuffered.
        command = [sys.executable, "-u", self.server, *extra_cmd_args]

        # Reusing one subprocess in multiple tests, but split up the logs
        # for each.
        self.__server_process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            cwd=popen_cwd,
        )

    def _start_redirect_thread(self) -> None:
        """Starts a thread redirecting the stdout/stderr to the Queue."""

        assert isinstance(self.__server_process, subprocess.Popen)
        # Run log_queue_worker() in a thread.
        # The thread will exit when the child process dies.
        self._log_queue = queue.Queue()
        log_thread = threading.Thread(
            target=self._log_queue_worker,
            args=(self.__server_process.stdout, self._log_queue),
        )

        # "daemon = True" means the thread won't interfere with the
        # process exit.
        log_thread.daemon = True
        log_thread.start()

    @staticmethod
    def _log_queue_worker(stream: IO, line_queue: queue.Queue) -> None:
        """
        Worker function to run in a seprate thread.
        Reads from 'stream', puts lines in a Queue (Queue is thread-safe).
        """

        while True:
            # readline() is a blocking operation.
            # decode to push a string in the queue instead of 8-bit bytes.
            log_line = stream.readline().decode("utf-8")
            line_queue.put(log_line)

            if len(log_line) == 0:
                # This is the end of the stream meaning the server process
                # has exited.
                stream.close()
                break

    def _wait_for_port(self, timeout: int) -> None:
        """
        Validates the first item from the Queue against the port message.
        If validation is successful, self.port is set.
        Raises TestServerProcessError if the process has exited or
        TimeoutError if no message was found within timeout seconds.
        """

        assert isinstance(self.__server_process, subprocess.Popen)
        assert isinstance(self._log_queue, queue.Queue)
        # We have hardcoded the message we expect on a successful server
        # startup. This message should be the first message sent by the server!
        expected_msg = "bind succeeded, server port is: "
        try:
            line = self._log_queue.get(timeout=timeout)
            if len(line) == 0:
                # The process has exited.
                raise TestServerProcessError(
                    self.server
                    + " exited unexpectedly "
                    + "with code "
                    + str(self.__server_process.poll())
                    + "!"
                )

            if line.startswith(expected_msg):
                self.port = int(line[len(expected_msg) :])
            else:
                # An exception or some other message is printed from the server.
                self.__logged_messages.append(line)
                print("line::::::::::::::::::::::", line)
                # Check if more lines are logged.
                self.flush_log()
                raise TestServerProcessError(
                    self.server
                    + " did not print port "
                    + "message as first stdout line as expected!"
                )
        except queue.Empty as e:
            raise TimeoutError("Failure during " + self.server + " startup!") from e

    def _kill_server_process(self) -> None:
        """Kills the server subprocess if it's running."""

        assert isinstance(self.__server_process, subprocess.Popen)
        if self.is_process_running():
            self.__logger.info(
                "Server process %d terminated", self.__server_process.pid
            )
            self.__server_process.kill()
            self.__server_process.wait()

    def flush_log(self) -> None:
        """Flushes the log lines from the logging queue."""

        assert isinstance(self._log_queue, queue.Queue)
        while True:
            # Get lines from log_queue
            try:
                line = self._log_queue.get(block=False)
                if len(line) > 0:
                    self.__logged_messages.append(line)
            except queue.Empty:
                # No more lines are logged in the queue.
                break

        if len(self.__logged_messages) > 0:
            title = "Test server (" + self.server + ") output:\n"
            message = [title, *self.__logged_messages]
            self.__logger.info("| ".join(message))
            self.__logged_messages = []

    def clean(self) -> None:
        """
        Kills the subprocess and closes the TempFile.
        Calls flush_log to check for logged information, but not yet flushed.
        """

        # If there is anything logged, flush it before closing the resourses.
        self.flush_log()

        self._kill_server_process()

    def is_process_running(self) -> bool:
        assert isinstance(self.__server_process, subprocess.Popen)
        return self.__server_process.poll() is None
