import os
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from os import path
from urllib import parse

from tuf_conformance.repository_simulator import RepositorySimulator


@dataclass
class ClientInitData:
    metadata_url: str
    targets_url: str
    trusted_root: bytes


class _ReqHandler(BaseHTTPRequestHandler):
    """HTTP handler for the repository simulations

    Serves metadata and targets for multiple repositories
    """

    def do_GET(self) -> None:  # noqa: N802
        """Handle GET: metadata and target files"""

        test, _, path = self.path.lstrip("/").partition("/")

        try:
            assert isinstance(self.server, SimulatorServer)
            repo = self.server.repos[parse.unquote(test)]
        except KeyError:
            self.send_error(404, f"Did not find repository for {test}")
            return

        try:
            data = repo.fetch(path)
        except (ValueError, IndexError) as e:
            self.send_error(404, str(e))
            return
        self.send_response(200)
        self.send_header("Content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format: str, *args: str) -> None:
        """Log an arbitrary message.

        Avoid output for now. TODO We may want to log in some situations?
        """


class SimulatorServer(ThreadingHTTPServer):
    """Web server to serve a number of repositories"""

    def __init__(self, dump_dir: str | None) -> None:
        super().__init__(("127.0.0.1", 0), _ReqHandler)
        self.timeout = 0
        self._dump_dir = dump_dir

        # key is test name, value is the repository sim for that test
        self.repos: dict[str, RepositorySimulator] = {}

    def new_test(self, name: str) -> tuple[ClientInitData, RepositorySimulator]:
        """Return a tuple of
        * A new repository simulator (for test case to control)
        * client initialization parameters (so client can find the simulated repo)
        """
        safe_name = parse.quote(name, "")
        dump_dir = path.join(self._dump_dir, safe_name) if self._dump_dir else None
        repo = RepositorySimulator(dump_dir)
        self.repos[name] = repo

        host, port = self.server_address[0], self.server_address[1]
        assert isinstance(host, str)
        client_data = ClientInitData(
            f"http://{host}:{port}/{safe_name}/metadata/",
            f"http://{host}:{port}/{safe_name}/targets/",
            repo.fetch_metadata("root", 1),
        )

        return client_data, repo

    def debug_dump(self, test_name: str) -> None:
        self.repos[test_name].debug_dump()


class StaticServer(ThreadingHTTPServer):
    """Web server to serve static repositories"""

    data_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static_data")

    @classmethod
    def static_test_names(cls) -> list[str]:
        """Return list of static test names (subdirectories of 'static_data/')."""
        static_tests = []
        for static_dir in os.listdir(StaticServer.data_dir):
            if os.path.isdir(os.path.join(StaticServer.data_dir, static_dir)):
                static_tests.append(static_dir)
        return static_tests

    def __init__(self) -> None:
        class _StaticReqHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                filepath = os.path.join(StaticServer.data_dir, self.path[1:])
                try:
                    with open(filepath, "rb") as f:
                        data = f.read()
                except OSError:
                    self.send_error(404, f" {self.path} not found")
                    return

                self.send_response(200)
                self.send_header("Content-length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        super().__init__(("127.0.0.1", 0), _StaticReqHandler)
        self.timeout = 0

    def new_test(self, static_dir: str) -> tuple[ClientInitData, str]:
        sub_dir = os.path.join(self.data_dir, static_dir)
        with open(os.path.join(sub_dir, "initial_root.json"), "rb") as f:
            initial_root = f.read()

        host, port = self.server_address[0], self.server_address[1]
        assert isinstance(host, str)
        client_data = ClientInitData(
            f"http://{host}:{port}/{static_dir}/metadata/",
            f"http://{host}:{port}/{static_dir}/targets/",
            initial_root,
        )

        with open(os.path.join(sub_dir, "targetpath")) as f:
            targetpath = f.readline().strip("\n")

        return client_data, targetpath

    def debug_dump(self, test_name: str) -> None:
        pass  # not implemented
