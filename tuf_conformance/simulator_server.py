from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from os import path
from typing import Dict
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

    def do_GET(self):
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
        except ValueError as e:
            self.send_error(404, str(e))
            return
        self.send_response(200)
        self.send_header("Content-length", len(data))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format, *args):
        """Log an arbitrary message.

        Avoid output for now. TODO We may want to log in some situations?
        """
        pass


class SimulatorServer(ThreadingHTTPServer):
    """Web server to serve a number of repositories"""

    def __init__(self, dump_dir: str | None):
        super().__init__(("127.0.0.1", 0), _ReqHandler)
        self.timeout = 0
        self._dump_dir = dump_dir

        # key is test name, value is the repository sim for that test
        self.repos: Dict[str, RepositorySimulator] = {}

    def new_test(self, name: str) -> tuple[ClientInitData, RepositorySimulator]:
        """Return a tuple of
        * A new repository simulator (for test case to control)
        * client initialization parameters (so client can find the simulated repo)
        """
        dump_dir = path.join(self._dump_dir, name) if self._dump_dir else None
        repo = RepositorySimulator(dump_dir)
        self.repos[name] = repo

        host, port = self.server_address[0], self.server_address[1]
        assert isinstance(host, str)
        client_data = ClientInitData(
            f"http://{host}:{port}/{parse.quote(name, '')}/metadata/",
            f"http://{host}:{port}/{parse.quote(name, '')}/targets/",
            repo.fetch_metadata("root", 1),
        )

        return client_data, repo

    def debug_dump(self, test_name):
        self.repos[test_name].debug_dump()
