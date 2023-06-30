from typing import Dict, List
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from tuf_conformance.repository_simulator import RepositorySimulator

@dataclass
class ClientInitData:
    metadata_url: str
    trusted_root: bytes


class _ReqHandler(BaseHTTPRequestHandler):
    """HTTP handler for the repository simulations

    Serves metadata and targets for multiple repositories
    """

    def do_GET(self):
        """Handle GET: metadata and target files"""

        test, _, path = self.path.lstrip("/").partition("/")

        try:
            repo:RepositorySimulator = self.server.repos[test]
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
    def __init__(self, port: int):
        super().__init__(("127.0.0.1", port), _ReqHandler)
        self.timeout = 0

        # key is test name, value is the repository sim for that test
        self.repos: Dict[str, RepositorySimulator] = {}


    def get_client_init_data(self, repo: str) -> ClientInitData:
        return ClientInitData(
            f"http://{self.server_name}:{self.server_port}/{repo}/metadata/",
            self.repos[repo].fetch_metadata("root", 1)
        )
        

