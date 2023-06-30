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

        test, _, path = self.path.partition("/")

        repo:RepositorySimulator = self.server.repos[test]
        if repo is None:
            self.send_error(404, f"Did not find repository for {test}")
            return

        data = repo.fetch(path)
        self.send_response(200)
        self.send_header("Content-length", len(data))
        self.end_headers()
        self.wfile.write(data)


class SimulatorServer(ThreadingHTTPServer):
    """Web server to serve a number of repositories"""
    def __init__(self, port: int):
        super().__init__(("127.0.0.1", port), _ReqHandler)
        self.timeout = 1

        # key is test name, value is the repository sim for that test
        self.repos: Dict[str, RepositorySimulator] = {}


    def get_client_init_data(self, repo: str) -> ClientInitData:
        return ClientInitData(
            f"http://{self.server_name}:{self.server_port}/{repo}/metadata/",
            self.repos[repo].fetch_metadata("root", 1)
        )
        

