import http.server
import socketserver
import os
import webbrowser
import socket


def start_local_server(encrypted_session_token, transmission_key):
    # Set the directory that contains your static files

    static_dir = "images/"

    # Set the port that the server should listen on
    port = get_open_port()

    # Change to the static directory so that the server serves files from there
    os.chdir(static_dir)

    # Start the server
    Handler = http.server.SimpleHTTPRequestHandler
    httpd = socketserver.TCPServer(("", port), Handler)
    url = f"http://localhost:{port}/helloworld.html?sessionToken={encrypted_session_token}" \
          f"&transmissionKey={transmission_key}" \
          f"&recordUid=1234567890"
    print(f"Serving static files from {static_dir} at {url}")

    # Open the default web browser
    webbrowser.open(url)

    httpd.serve_forever()


def get_open_port():
    """
    Returns an open port number.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('', 0))
    port = sock.getsockname()[1]
    sock.close()
    return port
