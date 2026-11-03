"""Run OvpnSession tests with a temporary local server in a private network namespace."""

import errno
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time


def openssl(directory, *arguments):
    subprocess.run(["openssl", *arguments], cwd=directory, check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)


def prepare_profiles(directory):
    openssl(directory, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
            "-subj", "/CN=xtun-session-CA", "-keyout", "ca.key", "-out", "ca.pem")
    for name, usage in (("server", "serverAuth"), ("client", "clientAuth")):
        openssl(directory, "req", "-new", "-newkey", "rsa:2048", "-nodes",
                "-subj", "/CN=xtun-" + name, "-keyout", name + ".key", "-out", name + ".csr")
        (directory / (name + ".ext")).write_text(
            "basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\n"
            "extendedKeyUsage=" + usage + "\n")
        openssl(directory, "x509", "-req", "-in", name + ".csr", "-CA", "ca.pem", "-CAkey", "ca.key",
                "-CAcreateserial", "-days", "2", "-extfile", name + ".ext", "-out", name + ".pem")

    (directory / "server.conf").write_text(
        "dev xtun-ovpn-test\ndev-type tun\nproto udp4\nlocal 127.0.0.1\nport 21194\n"
        "topology subnet\nserver 10.8.0.0 255.255.255.0\ndh none\n"
        "ca ca.pem\ncert server.pem\nkey server.key\n"
        "data-ciphers AES-256-GCM:AES-128-GCM\ntun-mtu 1400\n"
        'push "tun-mtu 1400"\npush "route 10.9.0.0 255.255.255.0"\n'
        'push "dhcp-option DNS 10.8.0.1"\nkeepalive 10 60\nverb 0\n')
    ca = (directory / "ca.pem").read_text()
    cert = (directory / "client.pem").read_text()
    key = (directory / "client.key").read_text()
    (directory / "client.ovpn").write_text(
        "client\ndev tun\nproto udp4\nremote 127.0.0.1 21194\nremote-cert-tls server\n"
        "connect-timeout 2\nserver-poll-timeout 3\n"
        "route 10.8.0.0 255.255.255.0\nroute 198.51.100.0 255.255.255.0\n"
        "dhcp-option DNS 192.0.2.53\n"
        f"<ca>\n{ca}</ca>\n<cert>\n{cert}</cert>\n<key>\n{key}</key>\n")


def bind_echo(server, echo):
    # The VPN-side address becomes available after OpenVPN configures its TUN.
    deadline = time.monotonic() + 15
    while True:
        if server.poll() is not None:
            raise RuntimeError("The local OpenVPN server stopped during startup")
        try:
            echo.bind(("10.8.0.1", 19080))
            return
        except OSError as error:
            if error.errno != errno.EADDRNOTAVAIL:
                raise
            if time.monotonic() >= deadline:
                raise RuntimeError("The local OpenVPN server did not configure 10.8.0.1") from error
            time.sleep(0.05)


def run_tests(openvpn, executable, arguments):
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
    with tempfile.TemporaryDirectory(prefix="xtun-ovpn-session-") as scratch:
        directory = Path(scratch)
        prepare_profiles(directory)
        processes = []
        try:
            # Output goes to the caller's console; no log files are created.
            server = subprocess.Popen([openvpn, "--config", "server.conf"], cwd=directory)
            processes.append(server)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as echo_socket:
                bind_echo(server, echo_socket)
                echo = subprocess.Popen([sys.executable, str(Path(__file__).resolve()),
                                         "--echo", str(echo_socket.fileno())],
                                        pass_fds=(echo_socket.fileno(),))
                processes.append(echo)
                result = subprocess.run([executable, "--ovpn-server-ready", *arguments], cwd=directory)
                if server.poll() is not None or echo.poll() is not None:
                    raise RuntimeError("The local OpenVPN or UDP echo server stopped during the tests")
                return result.returncode
        finally:
            for process in reversed(processes):
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()


def main():
    arguments = sys.argv[1:]
    if len(arguments) < 2:
        raise RuntimeError("Usage: ovpn_server.py <openvpn executable> <test executable> [test arguments]")
    if arguments[0] == "--echo":
        with socket.socket(fileno=int(arguments[1])) as echo:
            while True:
                packet, peer = echo.recvfrom(65535)
                echo.sendto(packet, peer)

    if arguments[0] != "--in-netns":
        if os.geteuid() != 0:
            print("OvpnSession requires root to create a network namespace and TUN; run sudo ctest.",
                  file=sys.stderr)
            return 77
        # Enter the namespace before starting the test executable and its connection threads.
        os.execvp("unshare", ["unshare", "--net", "--", sys.executable,
                             str(Path(__file__).resolve()), "--in-netns", *arguments])
    return run_tests(arguments[1], arguments[2], arguments[3:])


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuntimeError, subprocess.CalledProcessError) as error:
        print(error, file=sys.stderr)
        if isinstance(error, subprocess.CalledProcessError) and error.stderr:
            print(error.stderr, file=sys.stderr)
        sys.exit(1)
