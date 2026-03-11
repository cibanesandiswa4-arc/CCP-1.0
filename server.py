import socket, threading
from datetime import datetime
from colorama import Fore, init
from protocol import receive_message, build_response
from session_manager import SessionManager
import database

database.init_db()
init(autoreset=True)

TCP_PORT = 12345
UDP_PORT = 12346
BUFFER_SIZE = 4096
sessions = SessionManager()
sessions.groups = {}

def timestamp():
    return datetime.now().strftime("[%H:%M:%S]")

def handle_udp():
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(('0.0.0.0', UDP_PORT))
    print(Fore.CYAN + f"{timestamp()} [SERVER] UDP running {UDP_PORT}")
    while True:
        data, addr = udp.recvfrom(BUFFER_SIZE)
        msg = data.decode()
        print(Fore.YELLOW + f"{timestamp()} [UDP] {addr}: {msg}")
        for u,(s,up,_) in sessions.active_users.items():
            ip = s.getpeername()[0]
            if up and (ip, up) != addr:
                udp.sendto(data, (ip, up))

def handle_client(sock):
    user = "?"
    try:
        login = receive_message(sock)
        if not login or "CMD LOGIN" not in login:
            sock.close(); return
        user = [l.split(":")[1].strip() for l in login.split("\r\n") if l.startswith("From:")][0]
        password = login.split("\r\n\r\n")[-1].strip()
        if not database.verify_or_create_user(user, password):
            sock.sendall(build_response("CTRL ERROR CCP/1.0", "AUTH_FAILED").encode())
            sock.close(); return
        sock.sendall(f"CTRL ACK CCP/1.0\r\nTo: {user}\r\nSeq: 1\r\nLength: 0\r\n\r\n".encode())
        print(Fore.GREEN + f"{timestamp()} [LOGIN] {user}")

        reg = receive_message(sock)
        udp_line = [l for l in reg.split("\r\n") if "UDP-Port" in l][0]
        p2p_line = [l for l in reg.split("\r\n") if "P2P-Port" in l][0]
        up, pp = int(udp_line.split(":")[1]), int(p2p_line.split(":")[1])
        sessions.active_users[user] = (sock, up, pp)

        while True:
            msg = receive_message(sock)
            if not msg:
                break

            # join / leave groups store in DB
            if "CMD JOIN_GROUP" in msg:
                g = msg.split("To:")[1].split("\r\n")[0].strip()
                database.add_to_group(user, g)
                sock.sendall(build_response("CTRL ACK CCP/1.0", f"Joined {g}").encode())
                print(Fore.MAGENTA + f"{timestamp()} [GROUP] {user} joined {g}")
            elif "CMD LEAVE_GROUP" in msg:
                g = msg.split("To:")[1].split("\r\n")[0].strip()
                database.remove_from_group(user, g)
                sock.sendall(build_response("CTRL ACK CCP/1.0", f"Left {g}").encode())
                print(Fore.MAGENTA + f"{timestamp()} [GROUP] {user} left {g}")
            elif "CMD LIST_USERS" in msg:
                names = "\n".join(sessions.active_users.keys())
                resp = f"CTRL USERS_LIST CCP/1.0\r\nTo: {user}\r\nLength: {len(names)}\r\n\r\n{names}"
                sock.sendall(resp.encode())
            elif "CMD LIST_GROUPS" in msg:
                groups = database.get_group_memberships(user)
                glist = "\n".join(groups) if groups else "(no groups)"
                reply = f"CTRL GROUPS_LIST CCP/1.0\r\nTo: {user}\r\nLength: {len(glist)}\r\n\r\n{glist}"
                sock.sendall(reply.encode())
            elif "CMD FILE_REQUEST" in msg:
                sender = user
                tgt = msg.split("To:")[1].split("\r\n")[0].strip()
                fname = msg.split("\r\n\r\n")[-1].strip()
                if tgt in sessions.active_users:
                    t_sock,_,p2p_p = sessions.active_users[tgt]
                    t_sock.sendall(f"CTRL FILE_REQUEST CCP/1.0\r\nFrom: {sender}\r\nTo: {tgt}\r\nLength: {len(fname)}\r\n\r\n{fname}".encode())
                    ip = t_sock.getpeername()[0]
                    auth = build_response("CTRL FILE_AUTH CCP/1.0", f"{ip} {p2p_p}")
                    sock.sendall(auth.encode())
                else:
                    sock.sendall(build_response("CTRL ERROR CCP/1.0", "USER_OFFLINE").encode())
            elif "CMD WHOIS" in msg:
                tgt = msg.split("To:")[1].split("\r\n")[0].strip()
                info, groups = database.get_user_info(tgt)
                if not info:
                    res = f"User '{tgt}' not found."
                else:
                    online = tgt in sessions.active_users
                    res = (f"User: {tgt}\nStatus: {'Online' if online else 'Offline'}"
                           f"\nGroups: {', '.join(groups) if groups else 'None'}"
                           f"\nLast login: {info[1]}\nLocation: {info[2]}")
                reply = f"CTRL WHOIS CCP/1.0\r\nTo: {user}\r\nLength: {len(res)}\r\n\r\n{res}"
                sock.sendall(reply.encode())
            elif "DATA MESSAGE" in msg:
                to_line = [l for l in msg.split("\r\n") if l.startswith("To:")][0]
                tgt = to_line.split(":")[1].strip()
                if tgt == "ALL":
                    for n,(s,_,_) in sessions.active_users.items():
                        if s != sock: s.sendall(msg.encode())
                else:
                    members = database.get_group_members(tgt)
                    sent = False
                    if members:
                        for m in members:
                            if m in sessions.active_users and m != user:
                                sessions.active_users[m][0].sendall(msg.encode())
                                sent = True
                    if not sent and tgt in sessions.active_users:
                        sessions.active_users[tgt][0].sendall(msg.encode())
    except Exception as e:
        print(Fore.RED + f"{timestamp()} [ERROR] {e}")
    finally:
        if user in sessions.active_users:
            del sessions.active_users[user]
            leave = build_response("CTRL USER_LEFT CCP/1.0", f"{user} left")
            for n,(s,_,_) in sessions.active_users.items():
                s.sendall(leave.encode())

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(('0.0.0.0', TCP_PORT))
server.listen()
print(Fore.CYAN + f"{timestamp()} [SERVER] TCP running {TCP_PORT}")
threading.Thread(target=handle_udp, daemon=True).start()
while True:
    s,a = server.accept()
    print(Fore.GREEN + f"{timestamp()} [CONNECT] {a}")
    threading.Thread(target=handle_client, args=(s,), daemon=True).start()
