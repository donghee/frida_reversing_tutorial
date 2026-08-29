import os
import sys
import time
import frida

TARGET = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else "./main")
SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "hook.js")


def on_message(message, data):
    if message["type"] == "send":
        print(message["payload"])
    elif message["type"] == "error":
        print("[frida error]", message.get("stack", message))
    else:
        print("[frida]", message)


def main():
    pid = frida.spawn([TARGET])
    session = frida.attach(pid)
    with open(SCRIPT) as f:
        script = session.create_script(f.read())
    script.on("message", on_message)
    script.load()
    frida.resume(pid)

    try:
        _, status = os.waitpid(pid, 0)
        print(f"[*] target exited, status={status}")
    except ChildProcessError:
        time.sleep(0.5)

    session.detach()


if __name__ == "__main__":
    main()
