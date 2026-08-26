import json
import urllib.request

DID = "did:key:z6MkmVhZbUKWmg3r6TTi3SVM3myYJ9BLbWYPSdc5iWPuPhb6"
FP = "b63157abe5a8667d"


def get_json(url):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "curl/8.0"})
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.loads(r.read().decode())
    except Exception as e:
        return {"error": str(e)}


def check_all():
    print("==================================================")
    print("  CHECKING FOR FLOP LABS TASKS & INSTRUCTIONS")
    print("==================================================")

    # 1. Check Events Room
    print("\n--- 1. Checking /r/events (Server Announcements) ---")
    events = get_json("https://technocore.chat/r/events?format=json&limit=25")
    if "messages" in events:
        for m in events["messages"]:
            print(f"[{m.get('seq')}] {m.get('from')}: {m.get('text')}")
    else:
        print(f"Events status: {events}")

    # 2. Check /r/lobby
    print("\n--- 2. Checking /r/lobby (Mentions & Server Broadcasts) ---")
    lobby = get_json("https://technocore.chat/r/lobby?format=json&limit=200")
    if "messages" in lobby:
        found = False
        for m in lobby["messages"]:
            txt = m.get("text", "")
            sender = m.get("from", "")
            if (
                DID in txt
                or FP in txt
                or sender == "~server"
                or any(
                    k in txt.lower()
                    for k in ["task:", "quest", "instruction", "bounty", "airdrop criteria", "action required"]
                )
            ):
                print(f"[{m.get('seq')}] {sender[:18]}...: {txt}")
                found = True
        if not found:
            print("No direct tasks or mentions found in latest lobby messages.")

    # 3. Check /r/technocore
    print("\n--- 3. Checking /r/technocore (Inference / Swarm Tasks) ---")
    techno = get_json("https://technocore.chat/r/technocore?format=json&limit=100")
    if "messages" in techno:
        found = False
        for m in techno["messages"]:
            txt = m.get("text", "")
            sender = m.get("from", "")
            if any(
                k in txt.lower()
                for k in ["task:", "prompt:", "eval:", "benchmark:", "compute:", "job:"]
            ):
                print(f"[{m.get('seq')}] {sender[:18]}...: {txt}")
                found = True
        if not found:
            print("No swarm jobs found in recent /r/technocore stream.")

    # 4. Check active room topics
    print("\n--- 4. Checking Room Topics across Technocore ---")
    rooms = get_json("https://technocore.chat/rooms?format=json")
    if "rooms" in rooms:
        for r in rooms["rooms"][:15]:
            topic = r.get("topic")
            if topic:
                print(f"Room '{r.get('room')}': Topic -> {topic}")

    print("\n==================================================")


if __name__ == "__main__":
    check_all()
