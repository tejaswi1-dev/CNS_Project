import asyncio
import json
import ssl
import websockets

STORAGE_FILE = "storage.json"

async def handler(ws):
    async for msg in ws:
        db = json.loads(msg)
        # Store encrypted database (ciphertext + signatures)
        with open(STORAGE_FILE, "w") as f:
            json.dump(db, f)
        await ws.send(json.dumps({"status": "ok"}))
        print("[+] Received and stored encrypted data")

sslctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
sslctx.load_cert_chain(certfile="server.crt", keyfile="server.key")

start_server = websockets.serve(handler, "0.0.0.0", 8765, ssl=sslctx)
print("[Server] Listening on wss://localhost:8765")
asyncio.get_event_loop().run_until_complete(start_server)
asyncio.get_event_loop().run_forever()
