import asyncio
import os

print("PID:", os.getpid())

async def handle(reader, writer):
    await reader.read(1024)
    writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
    await writer.drain()
    writer.close()

async def main():
    server = await asyncio.start_server(handle, '127.0.0.1', 8001)
    print("Asyncio server listening on 8001")
    async with server:
        await server.serve_forever()

asyncio.run(main())