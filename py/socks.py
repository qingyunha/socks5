import asyncio
import logging
import socket


logger = logging.getLogger("socks")


async def socks_server(reader, writer):
    try:
        version = await reader.readexactly(1)
        if version[0] != 0x05:
            logger.info("version not match")
            return

        nmethods = await reader.readexactly(1)
        nmethods = nmethods[0]
        if nmethods > 5:
            logger.info("too many conn mehtods")
            return

        methods = await reader.readexactly(nmethods)
        noauth = False
        for m in methods:
            if m == 0:
                noauth = True

        if not noauth:
            logger.info("only support no auth")
            writer.write(b"\x05\xff")
            await writer.drain()
            return
        writer.write(b"\x05\x00")
        await writer.drain()

        # read request
        version = await reader.readexactly(1)
        if version[0] != 0x05:
            logger.info("version not match")
            return

        cmd = await reader.readexactly(1)
        cmd = cmd[0]
        if cmd < 0x01 or cmd > 0x03:
            logger.info("unknown command")
            return
        if cmd != 0x01:
            logger.info("only support connect command")

        # ignore RSV
        await reader.readexactly(1)

        atype = await reader.readexactly(1)
        atype = atype[0]
        if atype not in (0x01, 0x03, 0x04):
            logger.info("unknown atype %d", atype)

        if atype == 0x01:
            dst_ip = await reader.readexactly(4)
            dst_host = socket.inet_ntoa(dst_ip)
        elif atype == 0x03:
            length = await reader.readexactly(1)
            length = length[0]
            dst_host = await reader.readexactly(length)
        else:
            logger.info("no support ipv6")
            return

        dst_port = await reader.readexactly(2)
        dst_port = (dst_port[0] << 8) + dst_port[1]
        logger.info("connect to %s %d", dst_host, dst_port)
        dreader, dwriter = await asyncio.open_connection(dst_host, dst_port)
        host, port = dwriter.get_extra_info('sockname')
        if len(host.split(".")) != 4:
            logger.info("local address not ipv4: %s", host)
        writer.writelines((
            b'\x05\x00\x00\x01',
            socket.inet_aton(host),
            port.to_bytes(2, "big"),
        ))
        await writer.drain()

        await asyncio.gather(
            iocopy(dwriter, reader),
            iocopy(writer, dreader)
        )

    finally:
        writer.close()
        await writer.wait_closed()


async def iocopy(writer, reader):
    while True:
        data = await reader.read(1500)
        if not data:
            break
        writer.write(data)
        await writer.drain()
    writer.close()
    await writer.wait_closed()



async def main():
	server = await asyncio.start_server(socks_server, '0.0.0.0', 1080)

	addr = server.sockets[0].getsockname()
	logger.info(f'Serving on {addr}')

	async with server:
		await server.serve_forever()


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    asyncio.run(main())
