import asyncio
import sca
import sca_docker

async def main():
    # try:
    #     await sca.open_connection()
    #     print("connection OK")
    # except:
    #     print("connection FAILED")

    try:
        await sca_docker.open_connection()
        print("connection OK")
    except:
        print("connection FAILED")

asyncio.run(main())