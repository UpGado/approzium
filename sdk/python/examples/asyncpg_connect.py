import asyncio

from approzium import AuthClient
from approzium.asyncpg import connect
from approzium.asyncpg.pool import create_pool

auth = AuthClient(
    "authenticator:6001",
    # This is insecure, see https://approzium.org/configuration for proper use.
    disable_tls=True,
)


async def run():
    conn = await connect(user="bob", database="db", host="dbmd5", authenticator=auth)
    print("Connection Established!")
    await conn.fetch("""SELECT 1""")
    await conn.close()

    pool = await create_pool(
        user="bob", database="db", host="dbmd5", authenticator=auth
    )
    print("Connection Established!")
    async with pool.acquire() as conn:
        await conn.fetch("""SELECT 1""")


loop = asyncio.get_event_loop()
loop.run_until_complete(run())
