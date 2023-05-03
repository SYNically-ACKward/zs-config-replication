# flake8: noqa
import timeit
import time

def obfuscateApiKey(apikey):
    seed = apikey
    now = int(time.time() * 1000)
    n = str(now)[-6:]
    r = str(int(n) >> 1).zfill(6)
    key = ""

    for digit in n:
        key += seed[int(digit)]

    for digit in r:
        key += seed[int(digit) + 2]

    return now, key


def original_obfuscateApiKey(apikey):
    seed = apikey
    now = int(time.time() * 1000)
    n = str(now)[-6:]
    r = str(int(n) >> 1).zfill(6)
    key = ""
    for i in range(0, len(str(n)), 1):
        key += seed[int(str(n)[i])]
    for j in range(0, len(str(r)), 1):
        key += seed[int(str(r)[j])+2]

    return now, key

# time the refactored function
refactored_time = timeit.timeit(lambda: obfuscateApiKey('apikey'), number=100000)

# time the original function
original_time = timeit.timeit(lambda: original_obfuscateApiKey('apikey'), number=100000)

print(f"Refactored time: {refactored_time}")
print(f"Original time: {original_time}")
