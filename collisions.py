import siphash

htsize = 2**16


def callhash(hashkey, inval):
    return siphash.SipHash_2_4(hashkey, inval).hash()


def ht_hash(hashkey, inval, htsize):
    return callhash(hashkey, inval) % htsize


# Put your collision-finding code here.
# Your function should output the colliding strings in a list.
def find_collisions(hash_key):

    def randomString(stringLength):
        import random
        """Generate a random string of fixed length """
        letters = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
        return ''.join(random.choice(letters) for i in range(stringLength))

    col_strings = []
    target_hash = 0
    while len(col_strings) < 20:
        try_str = randomString(stringLength=5)
        if try_str in col_strings:
            continue
        if ht_hash(hash_key, try_str.encode("utf8"), htsize) == target_hash:
            col_strings.append(try_str)
            print(try_str)
    return col_strings

# Implement this function, which takes the list of
# collisions and verifies they all have the same
# SipHash output under the given key.
def check_collisions(hashkey, colls):

    assert(len(colls) == 20)
    hash_results = [ht_hash(hashkey, c.encode("utf8"), htsize) for c in colls]
    assert(set(hash_results) == 1)
    return



if __name__=='__main__':
    # Look in the source code of the app to
    # find the key used for hashing.
    hash_key = b'\x00'*16
    colls = find_collisions(hash_key)
    check_collisions(hash_key, colls)