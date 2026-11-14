from argon2 import PasswordHasher, VerificationLimits
from argon2.exceptions import VerifyMismatchError, VerificationLimitExceeded
import argon2._password_hasher as native

password=b'local-demo-password'
producer=PasswordHasher(time_cost=1,memory_cost=32,parallelism=1,hash_len=16,salt_len=8)
encoded=producer.hash(password)
policy=VerificationLimits(hash_length=256,memory_cost=32,time_cost=2,parallelism=2,work=64,salt_length=8,hash_bytes_length=16)
verifier=PasswordHasher(verification_limits=policy)
print('Password import verification')
print('Memory: 32 KiB; iterations: 1; lanes: 1')
print('Correct password accepted:',verifier.verify(encoded,password))
try:verifier.verify(encoded,b'incorrect-example')
except VerifyMismatchError:print('Incorrect password: rejected as mismatch')
original=native.verify_secret;calls=[]
def count_native(*args,**kwargs):
    calls.append(True)
    raise AssertionError('Expensive verification must not start')
native.verify_secret=count_native
try:
    excessive=encoded.replace('m=32','m=1048576')
    try:verifier.verify(excessive,password)
    except VerificationLimitExceeded:print('Excessive memory request: blocked by policy')
    print('Native calls for blocked request:',len(calls))
    assert calls==[]
finally:native.verify_secret=original
print('Next allowed verification accepted:',verifier.verify(encoded,password))
print('Rehash decision still separate:',verifier.check_needs_rehash(encoded))
