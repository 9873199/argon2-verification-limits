import pytest
from argon2 import PasswordHasher, VerificationLimits
from argon2.low_level import Type, hash_secret
from argon2.exceptions import InvalidHashError, VerificationLimitExceeded, VerifyMismatchError
import argon2._password_hasher as implementation

FIELDS=['hash_length','memory_cost','time_cost','parallelism','work','salt_length','hash_bytes_length']
@pytest.mark.parametrize('field',FIELDS)
@pytest.mark.parametrize('value',[True,False,0,-1,1.5,'1'])
def test_policy_rejects_non_positive_integers(field,value):
    with pytest.raises((ValueError,TypeError)): VerificationLimits(**{field:value})

def encoded(kind=Type.ID,version=19,p=1):
    return hash_secret(b'local-example-password',b'12345678',time_cost=1,memory_cost=32,parallelism=p,hash_len=16,type=kind,version=version)

@pytest.mark.parametrize('kind',[Type.I,Type.D,Type.ID])
@pytest.mark.parametrize('version',[16,19])
def test_real_low_cost_variants_and_mismatch(kind,version):
    data=encoded(kind,version)
    hasher=PasswordHasher(verification_limits=VerificationLimits(hash_length=len(data),memory_cost=32,time_cost=1,parallelism=1,work=32,salt_length=8,hash_bytes_length=16))
    assert hasher.verify(data,b'local-example-password') is True
    with pytest.raises(VerifyMismatchError): hasher.verify(data,b'wrong-password')

@pytest.mark.parametrize('field,value',[('hash_length',10),('memory_cost',31),('time_cost',1),('parallelism',1),('work',31),('salt_length',7),('hash_bytes_length',15)])
def test_rejection_precedes_native_computation(monkeypatch,field,value):
    data=encoded(p=2) if field=='parallelism' else encoded()
    if field=='time_cost': data=data.replace(b't=1',b't=2')
    calls=[]
    def forbidden(*args): calls.append(True);raise AssertionError('native verification must not run')
    monkeypatch.setattr(implementation,'verify_secret',forbidden)
    hasher=PasswordHasher(verification_limits=VerificationLimits(**{field:value}))
    with pytest.raises(VerificationLimitExceeded) as error: hasher.verify(data,b'private-example-password')
    assert calls==[]
    assert data.decode() not in str(error.value) and 'private-example-password' not in str(error.value)

BAD=[
 lambda x:x.replace(b'm=32,t=1,p=1',b'm=32,m=32,t=1,p=1'),
 lambda x:x.replace(b'v=19',b'v=999'),
 lambda x:x.replace(b'm=32',b'm='+b'9'*20000),
 lambda x:x.replace(b'$MTIzNDU2Nzg$',b'$*$'),
 lambda x:x.rsplit(b'$',1)[0]+b'$A',
 lambda x:x.replace(b't=1',b't=0'),
 lambda x:x.replace(b'p=1',b'p=0'),
 lambda x:x.replace(b'm=32',b'm=0'),
]
@pytest.mark.parametrize('mutate',BAD,ids=['duplicate','version','long-decimal','base64','truncated','zero-time','zero-lanes','zero-memory'])
def test_malformed_rejected_before_native(monkeypatch,mutate):
    data=mutate(encoded());calls=[]
    def forbidden(*args):calls.append(True);raise AssertionError('malformed hash reached native verification')
    monkeypatch.setattr(implementation,'verify_secret',forbidden)
    with pytest.raises(InvalidHashError):PasswordHasher(verification_limits=VerificationLimits()).verify(data,b'password')
    assert calls==[]

def test_parallelism_does_not_multiply_total_memory():
    for p in (1,2,4):
        data=encoded(p=p)
        assert PasswordHasher(verification_limits=VerificationLimits(memory_cost=32,parallelism=4,work=32)).verify(data,b'local-example-password')

def test_no_policy_compatibility_and_separate_rehash():
    data=encoded();hasher=PasswordHasher(time_cost=2,memory_cost=32,parallelism=1,hash_len=16,salt_len=8)
    assert hasher.verify(data,b'local-example-password')
    assert hasher.check_needs_rehash(data)

def test_rejection_does_not_change_hasher_or_next_call():
    data=encoded();limits=VerificationLimits(memory_cost=32);hasher=PasswordHasher(verification_limits=limits)
    with pytest.raises(VerificationLimitExceeded):hasher.verify(data.replace(b'm=32',b'm=33'),b'local-example-password')
    assert hasher.verification_limits==limits
    assert hasher.verify(data,b'local-example-password')
