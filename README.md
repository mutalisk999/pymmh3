# pymmh3

### about pymmh3


pymmh3 is a pure python implementation of the murmur3 hash algorithm.

It is a python translation of a cpp implementation from https://github.com/hajimes/mmh3



### how to use

    >>> import pymmh3
    >>> pymmh3.hash(key="123456789", seed=40)
    497144878
    
    >>> pymmh3.hash64(key="123456789", seed=40, x64arch=False)
    (16478360541244280935, 1458075901387315304)
    
    >>> pymmh3.hash64(key="123456789", seed=40, x64arch=True)
    (17601866768076350022, 16834372491614140661)
    
    >>> pymmh3.hash128(key="123456789", seed=40, x64arch=False)
    26896752992935171190002579949099012199
    
    >>> pymmh3.hash128(key="123456789", seed=40, x64arch=True)
    310539360994302247664662678975540208198