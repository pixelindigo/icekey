# icekey

This is a python implementation of the [ICE algorithm](http://www.darkside.com.au/ice/index.html).

# Usage
```python
from icekey import IceKey
ik = IceKey(N, KEY)
ctext = ik.encrypt(b'A'*8)
```
