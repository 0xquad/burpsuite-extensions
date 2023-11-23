# Extension template file for a Burp Suite Intruder Payload Generator
#
# How to use:
# - TODO...
#
# Copyright (c) 2023, Alexandre Hamelin <alex@synlabs.co>
#
# Distributed under the Apache 2.0 License.


from array import array     # convert strings <-> byte arrays
from burp import (
    IBurpExtender, IExtensionStateListener, IIntruderPayloadGeneratorFactory,
    IIntruderPayloadGenerator
)
#import thirdparty
#from thirdparty import symbol


EXT_NAME = 'MyExtension'


# basic tutorial: https://portswigger.net/burp/extender/writing-your-first-burp-suite-extension
# callbacks ref:
# https://github.com/PortSwigger/burp-extender-api/blob/master/src/main/java/burp/IBurpExtenderCallbacks.java

# pseudo code of how Burp calls a payload generator:
'''
void processIntruderAttack(IIntruderAttack attack) {

    placeholders[] = attack.getPayloadPlaceholders();
    
    // for a sniper attack (i.e. iterate through all payloads, for each placeholder in turn)
    
    IIntruderPayloadGeneratorFactory factory;
    IIntruderPayloadGenerator generator;
    
    PayloadType payloadType = getPayloadType();
    // ...
    if (payloadType == PayloadType.EXTENSION) {
        // initialize the user extension for generating payloads
        factory = getExtensionPayloadGeneratorFactory();
        generator = factory.createNewInstance(attack); // user method
    }
    
    for (Placeholder ph : placeholders) {
        byte[] baseValue = ph.getBaseValue();
        while (generator.hasMorePayloads()) { // user method
            byte[] payload = generator.getNextPayload(baseValue); // user method
            sendRequestUsingPayload(attack, payload);
        }
        g.reset(); // user method (also called for the last placeholder???)
    }
}
'''


class MyGenerator(IIntruderPayloadGenerator):
    def __init__(self, callbacks):
        self._morePayloads = True
        self._generator = None
        self._baseValue = None
        self._nextValue = None
        self._callbacks = callbacks

        self.debug = False
        self.log = self._callbacks.printOutput if self.debug else lambda x: None
        self.log('Generator initialized')


    def hasMorePayloads(self):
        self.log('g.hasMorePayloads: more={}, g={}, nextvalue={}'.format(
            self._morePayloads, self._generator, self._nextValue))
        if self._generator is None:
            # special case on first call, not initialized with base value yet;
            # i.e. we don't know what the base value is yet, which is only
            # known when getNextPayload() is called a first time
            return True

        # If initialized, check for the next value using the internal generator
        # and queue the value for the next getNextPayload() call
        try:
            self._nextValue = next(self._generator)
            self.log('queued next value to return = ' + str(self._nextValue))
        except StopIteration:
            self._morePayloads = False
            self.log('no more values!')
        return self._morePayloads


    def __iter__(self):
        # Called from getNextPayload() on its first call only; return
        # a generator to Burp, one that will sequentially return payloads
        # This method is only needed if using a custom iterator to generate
        # values; otherwise the generator/iterator can be assigned directly
        # from getNextPayload() below.
        self.log('g.iter initialized with ' + str(self._baseValue))
        
        # example: return the base value (already set by the first call
        # to getNextPayload())
        # use `yield` to return a generator object (not the value itself!)
        yield self._baseValue


    def getNextPayload(self, baseValue):
        # This method is called sequentially by Burp to return each generated
        # payload. The base value is always passed as an argument, no matter if
        # this is the first call to this function or any other subsequent call.
        # It could be ignored if the generated values are not based on that
        # initial value. Otherwise it should be 'remembered' on the first call
        # so that successive calls are able to generate more payloads by
        # transforming the initial value.

        self.log('g.getnext: basevalue={}, g={}'.format(baseValue.tostring(), self._generator))

        if self._generator is None:
            # special case on first call: initialize the generator/iterator

            # case 1: if using this class as a generator/iterator
            # (i.e. using self.__iter__ above), then we need to remember
            # the initial value for __iter__ to use it
            self._baseValue = baseValue.tostring()
            self._generator = iter(self)

            # case 2: if using another kind of generator/iterator, no need to
            # remember the base value; just initialize the g/i here
            #self._generator = iter([c for c in baseValue]) # for example

            return next(self._generator) # return the first value immediately
        return self._nextValue # otherwise, return the one that was queued
        # return values should always be as bytes


    def reset(self):
        self.log('g.reset')
        self._morePayloads = True
        self._generator = None
        self._nextValue = None
        self._baseValue = None


class MyGeneratorFactory(object):
    def __init__(self, callbacks):
        self._callbacks = callbacks


    def getGeneratorName(self):
        return EXT_NAME


    def createNewInstance(self, intruderAttack):
        # return a IIntruderPayloadGenerator object
        # intruderAttack is a IIntruderAttack object
        g = MyGenerator(self._callbacks)
        return g


class BurpExtender(IBurpExtender, IExtensionStateListener):
    def registerExtenderCallbacks(self, callbacks):
        callbacks.setExtensionName(EXT_NAME);
        self._callbacks = callbacks
        self._stdout = callbacks.getStdout()
        self._stderr = callbacks.getStderr()
        self._helpers = callbacks.getHelpers()
        self.printOutput = callbacks.printOutput
        self.printError = callbacks.printError

        callbacks.registerExtensionStateListener(self);

        factory = MyGeneratorFactory(callbacks)
        callbacks.registerIntruderPayloadGeneratorFactory(factory)

        """
        some helpers methods:
        ----------------
        int indexOf (byte[] data, byte[] pattern, boolean caseSensitive, int from, int to);
        String bytesToString(byte[] data);
        byte[] stringToBytes(String data);
        String urlDecode(String data);
        String urlEncode(String data);
        byte[] urlDecode(byte[] data);
        byte[] urlEncode(byte[] data);
        byte[] base64Decode(String data);
        byte[] base64Decode(byte[] data);
        String base64Encode(String data);
        String base64Encode(byte[] data);
        
        or use array.array('b', 'mystr') to convert to a byte array
        and array.array('b', []).tostring() to convert to a string
        """

        return


    # IExtensionStateListener

    def extensionUnloaded(self):
        pass
