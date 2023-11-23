# Reyield - A regular expression-based payload generator extension for Burp Suite
#
# How to use:
# - Have Jython working in Burp
# - Select a folder to load third-party Python2 modules
# - Download a copy of https://github.com/0xquad/sre-yield (branch "py2")
# - Add the module sre_yield to the configured folder so that Jython recognizes it
# - Load this extension in Burp
# - In Intruder, use the Sniper Attack (others have issues)
# - Add markers and replace the inner text by a regular expression
# - Select the payload type to be Extension Generated
# - Select the Reyield extension
# - Launch the attack
#
# Copyright (c) 2023, Alexandre Hamelin <alex@synlabs.co>
#
# Distributed under the Apache 2.0 License.

from array import array
from burp import (
    IBurpExtender, IExtensionStateListener, IIntruderPayloadGeneratorFactory,
    IIntruderPayloadGenerator
)
import sre_yield


EXT_NAME = 'Reyield'

class RegexStringsGenerator(IIntruderPayloadGenerator):
    def __init__(self, callbacks):
        self._morePayloads = True
        self._generator = None
        self._nextValue = None
        self._callbacks = callbacks

        self.debug = True
        self.log = self._callbacks.printOutput if self.debug else lambda x: None
        self.log('Generator initialized')


    def hasMorePayloads(self):
        self.log('g.hasMorePayloads: more={}, g={}, nextvalue={}'.format(
            self._morePayloads, self._generator, self._nextValue))
        if self._generator is None:
            # special case on first call
            # has not been initialized with the base value yet
            return True

        try:
            self._nextValue = next(self._generator)
            self.log('queued next value to return = ' + str(self._nextValue))
        except StopIteration:
            self._morePayloads = False
            self.log('no next value!')
        return self._morePayloads


    def getNextPayload(self, baseValue):
        self.log('g.getnext: basevalue={}, g={}'.format(baseValue.tostring(), self._generator))
        if self._generator is None:
            self._generator = iter(sre_yield.AllStrings(baseValue.tostring()))
            return next(self._generator) # return the first value immediately
        return self._nextValue # otherwise, return the one that was queued


    def reset(self):
        self.log('g.reset')
        self._morePayloads = True
        self._generator = None
        self._nextValue = None


class RegexStringsGeneratorFactory(IIntruderPayloadGeneratorFactory):
    def __init__(self, callbacks):
        self._callbacks = callbacks

    def getGeneratorName(self):
        return EXT_NAME

    def createNewInstance(self, intruderAttack):
        # return a IIntruderPayloadGenerator object
        # intruderAttack is a IIntruderAttack object
        g = RegexStringsGenerator(self._callbacks)
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

        factory = RegexStringsGeneratorFactory(callbacks)
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
