# Extension template file for Burp Suite
#
# How to use:
# - TODO...
#
# Author: Alexandre Hamelin <alexandre.hamelin gmail.com>

from array import array
from burp import IBurpExtender, IExtensionStateListener
#from burp import IIntruderPayloadProcessor


# basic tutorial: https://portswigger.net/burp/extender/writing-your-first-burp-suite-extension
# callbacks ref:
# https://github.com/PortSwigger/burp-extender-api/blob/master/src/main/java/burp/IBurpExtenderCallbacks.java


class BurpExtender(IBurpExtender, IExtensionStateListener):
    def registerExtenderCallbacks(self, callbacks):
        callbacks.setExtensionName("Extension Name");
        self._callbacks = callbacks
        self._stdout = callbacks.getStdout()
        self._stderr = callbacks.getStderr()
        self._helpers = callbacks.getHelpers()
        self.printOutput = callbacks.printOutput
        self.printError = callbacks.printError

        callbacks.registerExtensionStateListener(self);

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
