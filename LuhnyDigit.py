# LuhnyDigit - Luhn Check Digit Generator Payload Processor for Burp Suite
#
# How to use:
# - Load the extension in Burp Suite (make sure the Jython runtime works first).
# - In Intruder, mark a numeric field and choose Sniper attack.
# - In the Payloads tab, select the Payload type = Numbers then specify the
#   sequence in the From/To field and strip the check digit if it was already
#   included. i.e. if the original value was 8003, use 800 to e.g. 899
# - Under Payload Processing, add a processor and select Invoke Burp Extension.
# - Select LuhnyDigit
# - Launch the attack. Values between 8003 to 8995 will be generated ('3' and '5'
#   are the check digit that is automatically appended to the value).
#
# Author: Alexandre Hamelin <alexandre.hamelin gmail.com>

from array import array
from burp import IBurpExtender, IExtensionStateListener, IIntruderPayloadProcessor



class BurpExtender(IBurpExtender, IExtensionStateListener, IIntruderPayloadProcessor):
    def registerExtenderCallbacks(self, callbacks):
        callbacks.setExtensionName('LuhnyDigit');
        self._callbacks = callbacks
        self._stdout = callbacks.getStdout()
        self._stderr = callbacks.getStderr()
        self._helpers = callbacks.getHelpers()
        self.printOutput = callbacks.printOutput
        self.printError = callbacks.printError

        callbacks.registerExtensionStateListener(self);
        callbacks.registerIntruderPayloadProcessor(self)

        return

    # IExtensionStateListener

    def extensionUnloaded(self):
        pass

    # IIntruderPayloadProcessor

    def getProcessorName(self):
        return 'LuhnyDigit'

    def processPayload(self, currentPayload, originalPayload, baseValue):
        """Append the check digit to the current payload (e.g. '31' -> '315')"""
        payload = currentPayload.tostring()     # from array.array('b',[]) to str
        if all(['0' <= a <= '9' for a in payload]):
            # convert back to byte array
            return array('b', payload + str(calculate_luhn_digit(payload)))
        return None

        
def calculate_luhn_digit(number):
    """number: a numeric string without any punctuation
    returns: an integer between 0 and 9 (int type)
    """
    return (10 - sum(d if i & 1                         # use digit as is
                     else (d * 2 if d < 5               # double the number if in even position
                           else d * 2 - 9)              # subtract 9 if above 10
                     for i, d in map(
                        lambda e: (e[0], int(e[1])),    # convert str to int
                        enumerate(number[::-1]))        # iterate through digits in reverse
                     )) % 10
