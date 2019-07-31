#
# Transfuzz Extension for PortSwigger Burp Suite
#
# Transform payloads for fuzzing.
#
# How to use:
# 0. Install Jython in Burp Suite and load this extension in Burp Suite.
# 1. In Intruder > Positions, clear all markers and surround one character
#    of payload to test with markers. Choose a Request that usually returns
#    a valid/expected/working response.
# 2. In Intruder > Payloads, select Payload type = Extension generated,
#    and then select this extension.
# 3. Launch the attack.
#
# Note: For fuzzing JSON payloads, disable URL encoding and you might want
# to add these two payload processing rules so that the JSON body does not break.
#   - Match/replace: \\ with \\\\
#   - Match/replace: "  with \\"
#
# Copyright (c) 2019, Alexandre Hamelin <alex@synlabs.co>
#
# Distributed under the Apache 2.0 License.


try:
    from burp import IBurpExtender, IIntruderPayloadGeneratorFactory, IIntruderPayloadGenerator
except ImportError:
    print 'sorry this file must be loaded in Burp Suite'
    raise SystemExit(1)



class FuzzEncodingsGenerator(IIntruderPayloadGenerator):
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
        self.log('g.hasMorePayloads: more={0}, g={1}, nextvalue={2}'.format(
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
        

    def __iter__(self):
        self.log('g.iter initialized with ' + str(self._baseValue))
        def key(name):
            key.count = getattr(key, 'count', 0) + 1
            return '{0:03}'.format(key.count)
        # Ideally we'd use basic transformations and find a nice way to
        # mix/chain/stack them for more flexibility.
        #
        # Chaining could be dumb (\u0041 -> %5c%30%30%34%31)
        # or smarter (\u0041 -> %5cu0041 i.e. not all chars).
        transforms = {
            'url' :             lambda val: ''.join(['%{0:02x}'.format(ord(c)) for c in val]),
            'urlpct' :          lambda val: ''.join(['%%{0:02x}'.format(ord(c)) for c in val]),
            'urluni' :          lambda val: ''.join(['%u{0:04x}'.format(ord(c)) for c in val]),
            'qprint' :          lambda val: ''.join(['={0:02x}'.format(ord(c)) for c in val]),
            'hexexpr' :         lambda val: ''.join(['0x{0:02x}'.format(ord(c)) for c in val]),
            'octexpr' :         lambda val: ''.join(['{0:03o}'.format(ord(c)) for c in val]),
            'hexesc' :          lambda val: ''.join(['\\x{0:02x}'.format(ord(c)) for c in val]),
            'hexescesc' :       lambda val: ''.join(['\\\\x{0:02x}'.format(ord(c)) for c in val]),
            'jsuni' :           lambda val: ''.join(['\\u{0:04x}'.format(ord(c)) for c in val]),
            'jsuniesc' :        lambda val: ''.join(['\\\\u{0:04x}'.format(ord(c)) for c in val]),
            'jsunilong' :       lambda val: ''.join(['\\U{0:08x}'.format(ord(c)) for c in val]),
            'jsunilongesc' :    lambda val: ''.join(['\\\\U{0:08x}'.format(ord(c)) for c in val]),
            'xmlhex' :          lambda val: ''.join(['&#x{0:x};'.format(ord(c)) for c in val]),
            'xmldec' :          lambda val: ''.join(['&#{0};'.format(ord(c)) for c in val]),
            'xmldecamp' :       lambda val: ''.join(['&amp;#{0};'.format(ord(c)) for c in val]),
            'xmldec+url' :      lambda val: ''.join(['%26#{0};'.format(ord(c)) for c in val]),
            'cdata' :           lambda val: '<![CDATA[' + val + ']]>',
            'cdatarev' :        lambda val: ']]>' + val + '<![CDATA[',
            'cdata+xmlhex' :    lambda val: '<![CDATA[' + ''.join(['&#x{0:x};'.format(ord(c)) for c in val]) + ']]>',
            'cdata+url' :       lambda val: '<![CDATA[' + ''.join(['%{0:02x}'.format(ord(c)) for c in val]) + ']]>',
            'cdata+urluni' :    lambda val: '<![CDATA[' + ''.join(['%u{0:04x}'.format(ord(c)) for c in val]) + ']]>',
            'cdata+jsuni' :     lambda val: '<![CDATA[' + ''.join(['\\u{0:04x}'.format(ord(c)) for c in val]) + ']]>',
            'oct' :             lambda val: ''.join(['\\{0:03o};'.format(ord(c)) for c in val]),
            'octesc' :          lambda val: ''.join(['\\\\{0:03o};'.format(ord(c)) for c in val]),
            'url+url' :         lambda val: ''.join(['%25{0:02x};'.format(ord(c)) for c in val]),
            'chrplus' :         lambda val: ''.join(['+chr({0})+'.format(ord(c)) for c in val]),
            'chrdot' :          lambda val: ''.join(['.chr({0}).'.format(ord(c)) for c in val]),
            key('str') :        lambda val: '"+"' + val + '"+"',
            key('str') :        lambda val: "'+'" + val + "'+'",
            key('str') :        lambda val: '"' + val + '"',
            key('str') :        lambda val: "'" + val + "'",
            key('str') :        lambda val: '`' + val + '`',
            key('str') :        lambda val: '/' + val + '/',
            key('tmpl') :       lambda val: '{{"' + val + '"}}',
            key('tmpl') :       lambda val: '${{"' + val + '"}}',
            key('tmpl') :       lambda val: '{{$"' + val + '"}}',
            key('tmpl') :       lambda val: '`${"' + val + '"}`',
            key('tmpl') :       lambda val: '{"' + val + '"}',
            key('tmpl') :       lambda val: '${"' + val + '"}',
            key('tmpl') :       lambda val: '{$"' + val + '"}',
            key('tmpl') :       lambda val: '[["' + val + '"]]',
            key('tmpl') :       lambda val: '$[["' + val + '"]]',
            key('tmpl') :       lambda val: '$["' + val + '"]',
            key('tmpl') :       lambda val: '<%="' + val + '"%>',
            key('tmpl') :       lambda val: '<@="' + val + '"@>',
            key('tmpl') :       lambda val: '<!="' + val + '"!>',
            key('tmpl') :       lambda val: '<#="' + val + '"#>',
            key('tmpl') :       lambda val: '<?="' + val + '"?>',
            key('tmpl') :       lambda val: '@{' + val + '}',
            key('tmpl') :       lambda val: '@{"' + val + '"}',
            key('tmpl') :       lambda val: '@{{' + val + '}}',
            key('tmpl') :       lambda val: '@{{"' + val + '"}}',
            key('tmpl') :       lambda val: '{#' + val + '#}',
            key('tmpl') :       lambda val: '{#=' + val + '#}',
            key('tmpl') :       lambda val: '{#"' + val + '"#}',
            key('tmpl') :       lambda val: '{#="' + val + '"#}',
            key('tmpl') :       lambda val: '{%' + val + '%}',
            key('tmpl') :       lambda val: '{%=' + val + '%}',
            key('tmpl') :       lambda val: '{%"' + val + '"%}',
            key('tmpl') :       lambda val: '{%="' + val + '"%}',
            key('tmpl') :       lambda val: '##' + val + '##',
            key('tmpl') :       lambda val: '@@' + val + '@@',
            key('tmpl') :       lambda val: '%%' + val + '%%',
            key('tmpl') :       lambda val: '!!' + val + '!!',
            key('tmpl') :       lambda val: '$$' + val + '$$',
        }
        
        try:
            n = int(self._baseValue)
            transforms.update({
                key('int') :    lambda val: 'Integer(' + val + ')',
                key('int') :    lambda val: 'int(' + val + ')',
                key('int') :    lambda val: 'Integer(' + val + ')',
                key('int') :    lambda val: 'int(' + val + ')',
                key('int') :    lambda val: '(' + val + ')',
                key('int') :    lambda val: val + '.0',
                key('int') :    lambda val: '+' + val,
                key('int') :    lambda val: '0x{0:x}'.format(n),
                key('int') :    lambda val: '0{0:o}'.format(n),
                key('int') :    lambda val: '0b{0:b}'.format(n),
                key('int') :    lambda val: '+0x{0:x}'.format(n),
                key('int') :    lambda val: '+0{0:o}'.format(n),
                key('int') :    lambda val: '+0b{0:b}'.format(n),
                key('int') :    lambda val: '16#{0:x}#'.format(n),
                key('int') :    lambda val: 'x"{0:x}"'.format(n),
                key('int') :    lambda val: '${0:x}'.format(n),
                key('int') :    lambda val: '16r{0:x}'.format(n),
                key('int') :    lambda val: '&H{0:x}'.format(n),
            })
        except ValueError:
            pass

        '''
        try:
            n = float(self._baseValue)
            transforms.update({
                'tmpl1' :       lambda val: '{{1+' + str(n-1) + '}}',
                'tmpl2' :       lambda val: '{1+' + str(n-1) + '}',
                'tmpl3' :       lambda val: '${{1+' + str(n-1) + '}}',
                'tmpl4' :       lambda val: '${1+' + str(n-1) + '}',
            })
        except ValueError:
            pass
        '''

        for tr in transforms.values():
            yield tr(self._baseValue)


    def getNextPayload(self, baseValue):
        self.log('g.getnext: basevalue={0}, g={1}'.format(baseValue, self._generator))
        if self._generator is None:
            # special case on first call
            self._baseValue = str(bytearray(baseValue)) # remember base value for iter()
            self._generator = iter(self)
            return next(self._generator) # return the first value immediately
        return self._nextValue # otherwise, return the one that was queued


    def reset(self):
        self.log('g.reset')
        self._morePayloads = True
        del self._generator
        del self._nextValue
        del self._baseValue



class FuzzEncodingsGeneratorFactory(IIntruderPayloadGeneratorFactory):
    def __init__(self, callbacks):
        self._callbacks = callbacks
        
    def getGeneratorName(self):
        return 'Transfuzz'

    def createNewInstance(self, intruderAttack):
        # return a IIntruderPayloadGenerator object
        # intruderAttack is a IIntruderAttack object
        g = FuzzEncodingsGenerator(self._callbacks)
        return g


class BurpExtender(IBurpExtender):
    def registerExtenderCallbacks(self, callbacks):
        # 'entrypoint'
        callbacks.setExtensionName('Transfuzz')
        factory = FuzzEncodingsGeneratorFactory(callbacks)
        callbacks.registerIntruderPayloadGeneratorFactory(factory)
        return
