# Custom PortSwigger Burp Suite Extensions

## Transfuzz

Transformation-based fuzzer that encodes payloads in a number of ways to detect what kinds of encoding the application will accept. This is often useful to help identify backend technologies and launch more sophisticated injection attacks.

## LuhnyDigit

Luhn Check Digit calculator as a payload processor. Automatically transform sequential numbers to valid Luhn compliant numbers by appending a check digit to the field value. For example, iterating from 800 to 899 will generate numbers between 8003 and 8995 where the '3' and '5' are the check digit.

How to use:
- Load the extension in Burp Suite (make sure the Jython runtime works first).
- In Intruder, mark a numeric field and choose Sniper attack.
- In the Payloads tab, select the Payload type = Numbers then specify the
  sequence in the From/To field and strip the check digit if it was already
  included. i.e. if the original value was 8003, use 800 to e.g. 899
- Under Payload Processing, add a processor and select Invoke Burp Extension.
- Select LuhnyDigit
- Launch the attack. Values between 8003 to 8995 will be generated ('3' and '5'
  are the check digit that is automatically appended to the value).

TODO: Implement as a trivial Hackvertor tag too: e.g. <@_luhn>800<@/_luhn> -> 8003

## JWTBuzz

JWTBuzz is a simple fuzzer for JSON Web Tokens. To use it, go to Intruder and mark the entire JWT in the payload and select the extension for the payload generator. It will try modifying the fields in the headers and various other attacks. Signature verification is not yet implemented.