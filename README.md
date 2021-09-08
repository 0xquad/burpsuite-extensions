# Custom PortSwigger Burp Suite Extensions

## Transfuzz

Transformation-based fuzzer that encodes payloads in a number of ways to detect what kinds of encoding the application will accept. This is often useful to help identify backend technologies and launch more sophisticated injection attacks.

## LuhnyDigit

Luhn Check Digit calculator as a payload processor. Automatically transform sequential numbers to valid Luhn compliant numbers by appending a check digit to the field value. For example, iterating from 800 to 899 will generate numbers between 8003 and 8995 where the '3' and '5' are the check digit.

TODO: Implement as a trivial Hackvertor tag too: e.g. <@_luhn>800<@/_luhn> -> 8003