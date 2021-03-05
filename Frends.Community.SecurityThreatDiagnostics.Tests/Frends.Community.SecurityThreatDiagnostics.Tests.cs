using System;
using System.Collections.Generic;
using NUnit.Framework;
using System.Threading;

namespace Frends.Community.SecurityThreatDiagnostics.Tests
{
    [TestFixture]
    public class TestClass
    {
        private ValidationInput _validationInput;
        private ValidationAttributes _validationAttributes;
        private Options _options;

        [SetUp]
        public void SetUp()
        {
            _validationInput = new ValidationInput();
            _validationAttributes = new ValidationAttributes();

            _options = new Options
            {
                SourceEncoding = "ISO-8859-1",
                DestinationEncoding = "ISO-8859-7",
                Base64Decode = true
            };

        }
        
        //TODO: Left original commented out test names which were not easy to read so they can be compared. Delete the commented test names before the final commit

        [TestCase("This is a valid content.")]
        public void ChallengeAgainstSecurityThreats_ShouldAcceptValidInput(string validInput)
            
            //GivenValidTextWhenChallengingValidationThenSecurityThreatDiagnosticsMustRaiseExceptionDueToFoundInjection()
        {
            _validationInput.Payload = validInput;
            var result =
                SecurityThreatDiagnostics.ChallengeAgainstSecurityThreats(_validationInput, _options,
                    CancellationToken.None);
            Assert.IsTrue(result.IsValid);
        }
        
        // Combined these four test into one test with multiple cases because they had identical code:
        [TestCase( "<xml><entity><script>function xss() { alert('injection'); } xss();</script></entity></xml>", 16)]
        [TestCase("<xml><entity><script>function xss() { alert(\"injection\"); } xss();</script></entity></xml>", 16)]
        [TestCase("function xss() { alert('injection'); } xss();",16)]
        [TestCase("<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM \"file:///etc/passwd\" >]><foo>&xxe;</foo>", 28)]
        // Base64Encoded: function xss() { alert('injection'); } xss();
        [TestCase("ZnVuY3Rpb24geHNzKCkgeyBhbGVydCgnaW5qZWN0aW9uJyk7IH0geHNzKCk7", 16)]
        public void ChallengeAgentSecurityThreats_ShouldThrowFor(string input, int expectedFilterId)
        {
            _validationInput.Payload = input;
            var result = Assert.Throws<Exception>(() =>
                SecurityThreatDiagnostics.ChallengeAgainstSecurityThreats(_validationInput, _options,
                    CancellationToken.None));
            StringAssert.Contains($"id [{expectedFilterId.ToString()}]",result.Message);
        }

        [Test]
        public void
            ChallengeUrlEncoding_ShouldThrowForDoubleEncodedInjection()
            //GivenDoubleEncodedUrlInjectionInURIFormatWhenChallengingValidationThenSecurityThreatDiagnosticsMustRaiseExceptionDueToDoubleEncodedURI()
        {
            var unsecureUrl = "http://victim/cgi/%252E%252E%252F%252E%252E%252Fwinnt/system32/cmd.exe?/c+dir+c:\";";
            _validationInput.Payload = unsecureUrl;
            var options = new ChallengeUrlEncodingOptions
            {
                Iterations = 2
            };
            var result = Assert.Throws<Exception>(() =>
                SecurityThreatDiagnostics.ChallengeUrlEncoding(_validationInput, options, CancellationToken.None));
            
            StringAssert.Contains("Found dangerous URL encoded input for", result.Message);
        }

        [Test]
        // TODO: How is ChallengeCharacterSetEncoding supposed to actually work? Shouldn't this actually throw, or what's the point of this?
        // TODO: This needs a case where the challenge fails as well
        public void ChallengeCharacterSetEncoding_ShouldConvertCharacterset() 
            //GivenUnknownCharacterWhenChallengingEncodingThenSecurityThreatDiagnosticsMustConvertToKnownCharacterSetEncoding()
        {
            var unknownCharacters = "ዩኒኮድ ወረጘ የጝ00F800F8يونِكودö'>>B$ôI#€%&/()?@∂öيونِكود";
            _validationInput.Payload = unknownCharacters;
            var result = SecurityThreatDiagnostics.ChallengeCharacterSetEncoding(_validationInput.Payload, _options);
            
            Assert.That(result.IsValid, Is.True);
        }

        [Test]
        public void ChallengeAgainstSecurityThreats_ShouldThrowAnExceptionForSqlInjectionInUriFormat()
            //GivenUrlInjectionInURIFormatWhenChallengingValidationThenSecurityThreatDiagnosticsMustRaiseExceptionDueToFoundSQLInjection()
        {
            var unsecureUrl = "http://example.org/foo?q=select * from Customers;`insert into";
            _validationInput.Payload = unsecureUrl;
            
            var result = Assert.Throws<Exception>(() =>
                SecurityThreatDiagnostics.ChallengeAgainstSecurityThreats(_validationInput, _options,
                    CancellationToken.None));
            
            StringAssert.Contains("id [57]", result.Message);
        }

        [Test]
        public void
            ChallengeSecurityHeaders_ShouldThrowForInjectedScript()
            //GivenInjectedHeaderInWhenChallengingHeadersForValidationThenSecurityThreatDiagnosticsMustRaiseExceptionDueToInjectedHeaderValue()
        {
            var whiteListedHeaders = new ChallengeSecurityHeadersInput
            {
                HttpUri = "http://localhost",
                AllowedHttpHeaders = new[] {"Authorization"},
                HttpHeaders = new Dictionary<string, string>
                {
                    {
                        "Authorization",
                        "<script>function attack(){ alert(\"i created XSS\"); } attack();</script>"
                    }
                }
            };
            var exception = Assert.Throws<Exception>(() =>
                SecurityThreatDiagnostics.ChallengeSecurityHeaders(whiteListedHeaders, _options,
                    CancellationToken.None));
            StringAssert.Contains("id [16]", exception.Message);
        }

        [Test]
        public void
            ChallengeAttributesAgainstSecurityThreats_ShouldThrowForInjectedAttributes()
            //GivenInvalidAttributesWhenChallengingPayloadAttributesForValidationThenSecurityThreatDiagnosticsMustRaiseExceptionDueToInjectedAttributss()
        {
            // TODO: Why two identical attributes?
            var invalidAttribute1 = "<script>function xss() { alert('injection'); } xss();</script>";
            var invalidAttribute2 = "<script>function xss() { alert('injection'); } xss();</script>";
            
            _validationAttributes.Attribute = new []{ invalidAttribute1, invalidAttribute2 };

            var result = Assert.Throws<Exception>(() =>
                SecurityThreatDiagnostics.ChallengeAttributesAgainstSecurityThreats(_validationAttributes, _options,
                    CancellationToken.None));
        }

        [Test]
        public void
            ChallengeAttributesAgainstSecurityThreats_ShouldThrowForAttributeWithAttackPattern()
            //GivenAttackVectorWithMultipleAttributesWhenChallengingPayloadAttributesForValidationThenSecurityThreatDiagnosticsMustRaiseExceptionDueToFoundAttackPattern()
        {
            var invalidAttribute1 = "{ \"payload\" : {\"Name\": \"%27 %3E%3E\"}}";
            var invalidAttribute2 = "{ \"Address\":\"%3Cscript%3E function attack() %7B alert(%27xss%27)%3B %7D\"}";
            var parallel = invalidAttribute1 + invalidAttribute2;
            string[] attributes = {invalidAttribute1, invalidAttribute2, parallel};
            _validationAttributes.Attribute = attributes;

            Assert.Throws<Exception>(() =>
                SecurityThreatDiagnostics.ChallengeAttributesAgainstSecurityThreats(_validationAttributes, _options,
                    CancellationToken.None));
        }

        [Test]
        public void
            ChallengeAttributesAgainstSecurityThreats_ShouldThrowForAttributeWithEscapedCharacter()
            //GivenAttackVectorWithCharacterEscapedAttributesWhenChallengingPayloadAttributesForValidationThenSecurityThreatDiagnosticsMustRaiseExceptionDueToInvalidException()
        {
            var invalidAttribute1 = "{ payload : {\"Name\":\"+00004oCZc2gxbjBiMXc0emgzcjM+Pmg0eDNkb2k=\"}}";
            var validAttribute = "{\"Address\" : \"test\"}";
            
            var parallel = invalidAttribute1 + validAttribute;
            string[] attributes = {invalidAttribute1, validAttribute, parallel}; // TODO: What is the point of this test? Why check them separately and concatenated? 
            _validationAttributes.Attribute = attributes;
            var result = Assert.Throws<Exception>(() =>
                SecurityThreatDiagnostics.ChallengeAttributesAgainstSecurityThreats(_validationAttributes, _options,
                    CancellationToken.None));
        }

        [Test]
        public void ChallengeIpAddresses_ShouldAcceptValidIpAddress()
        {
            //IPV4 and IPV6
            var allowedIpAddresses = new IpAddressValidationInput
            {
                WhiteListedIpAddresses = new[] {"\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}"},
                BlackListedIpAddresses = new[] {"255.255.255.255"},
                IpAddressToValidate = "127.0.0.1"
            };

            var result = SecurityThreatDiagnostics.ChallengeIPAddresses(allowedIpAddresses, CancellationToken.None);
            Assert.That(result.IsValid, Is.True);
        }
        
        [Test]
        public void ChallengeIpAddresses_ShouldThrowForInvalidIpAddress()
        {
            //IPV4 and IPV6
            var allowedIpAddresses = new IpAddressValidationInput
            {
                WhiteListedIpAddresses = new[] {"\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}"},
                BlackListedIpAddresses = new[] {"255.255.255.255"},
                IpAddressToValidate = "255.255.255.255"
            };

            var result = Assert.Throws<Exception>(() => SecurityThreatDiagnostics.ChallengeIPAddresses(allowedIpAddresses, CancellationToken.None));
            StringAssert.Contains("Invalid IP Address or range",result.Message);
        }
    }
}