using System;
using System.Collections.Generic;
using NUnit.Framework;
using System.Threading;

namespace Frends.Community.SecurityThreatDiagnostics.Tests
{
    [TestFixture]
    class TestClass
    {
        Validation validation = new Validation();
        ValidationAttributes validationAttributes = new ValidationAttributes();
        Options options = new Options();

        [Test]
        public void GivenValidTextWhenChallengingValidationThenSecurityThreatDiagnosticsMustReturnIsValidStatus()
        {
            string validXml = "This is a valid content.;function ' <script>  temp.txt";
            validation.Payload = validXml;
            options.MaxIterations = 2;
            Assert.Throws<ApplicationException>(
                delegate { SecurityThreatDiagnostics.ChallengeAgainstSecurityThreats(validation, options, CancellationToken.None); } );
        }
        
        [Test]
        public void GivenValidXMLWhenChallengingValidationThenSecurityThreatDiagnosticsMustReturnIsValidStatus()
        {
            string validXml = "<xml><entity>1</entity></xml>";
            validation.Payload = validXml;    
            options.MaxIterations = 2;
            Assert.Throws<ApplicationException>(
                delegate { SecurityThreatDiagnostics.ChallengeAgainstSecurityThreats(validation, options, CancellationToken.None); } );
        }
        
        [Test]
        public void GivenScriptInjectedXMLWhenChallengingValidationThenSecurityThreatDiagnosticsMustReturnIsValidStatus()
        {
            string invalidXml = "<xml><entity><script>function xss() { alert('injection'); } xss();</script></entity></xml>";
            validation.Payload = invalidXml;
            options.MaxIterations = 2;
            Assert.Throws<ApplicationException>(
                delegate { SecurityThreatDiagnostics.ChallengeAgainstSecurityThreats(validation, options, CancellationToken.None); } );
        }
        
        [Test]
        public void GivenScriptInjectedXMLWithDoubleQuatesWhenChallengingValidationThenSecurityThreatDiagnosticsMustReturnIsValidStatus()
        {
            string invalidXml = "<xml><entity><script>function xss() { alert(\"injection\"); } xss();</script></entity></xml>";
            validation.Payload = invalidXml;
            options.MaxIterations = 2;
            Assert.Throws<ApplicationException>(
                delegate { SecurityThreatDiagnostics.ChallengeAgainstSecurityThreats(validation, options, CancellationToken.None); } );
        }
        
        [Test]
        public void GivenXSScriptAttackScriptAsAnAttributeWhenChallengingValidationThenSecurityThreatDiagnosticsMustReturnIsValidStatus()
        {
            string invalidXml = "function xss() { alert('injection'); } xss();";
            validation.Payload = invalidXml;
            options.MaxIterations = 2;
            Assert.Throws<ApplicationException>(
                delegate { SecurityThreatDiagnostics.ChallengeAgainstSecurityThreats(validation, options, CancellationToken.None); } );
        }
        
        [Test]
        public void GivenDoubleEncodedUrlInjectionInURIFormatWhenChallengingValidationThenSecurityThreatDiagnosticsMustReturnIsValidStatus()
        {
            string unsecureUrl = "http://victim/cgi/%252E%252E%252F%252E%252E%252Fwinnt/system32/cmd.exe?/c+dir+c:\";";
            validation.Payload = unsecureUrl;
            options.MaxIterations = 2;
            Assert.Throws<ApplicationException>(
                delegate { SecurityThreatDiagnostics.ChallengeAgainstSecurityThreats(validation, options, CancellationToken.None); } );
        }
        
        [Test]
        public void GivenDoubleEncodedUrlInjectionInURIFormatWhenChallengingEncodingThenSecurityThreatDiagnosticsMustReturnIsValidStatus()
        {
            string unsecureUrl = "http://victim/cgi/%252E%252E%252F%252E%252E%252Fwinnt/system32/cmd.exe?/c+dir+c:\";";
            validation.Payload = unsecureUrl;
            options.MaxIterations = 2;
            Assert.Throws<ApplicationException>(
                delegate { SecurityThreatDiagnostics.ChallengeCharacterEncoding(validation, options, CancellationToken.None); } );
        }
        
        [Test]
        public void GivenUrlInjectionInURIFormatWhenChallengingValidationThenSecurityThreatDiagnosticsMustReturnIsValidStatus()
        {
            string unsecureUrl = "select * from Customers;`insert into";
            validation.Payload = unsecureUrl;
            options.MaxIterations = 2;
            Assert.Throws<ApplicationException>(
                delegate { SecurityThreatDiagnostics.ChallengeAgainstSecurityThreats(validation, options, CancellationToken.None); } );
        }
        
        [Test]
        [Ignore("Ignore a test")]
        public void GivenInjectedHeaderInWhenChallengingHeadersForValidationThenSecurityThreatDiagnosticsMustRaiseException()
        {
            WhiteListedHeaders whiteListedHeaders = new WhiteListedHeaders();
            whiteListedHeaders.HttpUri = "http://localhost";
            whiteListedHeaders.AllowedHttpHeaders = new [] {"Authorization"};
            whiteListedHeaders.HttpHeaders = new Dictionary<string, string>();
            whiteListedHeaders.HttpHeaders.Add("Authorization: ", "Bearer <script>function attack(){ alert(\"i created XSS\"); } attack();</script>"); 
            Assert.Throws<ApplicationException>(delegate { SecurityThreatDiagnostics.ChallengeSecurityHeaders(whiteListedHeaders, options, CancellationToken.None); });
        }
        
        [Test]
        public void GivenInvalidAttributesWhenChallengingPayloadAttributesForValidationThenSecurityThreatDiagnosticsMustReturnFailedAttributes()
        {
            string invalidAttribute1 = "<script>function xss() { alert('injection'); } xss();</script>";
            string invalidAttribute2 = "<script>function xss() { alert('injection'); } xss();</script>";
            string[] attributes = {invalidAttribute1, invalidAttribute2};
            validationAttributes.Attribute = attributes;
           
            Assert.Throws<ApplicationException>(delegate { SecurityThreatDiagnostics.ChallengeAttributesAgainstSecurityThreats(validationAttributes, options, CancellationToken.None); });
        }
        
        [Test]
        public void GivenAttackVectorWithMultipleAttributesWhenChallengingPayloadAttributesForValidationThenSecurityThreatDiagnosticsMustReturnFailedAttributes()
        {
            string invalidAttribute1 = "{ payload : {Name" + ":" + "%27 %3E%3E";
            string invalidAttribute2 = "Address" + ":" + "%3Cscript%3E function attack() %7B alert(%27xss%27)%3B %7D";
            string invalidAttribute3 = "Mobile"+ ":" + "attack()%3B %3C%2Fscript%3E}}";
            string parallel = invalidAttribute1 + invalidAttribute2 + invalidAttribute3;
            string[] attributes = {invalidAttribute1, invalidAttribute2, invalidAttribute3, parallel};
            validationAttributes.Attribute = attributes;
           
            Assert.Throws<ApplicationException>(delegate { SecurityThreatDiagnostics.ChallengeAttributesAgainstSecurityThreats(validationAttributes, options, CancellationToken.None); });
        }
        
        [Test]
        public void GivenAttackVectorWithCharacterEscapedAttributesWhenChallengingPayloadAttributesForValidationThenSecurityThreatDiagnosticsMustReturnFailedAttributes()
        {
            string invalidAttribute1 = "{ payload : {Name" + ":" + "U+00004oCZc2gxbjBiMXc0emgzcjM+Pmg0eDNkb2k=";
            string invalidAttribute2 = "Address : test";
            string invalidAttribute3 = "Mobile +358123456789 }}";
            string parallel = invalidAttribute1 + invalidAttribute2 + invalidAttribute3;
            string[] attributes = {invalidAttribute1, invalidAttribute2, invalidAttribute3, parallel};
            validationAttributes.Attribute = attributes;
           
            Assert.Throws<ApplicationException>(delegate { SecurityThreatDiagnostics.ChallengeAttributesAgainstSecurityThreats(validationAttributes, options, CancellationToken.None); });
        }

        [Test]
        public void GivenAllowedIPAddressWhenChallengingIPForValidationThenSecurityThreatDiagnosticsMustRaiseException() {
            AllowedIPAddresses allowedIpAddresses = new AllowedIPAddresses();
            //IPV4 and IPV6
            string[] allowedIPAddressesRegex =
            {
                "\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}",
                "\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3},\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}"
            };
            
            string[] denyBroadcastIPAddressesRegex =                                                        
            {                                                                                         
                "255.255.255.255"
            };                                                                                        
            
            allowedIpAddresses.WhiteListedIpAddress = allowedIPAddressesRegex;
            allowedIpAddresses.BlackListedIpAddresses = denyBroadcastIPAddressesRegex;
            allowedIpAddresses.Host = "127.0.0.1";
            Assert.DoesNotThrow(
                delegate { SecurityThreatDiagnostics.ChallengeIPAddresses(allowedIpAddresses, CancellationToken.None); } );
        }
        
    }
}
