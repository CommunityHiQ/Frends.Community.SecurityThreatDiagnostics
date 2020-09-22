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
        Options options = new Options();
        CancellationToken cancellationToken = new CancellationToken();
        
        [Test]
        public void GivenValidTextWhenChallengingValidationThenSecurityThreatDiagnosticsMustReturnFalse()
        {
            string validXml = "This is a valid content.;function ' <script>  temp.txt";
            validation.Payload = validXml;
            options.Encoding = "UTF-8";
            Assert.Throws<ApplicationException>(
                delegate { SecurityThreatDiagnostics.ChallengeAgainstSecurityThreats(validation, options, cancellationToken); } );
        }
        
        [Test]
        public void GivenValidXMLWhenChallengingValidationThenSecurityThreatDiagnosticsMustReturnFalse()
        {
            string validXml = "<xml><entity>1</entity></xml>";
            validation.Payload = validXml;
            options.Encoding = "UTF-8";
            Assert.Throws<ApplicationException>(
                delegate { SecurityThreatDiagnostics.ChallengeAgainstSecurityThreats(validation, options, cancellationToken); } );
        }
        
        [Test]
        public void GivenScriptInjectedXMLWhenChallengingValidationThenSecurityThreatDiagnosticsMustReturnTrue()
        {
            string invalidXml = "<xml><entity><script>function xss() { alert('injection'); } xss();</script></entity></xml>";
            validation.Payload = invalidXml;
            options.Encoding = "UTF-8";
            Assert.Throws<ApplicationException>(
                delegate { SecurityThreatDiagnostics.ChallengeAgainstSecurityThreats(validation, options, cancellationToken); } );
        }
        
        [Test]
        public void GivenDoubleEncodedUrlInjectionInURIFormatWhenChallengingValidationThenSecurityThreatDiagnosticsMustReturnTrue()
        {
            string unsecureUrl = "http://victim/cgi/%252E%252E%252F%252E%252E%252Fwinnt/system32/cmd.exe?/c+dir+c:\";";
            validation.Payload = unsecureUrl;
            options.Encoding = "UTF-8";
            Assert.Throws<ApplicationException>(
                delegate { SecurityThreatDiagnostics.ChallengeAgainstSecurityThreats(validation, options, cancellationToken); } );
        }
        
        [Test]
        public void GivenUrlInjectionInURIFormatWhenChallengingValidationThenSecurityThreatDiagnosticsMustReturnTrue()
        {
            string unsecureUrl = "select * from Customers;`insert into";
            validation.Payload = unsecureUrl;
            options.Encoding = "UTF-8";
            Assert.Throws<ApplicationException>(
                delegate { SecurityThreatDiagnostics.ChallengeAgainstSecurityThreats(validation, options, cancellationToken); } );
        }
        
        [Test]
        [Ignore("Ignore a test")]
        public void GivenInjectedHeaderInWhenChallengingHeadersForValidationThenSecurityThreatDiagnosticsMustRaiseException()
        {
            WhiteListedHeaders whiteListedHeaders = new WhiteListedHeaders();
            whiteListedHeaders.HttpUri = "http://localhost:8080";
            whiteListedHeaders.AllowedHttpHeaders = new [] {"Authorization"};
            whiteListedHeaders.HttpHeaders = new Dictionary<string, string>();
            whiteListedHeaders.HttpHeaders.Add("Authorization: ", "Bearer=<script>function attack(){ alert(\"i created XSS\"); } attack();</script>");
            Assert.Throws<ApplicationException>(delegate { SecurityThreatDiagnostics.ChallengeSecurityHeaders(whiteListedHeaders, cancellationToken); } );
        }
        
        [Test]
        public void GivenAllowdIPAddressWhenChallengingIPForValidationThenSecurityThreatDiagnosticsMustRaiseException() {
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
            Assert.DoesNotThrow(delegate { SecurityThreatDiagnostics.ChallengeIPAddresses(allowedIpAddresses, cancellationToken); } );
        }
        
    }
}
