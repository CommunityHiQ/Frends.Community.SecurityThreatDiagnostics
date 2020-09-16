using System;
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
            Assert.Throws<ApplicationException>(
                delegate { SecurityThreatDiagnostics.ChallengeAgainstSecurityThreats(validation, options, cancellationToken); } );
        }
        
        [Test]
        public void GivenValidXMLWhenChallengingValidationThenSecurityThreatDiagnosticsMustReturnFalse()
        {
            string validXml = "<xml><entity>1</entity></xml>";
            validation.Payload = validXml;
            Assert.Throws<ApplicationException>(
                delegate { SecurityThreatDiagnostics.ChallengeAgainstSecurityThreats(validation, options, cancellationToken); } );
        }
        
        [Test]
        public void GivenScriptInjectedXMLWhenChallengingValidationThenSecurityThreatDiagnosticsMustReturnTrue()
        {
            string invalidXml = "<xml><entity><script>function xss() { alert('injection'); } xss();</script></entity></xml>";
            validation.Payload = invalidXml;
            Assert.Throws<ApplicationException>(
                delegate { SecurityThreatDiagnostics.ChallengeAgainstSecurityThreats(validation, options, cancellationToken); } );
        }
        
        [Test]
        public void GivenDoubleEncodedUrlInjectionInURIFormatWhenChallengingValidationThenSecurityThreatDiagnosticsMustReturnTrue()
        {
            string unsecureUrl = "http://victim/cgi/%252E%252E%252F%252E%252E%252Fwinnt/system32/cmd.exe?/c+dir+c:\";";
            validation.Payload = unsecureUrl;
            Assert.Throws<ApplicationException>(
                delegate { SecurityThreatDiagnostics.ChallengeAgainstSecurityThreats(validation, options, cancellationToken); } );
        }
        
        [Test]
        public void GivenUrlInjectionInURIFormatWhenChallengingValidationThenSecurityThreatDiagnosticsMustReturnTrue()
        {
            string unsecureUrl = "select * from Customers;`insert into";
            validation.Payload = unsecureUrl;
            Assert.Throws<ApplicationException>(
                delegate { SecurityThreatDiagnostics.ChallengeAgainstSecurityThreats(validation, options, cancellationToken); } );
        }
    }
}
