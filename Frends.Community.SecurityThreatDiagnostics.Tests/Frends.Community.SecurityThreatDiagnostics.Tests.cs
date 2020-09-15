using NUnit.Framework;
using System.Threading;

namespace Frends.Community.SecurityThreatDiagnostics.Tests
{
    [TestFixture]
    class TestClass
    {
        Validation _validation = new Validation();
        Options options = new Options();
        CancellationToken cancellationToken = new CancellationToken();
        
        [Test]
        public void GivenValidTextWhenChallengingValidationThenSecurityThreatDiagnosticsMustReturnFalse()
        {
            string validXml = "This is a valid content.;'  temp.txt";
            _validation.Payload = validXml;
            Assert.IsFalse(SecurityThreatDiagnostics.ChallengeAgainstSecurityThreats(_validation, options, cancellationToken)) ;
        }
        
        [Test]
        public void GivenValidXMLWhenChallengingValidationThenSecurityThreatDiagnosticsMustReturnFalse()
        {
            string validXml = "<xml><entity>1</entity></xml>";
            _validation.Payload = validXml;
            Assert.IsTrue(SecurityThreatDiagnostics.ChallengeAgainstSecurityThreats(_validation, options, cancellationToken)) ;
        }
        
        [Test]
        public void GivenScriptInjectedXMLWhenChallengingValidationThenSecurityThreatDiagnosticsMustReturnTrue()
        {
            string invalidXml = "<xml><entity><script>function xss() { alert('injection'); } xss();</script></entity></xml>";
            _validation.Payload = invalidXml;
            Assert.IsTrue(SecurityThreatDiagnostics.ChallengeAgainstSecurityThreats(_validation, options, cancellationToken)) ;
        }
        
        [Test]
        public void GivenDoubleEncodedUrlInjectionInURIFormatWhenChallengingValidationThenSecurityThreatDiagnosticsMustReturnTrue()
        {
            string unsecureUrl = "http://victim/cgi/%252E%252E%252F%252E%252E%252Fwinnt/system32/cmd.exe?/c+dir+c:\";";
            _validation.Payload = unsecureUrl;
            Assert.IsFalse(SecurityThreatDiagnostics.ChallengeAgainstSecurityThreats(_validation, options, cancellationToken)) ;
        }
        
        [Test]
        public void GivenUrlInjectionInURIFormatWhenChallengingValidationThenSecurityThreatDiagnosticsMustReturnTrue()
        {
            string unsecureUrl = "select * from Customers;`insert into";
            _validation.Payload = unsecureUrl;
            Assert.IsFalse(SecurityThreatDiagnostics.ChallengeAgainstSecurityThreats(_validation, options, cancellationToken)) ;
        }
    }
}
