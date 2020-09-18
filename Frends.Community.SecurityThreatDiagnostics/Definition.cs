#pragma warning disable 1591

using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

namespace Frends.Community.SecurityThreatDiagnostics
{
    /// <summary>
    /// Parameters class usually requires parameters that are required.
    /// </summary>
    public class Validation
    {
        /// <summary>
        /// Something that will be repeated.
        /// </summary>
        [DisplayFormat(DataFormatString = "Text")] 
        [DefaultValue("Payload to be challenged against vulnerabilities")]
        public string Payload { get; set; }
    }
    
    /// <summary>
    /// Challenge against allowed IP addresses
    /// </summary>
    public class AllowedIPAddresses
    {
        /// <summary>
        /// Current HTTP url where the message is coming from
        /// </summary>
        [DisplayFormat(DataFormatString = "Text")] 
        [DefaultValue("Current HTTP url")]
        public string Host { get; set; }

        /// <summary>
        /// Whitelisted IP addresses to be bypassed 
        /// </summary>
        [DisplayFormat(DataFormatString = "Text")] 
        [DefaultValue("Whitelisted IP addresses to bypass validation")]
        //public IPAddress[] WhiteListedIpAddress { get; set; }
        public string[] WhiteListedIpAddress { get; set; }

        /// <summary>
        /// Blacklisted IP addresses and ranges 
        /// </summary>
        [DisplayFormat(DataFormatString = "Text")] 
        [DefaultValue("Whitelisted IP addresses to bypass validation")]
        //public IPAddress[] BlackListedIpAddresses { get; set; }
        public string[] BlackListedIpAddresses { get; set; }
    }

    /// <summary>
    /// Challenge against allowed HTTP headers
    /// </summary>
    //[DisplayFormat(DataFormatString = "Text")] 
    [DefaultValue("#trigger.data.httpHeaders")]
    public class WhiteListedHeaders
    {
        public string HttpUri { get; set; }
        /// <summary>
        /// Define the HTTP(S) redirect url   
        /// </summary>
        [DisplayFormat(DataFormatString = "Text")] 
        [DefaultValue("https://somedomainforcesecure")]
        public string HttpRedirectUri { get; set; }
        
        /// <summary>
        /// Define the domain uri
        /// </summary>
        [DisplayFormat(DataFormatString = "Text")] 
        [DefaultValue("http://somedomain.com")]
        public string[] HttpHeader { get; set; }
        
    }

    /// <summary>
    /// Options class provides additional parameters.
    /// </summary>
    public class Options
    {
        /// <summary>
        /// Which encoding should be used, default UTF-8.
        /// </summary>
        [DisplayFormat(DataFormatString = "Text")]
        [DefaultValue(" ")]
        public string Encoding { get; set; }
    }

    public class Result
    {
        /// <summary>
        /// Contains input .
        /// </summary>
        [DisplayFormat(DataFormatString = "Text")]
        public string ICollection { get; set; }
    }
}
