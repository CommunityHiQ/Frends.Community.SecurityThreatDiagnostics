#pragma warning disable 1591

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

namespace Frends.Community.SecurityThreatDiagnostics
{
    
    public class ValidationChallengeException: Exception 
    {
        public ValidationChallengeException(string message, IList<string> validationErrors): base(message)
        {
            ValidationErrors = validationErrors;
        }

        public ValidationChallengeException(string message): this(message, new List<string>())
        {
            
        }
        public  IList<string> ValidationErrors { get; private set; }
    }

    /// <summary>
    /// This class is responsible for transmitting the validation parameters from the runtime configuration into process of security diagnostics.
    /// </summary>
    public class ValidationInput
    {
        /// <summary>
        /// The input to be validated.
        /// </summary>
        [DisplayFormat(DataFormatString = "Text")] 
        [DefaultValue("{{#trigger.data.body}}")]
        public string Payload { get; set; }
    }
    
    /// <summary>
    /// Validation input parameters
    /// </summary>
    public class ValidationAttributes
    {
        /// <summary>
        /// The input to be validated.
        /// </summary>
        [DefaultValue("{{#trigger.data.body}}")]
        public string[] Attribute { get; set; } // TODO: Collections/arrays should be named plural: Attributes
    }
    
    /// <summary>
    /// Allowed IP address validation input
    /// </summary>
    public class IpAddressValidationInput
    {
        /// <summary>
        /// IP address to validate
        /// </summary>
        [DisplayFormat(DataFormatString = "Text")] 
        [DefaultValue("{{#trigger.data.httpClientIp}}")]
        public string IpAddressToValidate { get; set; }

        /// <summary>
        /// Regular expression or value for allowed IP addresses, matching IPs pass validation
        /// </summary>
        [DisplayFormat(DataFormatString = "Text")]
        [DefaultValue("\\d{1,3}.\\d{1,3}.\\d{1,3}.\\d{1,3}")]
        public string[] WhiteListedIpAddresses { get; set; }

        /// <summary>
        /// Regular expression or value for black listed IP addresses, matching IPs will always fail validation 
        /// </summary>
        [DisplayFormat(DataFormatString = "Text")]
        [DefaultValue("\\d{1,3}.\\d{1,3}.\\d{1,3}.\\d{1,3}")]
        public string[] BlackListedIpAddresses { get; set; }
    }

    /// <summary>
    /// Input for validating HTTP header validation
    /// </summary>
    public class ChallengeSecurityHeadersInput
    {
        // TODO: Why is this parameter here, it is not used for anything?
        public string HttpUri { get; set; }
        
        // TODO: Why is this parameter here, it is not used for anything?
        /// <summary>
        /// Define the HTTP(S) redirect url   
        /// </summary>
        [DisplayFormat(DataFormatString = "Text")] 
        [DefaultValue("https://somedomainforcesecure")]
        public string HttpRedirectUri { get; set; }
        
        /// <summary>
        /// Allowed HTTP header names, * to allow all headers
        /// </summary>
        [DisplayFormat(DataFormatString = "Text")]
        [DefaultValue("*")]
        public string[] AllowedHttpHeaders { get; set; }

        /// <summary>
        /// Request based HTTP headers with a key value pair
        /// </summary>
        [DisplayFormat(DataFormatString = "Expression")]
        [DefaultValue("#trigger.data.httpHeaders")]
        public object HttpHeaders { get; set; }

    }

    public class ChallengeUrlEncodingOptions: Options
    {
        /// <summary>
        /// How many URL decoding iteration rounds will be executed for the input
        /// </summary>
        [DisplayFormat(DataFormatString = "Text")]
        [DefaultValue("2")]
        public int Iterations { get; set; }
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
        [DefaultValue("UTF-8")]
        public string SourceEncoding { get; set; } = "UTF-8";
        
        /// <summary>
        /// Which encoding should be used, default UTF-8.
        /// </summary>
        [DisplayFormat(DataFormatString = "Text")]
        [DefaultValue("UTF-8")]
        public string DestinationEncoding { get; set; } = "UTF-8";
        
        /// <summary>
        /// Should content be Base64 decoded for validation
        /// </summary>
        [DefaultValue(false)]
        public bool Base64Decode { get; set; }
        
    }
    
}
