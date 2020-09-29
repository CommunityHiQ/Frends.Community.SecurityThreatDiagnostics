﻿#pragma warning disable 1591

using System.Collections.Generic;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

namespace Frends.Community.SecurityThreatDiagnostics
{
    /// <summary>
    /// This class is responsible for transmitting the validation parameters from the runtime configuration into process phase execution.
    /// </summary>
    public class Validation
    {
        /// <summary>
        /// The payload or the attribute value to be validated.
        /// </summary>
        [DisplayFormat(DataFormatString = "Text")] 
        [DefaultValue("#var.")]
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
        /// Whitelisted IP addresses to be bypassed by the process engine's validation
        /// </summary>
        [DisplayFormat(DataFormatString = "Text")] 
        [DefaultValue("\\d{1,3}.\\d{1,3}.\\d{1,3}.\\d{1,3}")]
        public string[] WhiteListedIpAddress { get; set; }

        /// <summary>
        /// Blacklisted IP addresses and ranges which will be blocked by the process execution engine 
        /// </summary>
        [DisplayFormat(DataFormatString = "Text")] 
        [DefaultValue("\\d{1,3}.\\d{1,3}.\\d{1,3}.\\d{1,3}")]
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
        /// Define the allowed http headers
        /// </summary>
        [DisplayFormat(DataFormatString = "Text")] 
        [DefaultValue("Cookie")]
        public string[] AllowedHttpHeaders { get; set; }

        /// <summary>
        /// Request based http headers with a key value pair
        /// </summary>
        public Dictionary<string, string> HttpHeaders { get; set; }

    }

    /// <summary>
    /// Options class provides additional parameters.
    /// </summary>
    public class Options
    {
        /// <summary>
        /// How many iteration round for decoding of the payloadx.
        /// </summary>
        [DisplayFormat(DataFormatString = "Text")]
        [DefaultValue("2")]
        public int MaxIterations { get; set; }
        
        /// <summary>
        /// Which encoding should be used, default UTF-8.
        /// </summary>
        [DisplayFormat(DataFormatString = "Text")]
        [DefaultValue("UTF-8")]
        public string Encoding { get; set; }
    }
    
}
