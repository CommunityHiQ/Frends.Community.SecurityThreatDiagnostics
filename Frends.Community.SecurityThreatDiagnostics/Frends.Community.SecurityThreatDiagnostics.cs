using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Linq;

#pragma warning disable 1591

namespace Frends.Community.SecurityThreatDiagnostics
{
    using BuildFunc = Action<Func<IDictionary<string, object>, Func<Func<IDictionary<string, object>, Task>, Func<IDictionary<string, object>, Task>>>>;
    
    public sealed class SecurityFilterReader
    {
        private static readonly object PadLock = new object();
        private static readonly Lazy<ConcurrentDictionary<string, Regex>>
            
            Lazy = 
                new Lazy<ConcurrentDictionary<string, Regex>>
                (() =>
                {
                    XDocument xdoc = XDocument.Parse(SecurityFilters.SecurityRules);
                    XmlReader reader = new XmlTextReader(new StringReader(xdoc.ToString()));
                    try
                    {
                        ConcurrentDictionary<string, Regex> concurrentRules = new ConcurrentDictionary<string, Regex>();
                        while (reader.Read())
                        {
                            switch (reader.NodeType)
                            {
                                case XmlNodeType.CDATA:
                                    string id = Guid.NewGuid().ToString();
                                    concurrentRules.TryAdd(id, new Regex(reader.Value, RegexOptions.IgnoreCase));
                                    break;
                            }
                        }
                        return concurrentRules;
                    }
                    finally
                    {
                        if (reader != null)
                            reader.Dispose();
                    }
                });
        
        public static ConcurrentDictionary<string, Regex> Instance
        {
            get
            {
                lock(PadLock)
                    return Lazy.Value;
            }
        }

    }

    public static class SecurityThreatDiagnostics
    {
        private static string encode(string encoding, string payload)
        {
            {
                // Create two different encodings.
                Encoding ascii = Encoding.GetEncoding(encoding);
                Encoding unicode = Encoding.Unicode;

                // Convert the string into a byte array.
                byte[] unicodeBytes = unicode.GetBytes(payload);

                // Perform the conversion from one encoding to the other.
                byte[] asciiBytes = Encoding.Convert(unicode, ascii, unicodeBytes);
         
                char[] asciiChars = new char[ascii.GetCharCount(asciiBytes, 0, asciiBytes.Length)];
                ascii.GetChars(asciiBytes, 0, asciiBytes.Length, asciiChars, 0);
                string asciiString = new string(asciiChars);

                return asciiString;
            }
        }
        
        /// <summary>
        /// This is task which validates data 
        /// Documentation: https://github.com/CommunityHiQ/Frends.Community.SecurityThreatDiagnostics
        /// </summary>
        /// <param name="validation">What to repeat.</param>
        /// <param name="options">Define if repeated multiple times. </param>
        /// <param name="cancellationToken"></param>
        /// <returns>{bool challenges} </returns>
        public static bool ChallengeAgainstSecurityThreats([PropertyTab] Validation validation,
            [PropertyTab] Options options, CancellationToken cancellationToken)
        {
            Dictionary<string, string> dictionary = new Dictionary<string, string>();
            StringBuilder validationChallengeMessage = new StringBuilder();
            validationChallengeMessage
                .Append("Payload challenged for input validation [")
                .Append(validation.Payload)
                .Append("] \n\n");

            ConcurrentDictionary<string, Regex> ruleDictionary = SecurityFilterReader.Instance;

            foreach (var entry in ruleDictionary)
            {
                string encoded = encode(options.Encoding ?? "UTF-8", validation.Payload);
                if (entry.Value.IsMatch(validation.Payload) || encoded.Length > 0 &&
                    entry.Value.IsMatch(encoded))
                {
                    validationChallengeMessage
                        .Append("id [")
                        .Append(entry.Key)
                        .Append("]")
                        .Append(" contains vulnerability [")
                        .Append(entry.Value).Append("], ")
                        .Append("encoded value [")
                        .Append(encoded)
                        .Append("]");
                    dictionary.Add(entry.Key, validationChallengeMessage.ToString());
                }
            }
            
            if (dictionary.Count > 0)
            {
                throw new ApplicationException(validationChallengeMessage.ToString());
            }

            return true;
        }

        /// <summary>
        ///  Verifies the whitelist of known IP addresses
        /// </summary>
        /// <param name="allowedIpAddresses">Define IP addresses which can bypass the validation.</param>
        /// <param name="cancellationToken"></param>
        /// <returns>{bool challanges}</returns>
        public static bool ChallengeIPAddresses(
            [PropertyTab] AllowedIPAddresses allowedIpAddresses,
            CancellationToken cancellationToken)
        {
            List<string> invalidIPAddresses = new List<string>();
            allowedIpAddresses.WhiteListedIpAddress?.ToList().ForEach(
                entry =>
                {
                    Regex allowedInboundTrafficRule = new Regex(entry);
                    if  (!allowedInboundTrafficRule.IsMatch(allowedIpAddresses.Host)) 
                    {
                        invalidIPAddresses.Append(entry);
                    }
                });
            
            allowedIpAddresses.BlackListedIpAddresses?.ToList().ForEach(
                entry =>
                {
                    Regex allowedInboundTrafficRule = new Regex(entry);
                    if (allowedInboundTrafficRule.IsMatch(allowedIpAddresses.Host))
                    {
                        invalidIPAddresses.Append(entry);
                    }
                });
            
            if (invalidIPAddresses.Count > 0)
            {
                throw new ApplicationException("Invalid IP Address or range [" + allowedIpAddresses.Host + "]");
            }
            
            return true;
        }
        
        /// <summary>
        ///  Verifies the header content and validates data.
        /// </summary>
        /// <param name="WhiteListedHeaders">Known HTTP headers to be bypassed in validation.</param>
        /// <param name="cancellationToken"></param>
        /// <returns>{bool challanges}</returns>
        public static bool ChallengeSecurityHeaders([PropertyTab] WhiteListedHeaders whiteListedHeaders, CancellationToken cancellationToken)
        {
            Dictionary<string, string> dictionary = new Dictionary<string, string>();
            ConcurrentDictionary<string, Regex> ruleDictionary = SecurityFilterReader.Instance;
            
            StringBuilder validationChallengeMessage = new StringBuilder();
            validationChallengeMessage
                .Append("HTTP headers challenged for input validation ");
            
            foreach (KeyValuePair<string, string> kvp in whiteListedHeaders.HttpHeaders)
            {
                whiteListedHeaders?.AllowedHttpHeaders?.ToList().Select(allowedHeader =>
                {
                    if (kvp.Key.Equals(allowedHeader))
                    {
                        foreach (var rule in ruleDictionary)
                        {
                            if (rule.Value.IsMatch(kvp.Value))
                            {
                                validationChallengeMessage
                                    .Append("Header [")
                                    .Append(rule.Key)
                                    .Append("]")
                                    .Append(" contains vulnerability [")
                                    .Append(rule.Value)
                                    .Append("]");
                                dictionary.Add(rule.Key, validationChallengeMessage.ToString());
                            }
                        }
                    }
                    else
                    {
                        StringBuilder builder = new StringBuilder("Invalid Header name [");
                        builder
                            .Append(kvp.Key)
                            .Append("] found.");
                    }
                    return allowedHeader;
                });
            }
            
            if (dictionary.Count > 0)
            {
                StringBuilder builder = new StringBuilder("Invalid Header information contains [");
                builder.Append(dictionary.Count).Append("]\n\n");
                builder.Append(validationChallengeMessage.ToString());
                throw new ApplicationException(builder.ToString());
            }
            
            return true;
        }
    }
 
}