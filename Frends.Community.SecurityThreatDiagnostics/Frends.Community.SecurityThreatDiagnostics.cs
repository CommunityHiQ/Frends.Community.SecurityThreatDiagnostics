using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Net;
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

    public class SecurityRuleFilter
    {
        public string Id  { get; set; }
        
        public Regex Rule { get; set; }
        
        public string Description  { get; set; }
    }

    public sealed class SecurityFilterReader
    {
        private static readonly object PadLock = new object();
        private static readonly Lazy<ConcurrentDictionary<string, SecurityRuleFilter>>

            Lazy = 
                new Lazy<ConcurrentDictionary<string, SecurityRuleFilter>>
                (() =>
                {
                    XDocument xdoc = XDocument.Parse(SecurityFilters.SecurityRules);
                    XmlReader reader = new XmlTextReader(new StringReader(xdoc.ToString()));
                    try
                    {
                        ConcurrentDictionary<string, SecurityRuleFilter> concurrentRules = new ConcurrentDictionary<string, SecurityRuleFilter>();
                        while (reader.Read())
                        {
                            SecurityRuleFilter securityRuleFilter = new SecurityRuleFilter();
                            string id = Guid.NewGuid().ToString();
                            switch (reader.NodeType)
                            {
                                case XmlNodeType.CDATA:
                                    securityRuleFilter.Id = id;
                                    securityRuleFilter.Rule = new Regex(reader.Value, RegexOptions.IgnoreCase);
                                    break;
                                case XmlNodeType.Element:
                                {
                                    securityRuleFilter.Description = reader.GetAttribute("description");
                                    break;
                                } 
                           } 
                           if (securityRuleFilter.Id != null) {
                                concurrentRules.TryAdd(id, securityRuleFilter);
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
        
        public static ConcurrentDictionary<string, SecurityRuleFilter> Instance
        {
            get
            {
                lock(PadLock)
                    return Lazy.Value;
            }
        }

    }

    /// <summary>
    /// This is task which validates the common attack patterns against the underlying system.
    /// Documentation: https://github.com/CommunityHiQ/Frends.Community.SecurityThreatDiagnostics
    /// Throws application exception if diagnostics find vulnerability from the payload challenge.
    /// </summary>
    public static class SecurityThreatDiagnostics
    {
        private static string encode(string payload, Options options)
        {
            for (int i = 0; i < options.MaxIterations; i++)
            {
                payload = WebUtility.UrlDecode(payload);
            }
            return payload;
        }
        
        private static string encode(string encoding, Options options, string payload)
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
        /// Throws application exception if diagnostics find vulnerability from the payload challenge.
        /// </summary>
        /// <param name="validation">Runtime element to be diagnosted.</param>
        /// <param name="options">Options for the runtime validation.</param>
        /// <param name="cancellationToken"></param>
        /// <returns>{bool challenges for validation} </returns>
        public static bool ChallengeAgainstSecurityThreats(
            [PropertyTab] Validation validation,
            [PropertyTab] Options options, 
            CancellationToken cancellationToken)
        {
            Dictionary<string, string> dictionary = new Dictionary<string, string>();
            StringBuilder validationChallengeMessage = new StringBuilder();
            validationChallengeMessage
                .Append("Payload challenged for input validation [")
                .Append(validation.Payload)
                .Append("] \n\n");

            StringBuilder innerExceptionMessage = new StringBuilder();
            innerExceptionMessage
                .Append("Payload challenged for input validation [")
                .Append(validation.Payload)
                .Append("] \n\n");
            
            ConcurrentDictionary<string, SecurityRuleFilter> ruleDictionary = SecurityFilterReader.Instance;

            foreach (var entry in ruleDictionary)
            {
                string encoded = encode(validation.Payload, options);
                if (entry.Value.Rule.IsMatch(validation.Payload) ||
                    entry.Value.Rule.IsMatch(encoded))
                {
                    validationChallengeMessage
                        .Append("id [")
                        .Append(entry.Key)
                        .Append("]")
                        .Append(" contains vulnerability [")
                        .Append(entry.Value.Description)
                        .Append("], ")
                        .Append("encoded value [")
                        .Append(encoded)
                        .Append("]");
                    dictionary.Add(entry.Key, validationChallengeMessage.ToString());
                    innerExceptionMessage
                        .Append("id [")
                        .Append(entry.Key)
                        .Append("] ")
                        .Append("Validation pattern [")
                        .Append(entry.Value.Rule.ToString())
                        .Append("], ")
                        .Append("encoded value [")
                        .Append(encoded)
                        .Append("]");
                }
            }
            
            if (dictionary.Count > 0)
            {
                ArgumentException argumentException = new ArgumentException("Invalid argument information " + innerExceptionMessage.ToString());
                ApplicationException applicationException = new ApplicationException(validationChallengeMessage.ToString(), argumentException);
                throw applicationException;
            }

            return true;
        }
        
        /// <summary>
        ///  Verifies that the IP is in given whitelist of known IP addresses.
        /// Documentation: https://github.com/CommunityHiQ/Frends.Community.SecurityThreatDiagnostics
        /// Throws application exception if diagnostics find that IP address is not valid.
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
        /// Documentation: https://github.com/CommunityHiQ/Frends.Community.SecurityThreatDiagnostics
        /// Throws application exception if diagnostics find that header data is not valid.
        /// </summary>
        /// <param name="WhiteListedHeaders">Known HTTP headers to be bypassed in validation.</param>
        /// <param name="cancellationToken"></param>
        /// <returns>{bool challanges}</returns>
        public static bool ChallengeSecurityHeaders(
            [PropertyTab] WhiteListedHeaders whiteListedHeaders, 
            [PropertyTab] Options options, 
            CancellationToken cancellationToken)
        {
            Dictionary<string, string> dictionary = new Dictionary<string, string>();
            ConcurrentDictionary<string, SecurityRuleFilter> ruleDictionary = SecurityFilterReader.Instance;
            
            StringBuilder validationChallengeMessage = new StringBuilder();
            validationChallengeMessage
                .Append("HTTP headers challenged for input validation ");
            
            StringBuilder innerExceptionMessage = new StringBuilder();
            innerExceptionMessage
                .Append("HTTP headers challenged for input validation, \n");
            
            foreach (KeyValuePair<string, string> HttpHeaderPair in whiteListedHeaders?.HttpHeaders)
            {
                whiteListedHeaders?.AllowedHttpHeaders?.ToList().Select(allowedHeader =>
                {
                    if (HttpHeaderPair.Key.Equals(allowedHeader))
                    {
                        foreach (var rule in ruleDictionary)
                        {
                            //string encoded = encode(options.Encoding ?? "UTF-8", HttpHeaderPair.Value);
                            string encoded = encode(HttpHeaderPair.Value, options);
                            if (rule.Value.Rule.IsMatch(HttpHeaderPair.Value) || encoded.Length > 0 &&
                                rule.Value.Rule.IsMatch(encoded))
                            if (rule.Value.Rule.IsMatch(HttpHeaderPair.Value))
                            {
                                validationChallengeMessage
                                    .Append("Header [")
                                    .Append(rule.Key)
                                    .Append("]")
                                    .Append(" contains vulnerability [")
                                    .Append(rule.Value.Description)
                                    .Append("]");
                                dictionary.Add(rule.Value.Id, innerExceptionMessage.ToString());
                                innerExceptionMessage
                                    .Append("id [")
                                    .Append(HttpHeaderPair.Key)
                                    .Append("]")
                                    .Append(HttpHeaderPair.Value)
                                    .Append("], ")
                                    .Append("encoded value [")
                                    .Append(encoded)
                                    .Append("]");
                            }
                        }
                    }
                    else
                    {
                        StringBuilder builder = new StringBuilder("Invalid Header name [");
                        builder
                            .Append(HttpHeaderPair.Key)
                            .Append("] found.");
                    }
                    return allowedHeader;
                });
            }
            
            if (dictionary.Count > 0)
            {
                ArgumentException argumentException = new ArgumentException("Invalid argument information " + innerExceptionMessage.ToString());
                StringBuilder builder = new StringBuilder("Invalid Header information contains [");
                builder.Append(dictionary.Count).Append("]\n\n");
                builder.Append(validationChallengeMessage.ToString());
                throw new ApplicationException(builder.ToString(), argumentException);
            }
            
            return true;
        }
        
        
        /// <summary>
        ///  Challenges character encoding of the given data.
        /// Documentation: https://github.com/CommunityHiQ/Frends.Community.SecurityThreatDiagnostics
        /// Throws application exception if diagnostics find that character is not part of the encoding set.
        /// </summary>
        /// <param name="WhiteListedHeaders">Known HTTP headers to be bypassed in validation.</param>
        /// <param name="cancellationToken"></param>
        /// <returns>{bool challanges}</returns>
        public static bool ChallengeCharacterEncoding(
            [PropertyTab] Validation validation,     
            [PropertyTab] Options options, 
            CancellationToken cancellationToken)
        {
            try
            {
                encode(options.Encoding, options, validation.Payload);
            }
            catch (Exception exception)
            {
                StringBuilder builder = new StringBuilder("Invalid encoding in character set [");
                builder
                    .Append(validation.Payload)
                    .Append("]");
                ArgumentException argumentException = new ArgumentException("Invalid encoding information "  + exception.ToString(), exception);
                throw new ApplicationException(builder.ToString(), argumentException);                
            }
            return true;
        }
    }
    
}