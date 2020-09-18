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
using SecurityHeadersMiddleware;

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
        /// <summary>
        /// This is task which validates data 
        /// Documentation: https://github.com/CommunityHiQ/Frends.Community.SecurityThreatDiagnostics
        /// </summary>
        /// <param name="validation">What to repeat.</param>
        /// <param name="options">Define if repeated multiple times. </param>
        /// <param name="cancellationToken"></param>
        /// <returns>{bool Replication} </returns>
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
                if (entry.Value.IsMatch(validation.Payload))
                {
                    validationChallengeMessage
                        .Append("id [")
                        .Append(entry.Key)
                        .Append("]")
                        .Append(" contains vulnerability [")
                        .Append(entry.Value).Append("]");
                    dictionary.Add(entry.Key, validationChallengeMessage.ToString());
                }
            }

            //dictionary.ToList().ForEach(entry => Console.Out.WriteLine(entry.ToString()));
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
        /// <returns>{string Result} </returns>
        public static Result ChallengeSecurityHeaders([PropertyTab] WhiteListedHeaders whiteListedHeaders, CancellationToken cancellationToken)
        {
            //BuildFunc buildFunc = BuildFunc;

            // Add Strict-Transport-Security with the configured settings
            var config = new StrictTransportSecurityOptions {
                IncludeSubDomains = true,
                MaxAge = 31536000,
                RedirectToSecureTransport = true,
                RedirectUriBuilder = uri => whiteListedHeaders.HttpRedirectUri, // Only do this, when you want to replace the default behavior (from http to https).
                RedirectReasonPhrase = statusCode => "303 See Other"
            };
            // TODO : Logic for verifying HTTP headers
            return null;
        }
    }
 
}