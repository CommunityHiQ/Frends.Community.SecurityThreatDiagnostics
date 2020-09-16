using System;
using System.Collections;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Linq;
using Owin;
using SecurityHeadersMiddleware;
using SecurityHeadersMiddleware.OwinAppBuilder;

#pragma warning disable 1591

namespace Frends.Community.SecurityThreatDiagnostics
{
    using BuildFunc =
        Action<Func<IDictionary<string, object>,
            Func<Func<IDictionary<string, object>, Task>, Func<IDictionary<string, object>, Task>>>>;
    
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
            // TODO: https://help.hotjar.com/hc/en-us/articles/115012727628-How-to-Use-Regular-Expressions-for-Page-Targeting-and-IP-Blocking
            // 127\.76\.111\.(6[4-9]|7[1-9])
            // 0000:0000:0000:0000:0000:0000:0000:0001
            // \d{1,4}\.\d{1,4}\.\d{1,4}\.\d{1,4}\d{1,4}\.\d{1,4}\.\d{1,4}\.\d{1,4}
            // \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}

            IEnumerable<bool> isValidIPAddress = new List<bool>();

            //allowedIpAddresses.BlackListedIpAddresses
            //Uri uri = new Uri(allowedIpAddresses.Host);
            
            // HTTP GET only URL max length is 2048 marks.
            // if (allowedIpAddresses.Host.Length <= 2048)
            
            isValidIPAddress = allowedIpAddresses.WhiteListedIpAddress.ToList().Select(
                entry =>
                {
                    Uri inboundHost = new Uri(entry.ToString());
                    Regex allowedInboundTrafficRule = new Regex(inboundHost.Host);
                    return allowedInboundTrafficRule.IsMatch(allowedIpAddresses.Host);
                });
            
            isValidIPAddress = allowedIpAddresses.BlackListedIpAddresses.ToList().Select(
                entry =>
                {
                    Uri inboundHost = new Uri(entry.ToString());
                    Regex allowedInboundTrafficRule = new Regex(inboundHost.Host);
                    return allowedInboundTrafficRule.IsMatch(allowedIpAddresses.Host);
                });

            foreach (var b in isValidIPAddress.ToList())
            {
                if (b == true) return false;
                {
                    throw new ApplicationException("Invalid IP Address or range [" + b.ToString() + "]");
                }
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
            IAppBuilder appbuilder = null;
            BuildFunc buildFunc = null;

            // Add Strict-Transport-Security with the configured settings
            var config = new StrictTransportSecurityOptions {
                IncludeSubDomains = true,
                MaxAge = 31536000,
                RedirectToSecureTransport = true,
                RedirectUriBuilder = uri => whiteListedHeaders.HttpRedirectUri, // Only do this, when you want to replace the default behavior (from http to https).
                RedirectReasonPhrase = statusCode => "303 See Other"
            };

            buildFunc
                .AntiClickjackingHeader(new Uri(whiteListedHeaders.HttpUri), new Uri(whiteListedHeaders.HttpUri))
                .ContentTypeOptions()
                .StrictTransportSecurity(config)
                .XssProtectionHeader(true);//.ContentSecurityPolicyReportOnly(appbuilder, config);
            
            appbuilder
                .AntiClickjackingHeader(new Uri(whiteListedHeaders.HttpUri), new Uri(whiteListedHeaders.HttpUri))
                .ContentTypeOptions()
                .StrictTransportSecurity(config)
                .XssProtectionHeader(true);//.ContentSecurityPolicyReportOnly(appbuilder, config);
            
            //if (b == true) return false;
            {
                //throw new ApplicationException("Invalid HTTP header [" + b.ToString() + "]");
            }

            return null;
        }
    }
 
}