using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;
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
        private static readonly Lazy<XmlReader>
            lazy = 
                new Lazy<XmlReader>
                (() => {
                    SecurityFilters securityFilters = new SecurityFilters();
                    XmlReader reader = new XmlTextReader(securityFilters.ToString());
                    return reader;
                });
        public static XmlReader Instance { get { return lazy.Value; } }
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

            XmlReader reader = SecurityFilterReader.Instance;
            
            while (reader.Read())
            {
                string id = Guid.NewGuid().ToString();
                switch (reader.NodeType)
                {
                    case XmlNodeType.CDATA:
                        Regex validationPattern = new Regex(reader.Value, RegexOptions.IgnoreCase);
                        if (validationPattern.Matches(validation.Payload).Count > 0)
                        {
                            validationChallengeMessage
                                .Append("id [")
                                .Append(id)
                                .Append("]")
                                .Append(" contains vulnerability [")
                                .Append(reader.Value).Append("]");
                            dictionary.Add(id, validationChallengeMessage.ToString());
                        }
                        break;
                }
            }

            dictionary.ToList().ForEach(entry => Console.Out.WriteLine(entry.ToString()));
            if (dictionary.Count > 0)
            {
                throw new ApplicationException(validationChallengeMessage.ToString());
            }
            return false;
        }
        
        /// <summary>
        ///  Verifies the whitelist of known IP addresses
        /// </summary>
        /// <param name="whiteListedIPs">Define IP addresses which can bypass the validation.</param>
        /// <param name="cancellationToken"></param>
        public static bool ChallengeIPAddresses([PropertyTab] WhiteListedIPs whiteListedIPs, CancellationToken cancellationToken)
        {
            Uri uri = new Uri (whiteListedIPs.Host);
            return whiteListedIPs.IpAddress.ToList().Select(
                entry => 
                    entry.ToString().Equals(uri.Host)) != null ? true : false;
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

            return null;
        }
    }
 
}