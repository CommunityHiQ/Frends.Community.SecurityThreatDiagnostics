using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Xml.Linq;

#pragma warning disable 1591

namespace Frends.Community.SecurityThreatDiagnostics
{
    public class SecurityRuleFilter
    {
        public string Id { get; set; }

        public Regex Rule { get; set; }

        public string Description { get; set; }
    }

    public class SecurityFilterReader
    {
        private static readonly Lazy<List<SecurityRuleFilter>>
            Lazy =
                new Lazy<List<SecurityRuleFilter>>
                (() =>
                {
                    var ruleXml = XElement.Parse(SecurityFilters.SecurityRules);
                    XNamespace ns = "http://www.w3.org/2001/XMLSchema";
                    var rules = ruleXml.Descendants(ns + "element")
                        .Where(e => e?.Attribute("name")?.Value == "Filter")
                        .Select(xmlRule => new SecurityRuleFilter
                        {
                            Id = xmlRule.Descendants(ns + "attribute").Single(a => a?.Attribute("name")?.Value == "id")
                                .Value,
                            Description = xmlRule.Descendants(ns + "attribute")
                                .Single(a => a?.Attribute("name")?.Value == "description").Value,
                            Rule = new Regex(xmlRule.Descendants(ns + "attribute")
                                .Single(a => a?.Attribute("name")?.Value == "rule")
                                .Value)
                        })
                        .ToList();
                    return rules;
                });

        /// <summary>Gives instance access into the dictionary of security rule filters. Uses a static lazily
        /// initialized singleton 
        /// </summary>    
        public static List<SecurityRuleFilter> Instance => Lazy.Value;
    }

    /// <summary>
    /// This is a Task library which provides different ways of validating input
    /// Documentation: https://github.com/CommunityHiQ/Frends.Community.SecurityThreatDiagnostics
    /// Throws an exception if diagnostics finds a suspected vulnerability from the challenged payload.
    /// </summary>
    public static class SecurityThreatDiagnostics
    {
        /// <summary>
        /// Runs options.MaxIterations of UrlDecode on the payload
        /// </summary>
        /// <param name="payload"></param>
        /// <param name="options"></param>
        /// <returns></returns>
        private static string IterativeUrlDecode(string payload, ChallengeUrlEncodingOptions options)
        {
            for (var i = 0; i < options.Iterations; i++)
            {
                payload = WebUtility.UrlDecode(payload);
            }

            return payload;
        }

        /// <summary>
        /// If payload is Base64 encoded it will be returned back as decoded into ASCII. If message is not Base64 encoded the original string will be returned.
        /// </summary>
        private static bool TryDecodeBase64EncodingToAscii(string payload, out string base64DecodedResult)
        {
            base64DecodedResult = string.Empty;
            try
            {
                var data = Convert.FromBase64String(payload);
                base64DecodedResult = Encoding.ASCII.GetString(data);
                return true;
            }
            catch (FormatException)
            {
                return false;
            }
        }

        private static EncodingConversionResult TryChangeCharacterEncoding(string payload, Options options)
        {
            try
            {
                // TODO: Should we do anything here if the source and destination encoding are the same
                
                // Create two different encodings.
                var sourceEncoding = Encoding.GetEncoding(options.SourceEncoding);
                // Encoding of the underlying system.
                var destinationEncoding = Encoding.GetEncoding(options.DestinationEncoding);
                // Convert the string into a byte array.
                var sourceBytes = sourceEncoding.GetBytes(payload);

                // Perform the conversion from one encoding to the other.
                var destinationBytes = Encoding.Convert(sourceEncoding, destinationEncoding, sourceBytes);

                // Turn into destination encoding
                return new EncodingConversionResult
                {
                    Result = destinationEncoding.GetString(destinationBytes),
                    IsValid = true,
                    Error = null
                };
            }
            catch (Exception e)
            {
                return new EncodingConversionResult
                {
                    Result = null,
                    IsValid = false,
                    Error = e.Message
                };
            }
        }

        /// <summary>
        /// This is a task which challenges the payload attributes from client side character set encoding to target system character set encoding.
        /// Documentation: https://github.com/CommunityHiQ/Frends.Community.SecurityThreatDiagnostics
        /// Throws application exception if diagnostics find a vulnerability from the payload
        /// </summary>
        public static SecurityThreatDiagnosticsResult ChallengeCharacterSetEncoding(string payload, Options options)
        {
            var result = TryChangeCharacterEncoding(payload, options);
            if (!result.IsValid)
            {
                var errorMessage =
                    $@"Security Threat Diagnostics vulnerability report invalid character encoding: {result.Error}
            Security Threat Diagnostics found the following attack vectors: Payload contains illegal characters: {payload}";

                throw new ValidationChallengeException(errorMessage);
            }

            return new SecurityThreatDiagnosticsResult {IsValid = true};
        }

        /// <summary>
        /// This Task validates against common attack patterns inside of the payload
        /// Documentation: https://github.com/CommunityHiQ/Frends.Community.SecurityThreatDiagnostics
        /// Throws an exception if diagnostics find a vulnerability from the payload challenge.
        /// </summary>
        public static SecurityThreatDiagnosticsResult ChallengeAttributesAgainstSecurityThreats(
            [PropertyTab] ValidationAttributes validationAttributes,
            [PropertyTab] Options options,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var validationErrors = new List<string>();
            foreach (var attribute in validationAttributes.Attribute)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var validationInput = new ValidationInput {Payload = attribute};

                validationErrors.AddRange(GetValidationErrorsFor(validationInput, options, cancellationToken));
            }

            if (validationErrors.Any())
            {

                throw new ValidationChallengeException($"Security Threat Diagnostics vulnerability report for attributes contains the following invalid messages. See ValidationErrors for details.", validationErrors);
            }

            return new SecurityThreatDiagnosticsResult {IsValid = true};
        }

        /// <summary>
        /// This is task which validates data 
        /// Documentation: https://github.com/CommunityHiQ/Frends.Community.SecurityThreatDiagnostics
        /// Throws application exception if diagnostics find vulnerability from the payload challenge.
        /// </summary>
        /// <param name="validationInput">Runtime element to be diagnosted.</param>
        /// <param name="options">Options for the runtime validation.</param>
        /// <param name="cancellationToken"></param>
        /// <returns>{bool challenges for validation} </returns>
        public static SecurityThreatDiagnosticsResult ChallengeAgainstSecurityThreats(
            [PropertyTab] ValidationInput validationInput,
            [PropertyTab] Options options,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var validationErrors = GetValidationErrorsFor(validationInput, options, cancellationToken);

            if (validationErrors.Any())
            {
                throw new ValidationChallengeException("Security threat validation failed" ,validationErrors);
            }

            return new SecurityThreatDiagnosticsResult {IsValid = true};
        }

        private static List<string> GetValidationErrorsFor(ValidationInput validationInput, Options options,
            CancellationToken cancellationToken)
        {
            var validationErrors = new List<string>();

            var rules = SecurityFilterReader.Instance;

            // Check encoding before anything else
            ChallengeCharacterSetEncoding(validationInput.Payload, options);

            // Get a list of failed validation rules:
            foreach (var rule in rules)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var wasBase64encoded = false;
                string base64DecodedPayload = string.Empty;
                if (rule.Rule.IsMatch(validationInput.Payload) ||
                    options.Base64Decode &&
                    (wasBase64encoded =
                        TryDecodeBase64EncodingToAscii(validationInput.Payload, out base64DecodedPayload)) &&
                    rule.Rule.IsMatch(base64DecodedPayload))
                {
                    if (!wasBase64encoded)
                    {
                        validationErrors.Add(
                            
                            $"Input matches vulnerability id [{rule.Id}] [{rule.Description}], value [{validationInput.Payload}] with pattern [{rule.Rule}]");
                    }
                    else
                    {
                        validationErrors.Add(
                            $"Input matches vulnerability id [{rule.Id}] [{rule.Description}], encoded value [{base64DecodedPayload}] with pattern [{rule.Rule}]");
                    }
                }
            }

            return validationErrors;
        }

        /// <summary>
        ///  Verifies that the IP is in given whitelist of known IP addresses.
        /// Documentation: https://github.com/CommunityHiQ/Frends.Community.SecurityThreatDiagnostics
        /// Throws application exception if diagnostics find that IP address is not valid.
        /// </summary>
        /// <param name="ipAddressValidationInput">Define IP addresses which can bypass the validation.</param>
        /// <param name="cancellationToken"></param>
        /// <returns>{SecurityThreatDiagnosticsResult.IsValid challenge}</returns>
        public static SecurityThreatDiagnosticsResult ChallengeIPAddresses(
            [PropertyTab] IpAddressValidationInput ipAddressValidationInput,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var invalidIPAddresses = new List<string>();

            invalidIPAddresses.AddRange(
                ipAddressValidationInput?.WhiteListedIpAddresses?
                    .Where(ipToAllow => !new Regex(ipToAllow).IsMatch(ipAddressValidationInput.IpAddressToValidate))
                ?? new List<string>());

            invalidIPAddresses.AddRange(
                ipAddressValidationInput?.BlackListedIpAddresses?
                    .Where(ipToDeny => new Regex(ipToDeny).IsMatch(ipAddressValidationInput.IpAddressToValidate))
                ?? new List<string>());

            if (invalidIPAddresses.Any())
            {
                throw new ValidationChallengeException($"Invalid IP Address or range [{ipAddressValidationInput?.IpAddressToValidate}]");
            }

            return new SecurityThreatDiagnosticsResult {IsValid = true};
        }

        /// <summary>
        ///  Verifies the header content and validates data.
        /// Documentation: https://github.com/CommunityHiQ/Frends.Community.SecurityThreatDiagnostics
        /// Throws application exception if diagnostics find that header data is not valid.
        /// </summary>
        /// <param name="input">Known HTTP headers to be bypassed in validation.</param>
        /// <param name="options">Configuration of the task</param>
        /// <param name="cancellationToken"></param>
        /// <returns>{SecurityThreatDiagnosticsResult.IsValid challenge}</returns>
        public static SecurityThreatDiagnosticsResult ChallengeSecurityHeaders(
            [PropertyTab] ChallengeSecurityHeadersInput input,
            [PropertyTab] Options options,
            CancellationToken cancellationToken)
        {
            // TODO: Does this work correctly? When allowing all headers and making a plain chrome request, it detects vulnerabilities
            cancellationToken.ThrowIfCancellationRequested();
            var ruleDictionary = SecurityFilterReader.Instance;

            var validationErrors = new List<string>();

            var httpHeaders = ConvertHeadersToDictionary(input?.HttpHeaders);

            var allHeadersAllowed =
                input?.AllowedHttpHeaders?.Any(header => header.Trim() == "*") ?? false;

            foreach (var httpHeaderPair in httpHeaders)
            {
                // Is the header allowed, * allows all headers
                if (!allHeadersAllowed
                    &&
                    !(input?.AllowedHttpHeaders?.Contains(httpHeaderPair.Key,
                        StringComparer.InvariantCultureIgnoreCase) ?? false))
                {
                    validationErrors.Add($"Forbidden header [{httpHeaderPair.Key}] found");
                    continue; // header already not allowed continue to the next one
                }

                // Does the header contain anything suspicious?

                var changedEncodingResult =
                    TryChangeCharacterEncoding(httpHeaderPair.Value, options);
                if (!changedEncodingResult.IsValid)
                {
                    validationErrors.Add($"Could not validate character encoding for header [{httpHeaderPair.Key}]");
                    continue; // This header failed validation on character encoding, check the next one
                }


                validationErrors
                    .AddRange(
                        ruleDictionary.Where(r =>
                                r.Rule.IsMatch(httpHeaderPair.Value) // Rule matches directly
                                ||
                                // Base64Decode is used and data is base64 and it matches
                                (options.Base64Decode &&
                                 TryDecodeBase64EncodingToAscii(httpHeaderPair.Value, out var base64DecodedValue) &&
                                 r.Rule.IsMatch(base64DecodedValue)))
                            .Select(r =>
                                $"Header [{httpHeaderPair.Key}] matches vulnerability [{r.Description}] id [{r.Id}]")
                    );
            }

            if (validationErrors.Any())
            {
                throw new ValidationChallengeException("Some headers did not pass validation. See ValidationErrors for details.", validationErrors);
            }

            var securityThreatDiagnosticsResult = new SecurityThreatDiagnosticsResult {IsValid = true};

            return securityThreatDiagnosticsResult;
        }

        private static IDictionary<string,string> ConvertHeadersToDictionary(dynamic inputHttpHeaders)
        {
            // headers are already in dictionary format -> just return
            if (inputHttpHeaders is IDictionary<string, string> headers)
            {
                return headers;
            }

            var headersType = inputHttpHeaders.GetType().ToString();
            if (headersType.Contains("CaseInsensitivePropertyTree"))
            {
                // The headers are in the internal frends CaseInsensitivePropertyTree format, probably passed directly with #trigger.data.httpHeaders
                return ((IDictionary<string, object>) inputHttpHeaders
                    .GetCaseInsensitivePropertyDictionary())
                    .ToDictionary(kvp => kvp.Key, kvp => kvp.Value.ToString());
            }

            throw new Exception(
                "Headers format unrecognized, expected a Dictionary<string,string> or CaseInsensitivePropertyTree");
        }


        /// <summary>
        ///  Challenges character encoding of the given data.
        /// Documentation: https://github.com/CommunityHiQ/Frends.Community.SecurityThreatDiagnostics
        /// Throws application exception if diagnostics find that character is not part of the encoding set.
        /// </summary>
        /// <param name="validationInput">Data to be passed into the validation.</param>
        /// <param name="options">Configuration parameters</param>
        /// <param name="cancellationToken"></param>
        /// <returns>{SecurityThreatDiagnosticsResult.IsValid challenge}</returns>
        public static SecurityThreatDiagnosticsResult ChallengeUrlEncoding
        (
            [PropertyTab] ValidationInput validationInput,
            [PropertyTab] ChallengeUrlEncodingOptions options,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            validationInput.Payload = IterativeUrlDecode(validationInput.Payload, options);
            var errors = GetValidationErrorsFor(validationInput, options, cancellationToken);

            if (errors.Any())
            {
                throw new ValidationChallengeException($"Found dangerous URL encoded input for [{validationInput.Payload}]. See ValidationErrors for details.", errors);
            }

            return new SecurityThreatDiagnosticsResult
            {
                IsValid = true
            };
        }
    }

    public class EncodingConversionResult
    {
        public string Result { get; set; }
        public bool IsValid { get; set; }
        public string Error { get; set; }
    }
}