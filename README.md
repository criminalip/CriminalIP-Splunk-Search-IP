# Criminal IP Search for Splunk

Criminal IP Search App for Splunk is a command that integrates with Splunk Search, enabling users to retrieve detailed analysis data from Criminal IP for IP addresses identified in incoming logs.

## Description
This app allows Splunk users to enrich their log data with IP intelligence from Criminal IP, providing additional context for security analysis and threat hunting.

## Binary File Declaration
### charset_normalizer Binaries
The following binary files are part of the charset_normalizer package, which is a dependency of the requests library used in this app:

- lib/charset_normalizer/md.cpython-310-x86_64-linux-gnu.so
  - Source: charset_normalizer package (https://github.com/Ousret/charset_normalizer)
  - Version: 3.3.2
  - Purpose: Character encoding detection and normalization
  - Used by: requests library as a dependency
  - License: MIT

- lib/charset_normalizer/md__mypyc.cpython-310-x86_64-linux-gnu.so
  - Source: charset_normalizer package (https://github.com/Ousret/charset_normalizer)
  - Version: 3.3.2
  - Purpose: Character encoding detection and normalization
  - Used by: requests library as a dependency
  - License: MIT

These binary files are essential components of the requests library, which is used for making HTTP requests to the Criminal IP API. The charset_normalizer package helps in detecting and handling different character encodings in HTTP responses.

## Requirements
- Splunk Cloud / Enterprise 9.0 or later
- Criminal IP API key

## Support
For support, please contact AI Spera Inc.