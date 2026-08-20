Trellix Endpoint Detection and
Response Product Guide
Last Updated: August 11, 2026

Contents
Trellix EDR APIs . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 5
API sample for real-time search . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 8
POST request . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 9
Get status . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 12
Get result . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 14
Get result — file export . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 21
The Real-time Search API response objects or artifacts . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 24
API sample for historical search . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 33
POST request . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 34
Get status . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 39
Get result . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 42
Get result — file export . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 49
API sample for investigation . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 52
POST request . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 52
Get Investigations . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 55
Get Investigations by ID . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 58
Patch investigations . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 62
Delete investigations . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 65
POST - Metadata . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 67
GET - Evidence . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 70
API sample for remediation . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 74
POST - Host Remediation . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 74
POST - Search Remediation . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 78
POST - Threat Remediation . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 81
POST - Global-Threats . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 84

POST - Exclusions . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 87
GET - Exclusions . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 90
GET - Exclusions by ID . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 93
PATCH - Exclusions by ID . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 96
DELETE - Exclusions by ID . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 99
GET - Remediation status . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 101
GET - Actions . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 104
GET - host-info . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 107
API sample for threats and alerts . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 110
GET - Threats . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 111
GET - Threats by ID . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 117
GET - Affected hosts by threat id . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 123
GET - Detections by threat id . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 127
Get Alerts . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 132
Get Alerts . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 137
API sample for activity feed . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 143
Post webhook verification . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 143
Post Activity Feed configuration . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 145
Get Activity Feed configuration . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 149
Get Activity feed configuration with ID . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 152
Patch Activity feed configuration with ID . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 154
Delete Activity feed configuration with ID . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 159
Delete all Activity feed configurations for a tenant . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 161
Set up your AWS S3 . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 163
Set up your Syslog . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 165
Set up your Webhook . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 168
API sample for collectors and reactions . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 169
Create Reaction . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 169
Get Reaction . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 173
Get Reaction with ID . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 176
Patch Reaction . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 179

Delete Reaction . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 182
Trellix EDR API rate limits . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . 183

1| Trellix EDR APIs
Trellix EDR APIs
Make sure to have these details ready before using any of these Trellix EDR APIs:
• Gateway URL — get the gateway URL from the Trellix on-boarding email. For example, https://api.manage.trellix.com.
• Authorization key — generate a token using the Trellix Developer portal or from Client Credentials option in Trellix IAM.
For more information on generating Client Credentials and Token from Trellix IAM, see Managing your client credentials in
IAM.
Note
If you encounter API SKU or Developer Hub SKU errors while accessing any information in the Trellix Developers portal
or Trellix Market place, use the following links:
• Trellix Developers Portal
• Trellix Marketplace
The client credentials are available in your Trellix on-boarding email. However, you can follow these steps to generate
credentials again
Managing your client credentials in IAM
To generate Client Credentials and Access Token from Trellix IAM, follow the below steps.
• Log in to the Trellix IAM with your user credentials.
• At the top right of the page, click on the user icon, and from the dropdown, select Client Credentials.
Trellix Endpoint Detection and Response Product Guide 5

1| Trellix EDR APIs
Another page opens where you can see your Trellix Application Programming Interface (API) key.
• At the top right corner of the page, click Add.
• (optional) Add a description for the new client credentials.
• Select all EDR-related scopes as shown below:
• Click Create.
• Your Client ID and Secret will be generated as shown below:
6 Trellix Endpoint Detection and Response Product Guide

1| Trellix EDR APIs
• Use the following API call to obtain the tenant token, which can then be used to make API calls:
curl --location 'https://iam.cloud.trellix.com/iam/v1.0/
token?grant_type=client_credentials&scope=<scope>' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--header 'Authorization: Basic <BASICAUTH>'
• x-api-key — get the x-api-key from your on-boarding email. Also, you can navigate to the API Access Information page to
fetch the API key.
You can use the following scopes to perform different operations:
• soc.hts.c — create historical search query
• soc.hts.r — read historical search query status and results
• soc.rts.c — create real-time search query
• soc.rts.r — read real-time search query status and results
• mi.user.investigate — read and write investigation cases
• soc.act.tg and mi.user.config — read and write remediation requests
• soc.act.tg — get threats and alerts
• soc.edrfd.w and soc.edrfd.r — read and write activity feed configurations
The API samples help you to create requests, get status, get results, and get results in the file format:
• API sample for Real-time Search
• API sample for Historical Search
• API sample for Investigation
• API sample for Remediation
• API sample for Threats and Alerts
Trellix Endpoint Detection and Response Product Guide 7

1| Trellix EDR APIs
• API sample for Activity feed
These samples can be used to understand the usage of APIs. For more details, see Trellix Developer Portal.
For details about API rate limits, see Trellix EDR API rate limits.
Sample scripts to consume Trellix EDR APIs
To understand and better usage of these APIs, see Trellix EDR API sample scripts from Trellix GitHub repository.
Trellix EDR API integration scripts
To enable certain API workflows, see Trellix EDR API integration scripts from Trellix GitHub repository.
These scripts replace the earlier scripts available in GitHub repository.
For detailed information about how to use these scripts, see readme.md from the particular sample or integration scripts on
Trellix GitHub repository.
Note
These Trellix EDR API scripts are intended solely for testing purposes. Please note that Trellix does not provide any support
for it.
API sample for real-time search
The real-time search APIs let you query live data from all connected endpoints — running processes, files, network connections,
installed software, and more. Use these endpoints to collect current endpoint state for investigation, threat hunting, or ingestion
into an external analysis pipeline.
Endpoints
Endpoint Description
POST request Use this to submit a query and start a search job.
Get status Use this to check whether a search job has finished.
Get result Use this to retrieve completed results as paginated
JSON.
8 Trellix Endpoint Detection and Response Product Guide

1| Trellix EDR APIs
Endpoint Description
Get result — file export Download the full result set as a CSV file.
Common reference
All endpoints use the same authentication and request headers. Responses use the s0–s5 severity scale. For details see, Security
levels.
POST request
Overview
This endpoint initiates an asynchronous real-time search across all connected endpoints. To use it, you submit a structured
query in the request body that specifies what data you want to collect, such as host information or running processes. The API
starts the search as a background job and returns a job ID, which you must then use with the status and results endpoints to
track the search's progress and retrieve the data once complete.
Authentication
Authentication type: Bearer Token, API Key.
You can create a token using client credentials obtained through the developer portal. The API Key (x-api-key) is provided in
your onboarding email or on the API Access Management page.
Path (or URL)
POST https://{Trellix EDR_gateway_URL}/edr/v2/searches/realtime
You can get the gateway URL from the Trellix on-boarding email. For example, https://api.manage.trellix.com.
Trellix Endpoint Detection and Response Product Guide 9

1| Trellix EDR APIs
Request
Request headers
Authorization: Bearer <your_bearer_token>
Content-Type: application/vnd.api+json
x-api-key: <your_api_key>
• Authorization: This header is used to authenticate your request. You need to replace <your_bearer_token> with the actual
token you generate.
• Content-Type: This header tells the server that the request body format is json:api. Even though this specific call has no
request body, the API requires this header.
• x-api-key: This is a custom header required by the Trellix API for authentication. You'll need to replace <your_api_key> with
the key from your onboarding email or the API Access Management page.
Request body
{
"data": {
"type": "realTimeSearches",
"attributes": {
"query": "Processes name, id where Processes name equals \"csrss\" and Processes name contains \"exe\""
}
}
}
For details about the Real-time Search response objects or artifacts to customize your query, see The Real-time Search response
objects or artifacts.
Request parameters
There are no request parameters.
Response
Response example
{
"data": {
"type": "queue-jobs",
10 Trellix Endpoint Detection and Response Product Guide

1| Trellix EDR APIs
"id": "rts-5432",
"attributes": {
"status": "in-progress"
},
"links": {
"self": "/edr/v2/searches/queue-jobs/rts-5432"
}
}
}
Response codes
Status Response Description
201 Created Your request was successful, and a new resource was created as a
result. Your request was successful, and a new resource was created.
The response includes details such as the resource ID, which you can
use to track or manage the resource.
400 Bad request The server couldn't understand your request, likely due to a syntax error
or an invalid parameter.
401 Access denied request Your request was rejected because it lacks valid authentication
credentials. Check your API key and token.
403 Forbidden You are not authorized to access this resource. While your credentials
may be valid, you don't have the necessary permissions.
404 Not Found The specific resource or endpoint you requested does not exist.
415 Unsupported Media Type The server rejected your request because the data format (Content-
Type) is not supported.
429 Too Many Requests You've exceeded the rate limit by sending too many requests in a short
period. The Retry-After header in the response will tell you how long to
wait before trying again.
500 Internal Server Error Something went wrong on the server's end. This is not an issue with
your request.
Trellix Endpoint Detection and Response Product Guide 11

1| Trellix EDR APIs
Get status
Overview
This endpoint retrieves the current status of a previously initiated asynchronous search. By providing the unique search-id in
the path, you can poll this endpoint to track the progress of a real-time or historical search. While the job is running, the API
returns the current status; once complete, it provides a redirect to the location where the final results can be retrieved.
You should use this API after initiating a search to monitor its progress. It is designed to be polled periodically within a script or
automated workflow to determine when the search results are ready for collection.
Authentication
Authentication type: Bearer Token, API Key.
You can create a token using client credentials obtained through the developer portal. The API Key (x-api-key) is provided in
your onboarding email or on the API Access Management page.
Path (or URL)
GET https://{Trellix EDR_gateway_URL}/edr/v2/searches/queue-jobs/{search-id}
Example — {search-id}: rts-12212
Request
Request headers
Authorization: Bearer <your_bearer_token>
Content-Type: application/vnd.api+json
x-api-key: <your_api_key>
Accept-Encoding: gzip
• Authorization: This header is used to authenticate your request. You need to replace <your_bearer_token> with the actual
token you generate.
• Content-Type: This header tells the server that the request body format is json:api. Even though this specific call has no
request body, the API requires this header.
• x-api-key: This is a custom header required by the Trellix API for authentication. You'll need to replace <your_api_key> with
12 Trellix Endpoint Detection and Response Product Guide

1| Trellix EDR APIs
the key from your onboarding email or the API Access Management page.
• Accept-Encoding: This is an optional header you can include to tell the server you can accept a compressed response (using
gzip), which can make the data transfer faster.
Request parameters
Parameters Data type/Values Description
searchId string Search id of the search in progress.
export boolean Applicable only for specific related historical/device searches.
If set to True, this parameter must be used in the following APIs:
• /edr/vv2/searches/historical
• /edr/v2/searches/queue-jobs/{searchId}
• /edr/v2/searches/historical/{searchId}/results
Default value: False.
Response
Response example
{
"data": {
"type": "queue-jobs",
"id": "hs-01b5865f-0905-0572-002a-7003d239d812.346565425a0b6b2b7174aa555f67a043",
"attributes": {
"status": "in-progress"
}
}
}
Response codes
Status Response Description
200 OK Your request was successful. The response contains the current job
Trellix Endpoint Detection and Response Product Guide 13

1| Trellix EDR APIs
Status Response Description
status. The search is still in progress, and you must wait until it finishes
before retrieving the results.
303 See Other The search job has completed. The response includes a redirect
(Location header) to the results endpoint, where you can retrieve the
final search data.
400 Bad request The server couldn't understand your request, likely due to a syntax error
or an invalid parameter.
401 Access denied request Your request was rejected because it lacks valid authentication
credentials. Check your API key and token.
403 Forbidden You are not authorized to access this resource. While your credentials
may be valid, you don't have the necessary permissions.
404 Not Found The specific resource or endpoint you requested does not exist.
415 Unsupported Media Type The server rejected your request because the data format (Content-
Type) is not supported.
429 Too Many Requests You've exceeded the rate limit by sending too many requests in a short
period. The Retry-After header in the response will tell you how long to
wait before trying again.
500 Internal Server Error Something went wrong on the server's end. This is not an issue with
your request.
Get result
Overview
This endpoint retrieves the results of a completed search in a paginated JSON:API format. It's designed for applications that need
to process the realtime data one page at a time. By providing the search-id and using pagination parameters, you can
systematically iterate through the entire result set returned from the queried endpoints.
14 Trellix Endpoint Detection and Response Product Guide

1| Trellix EDR APIs
You should use this API when your application needs to programmatically process search results record by record. It's the ideal
method for integrating search data directly into an automated workflow, a custom dashboard, or for piping results into another
system for further analysis without downloading a full file.
Authentication
Authentication type: Bearer Token, API Key.
You can create a token using client credentials obtained through the developer portal. The API Key (x-api-key) is provided in
your onboarding email or on the API Access Management page.
Path (or URL)
GET https://{Trellix EDR_gateway_URL}/edr/v2/searches/realtime/{search-id}/results
Example — {search-id}: rts-12212
Note
You might also find the endpoint in the Location field of the headers tab of the status call's response after the search is
finished.
Request
Request headers
Authorization: Bearer <your_bearer_token>
Content-Type: application/vnd.api+json
x-api-key: <your_api_key>
Accept-Encoding: gzip
• Authorization: This header is used to authenticate your request. You need to replace <your_bearer_token> with the actual
token you generate.
• Content-Type: This header tells the server that the request body format is json:api. Even though this specific call has no
request body, the API requires this header.
• x-api-key: This is a custom header required by the Trellix API for authentication. You'll need to replace <your_api_key> with
the key from your onboarding email or the API Access Management page.
• Accept-Encoding: This is an optional header you can include to tell the server you can accept a compressed response (using
Trellix Endpoint Detection and Response Product Guide 15

1| Trellix EDR APIs
gzip), which can make the data transfer faster.
Request parameters
| Parameters  | Data type/Values  |     | Description                           |     |
| ----------- | ----------------- | --- | ------------------------------------- | --- |
| searchId    | string            |     | Search id of the search in progress.  |     |
page[offset]  integer  Number of records to skip (starts from 0th record).
| page[limit]  | integer  |     | Number of records to fetch on a page.  |     |
| ------------ | -------- | --- | -------------------------------------- | --- |
| output       | string   |     | Defines the search output type.        |     |
| format       | string   |     | Defines the output format.             |     |
sort  string  Single column to sort by value. By default, the records are sorted in
ascending order. If the records are prefixed with '-', sorted in
descending order.
Accept- string  Enable GZIP Compression to return compressed data.
| Encoding  |     |     | Example: gzip, deflate, br  |     |
| --------- | --- | --- | --------------------------- | --- |
Response
Response parameters
| Parameters  |     | Data type  |     | Description  |
| ----------- | --- | ---------- | --- | ------------ |
Severity  string (enum: s0–s5)  BANF rule severity: potential
impact of detection. For details,
see Security levels.
| Process_Integrity  |     | string  |                                                       | Process integrity levels for  |
| ------------------ | --- | ------- | ----------------------------------------------------- | ----------------------------- |
| 16                 |     |         | Trellix Endpoint Detection and Response Product Guide |                               |

1| Trellix EDR APIs
| Parameters  | Data type  | Description  |
| ----------- | ---------- | ------------ |
Windows devices.
| Root_Trace_Id  | string  | Root trace ID of the process  |
| -------------- | ------- | ----------------------------- |
group (may equal parentTraceId
if detected at root process).
Related_Trace_Id  array[string]  List of traceIds representing
events responsible for detection.
| Process_Sha256  | string  | SHA-256 hash of the parent  |
| --------------- | ------- | --------------------------- |
process.
| Hash_Id  | string  | Detection ID — identical for two  |
| -------- | ------- | --------------------------------- |
detections sharing same data
except detectionDate/traceId.
Parents_Trace_Id  array[string]  traceIds of all ancestor processes
(first = parentTraceId).
Detection_Tags  array[string]  MITRE ATT&CK tags (for example,
@ATA.Execution,
@ATE.T1059.001).
Process_Path, CommandLine  string  Full path and command line of
the triggering process.
| Rank  | integer  | Trellix Agent calculated rank,  |
| ----- | -------- | ------------------------------- |
used internally.
| Pid        | integer  | Process ID                |
| ---------- | -------- | ------------------------- |
| Host_Name  | string   | Host name of the device.  |
DetectionDate  string (date-time)  Time of detection in EDR cloud.
| ProcessName  | string  | Process initiating events  |
| ------------ | ------- | -------------------------- |
Trellix Endpoint Detection and Response Product Guide 17

1| Trellix EDR APIs
| Parameters  | Data type  | Description  |
| ----------- | ---------- | ------------ |
represented by relatedTraceIds
that triggered the rule.
| Trace_Id  | string  | Autogenerated GUID for the  |
| --------- | ------- | --------------------------- |
event.
| MAGUID  | string  | Endpoint MA (formerly McAfee  |
| ------- | ------- | ----------------------------- |
Agent) GUID — uniquely
identifies the device.
| Version      | string  | Version information.             |
| ------------ | ------- | -------------------------------- |
| Process_Md5  | string  | MD5 hash of the parent process.  |
Event_Date  string (date-time)  Earliest timestamp for related
traces as reported by the
endpoint clock (UTC).
Host_OS  string (enum: windows, linux,  Host OS: windows, linux, or mac.
mac)
| Artifact  | string  | Value is Threat for detection  |
| --------- | ------- | ------------------------------ |
events.
| Parent_Trace_Id  | string  | TraceId of the Process Created  |
| ---------------- | ------- | ------------------------------- |
event for the detection process.
| Score  | integer  | BANF rule score / confidence  |
| ------ | -------- | ----------------------------- |
level.
| User  | object  | User name and domain: {  |
| ----- | ------- | ------------------------ |
"domain": "...", "name": "..." }.
| Activity  | string                                                | Type of event                    |
| --------- | ----------------------------------------------------- | -------------------------------- |
| RuleId    | string                                                | BANF rule ID that triggered the  |
| 18        | Trellix Endpoint Detection and Response Product Guide |                                  |

1| Trellix EDR APIs
| Parameters  | Data type  | Description  |
| ----------- | ---------- | ------------ |
detection.
| Attack_Tags  | array[string]  | MITRE ATT&CK tactic and  |
| ------------ | -------------- | ------------------------ |
technique associations.
| HX_Agent_Id  | string  | HX Agent GUID.  |
| ------------ | ------- | --------------- |
Process_Embed_FileName,  string  Embedded filenames of process
| Parent_Process_Embed_FileName  |     | and grandparent process  |
| ------------------------------ | --- | ------------------------ |
binaries.
| Parent_Process_Path,     | string  | Grandparent process details   |
| ------------------------ | ------- | ----------------------------- |
| Parent_Process_CmdLine,  |         | (path, command line, hashes,  |
| Parent_Process_MD5,      |         | name).                        |
Parent_Process_Sha256,
Parent_Process_Name
| P_Parent_TraceId  | string  | TraceID of the grandparent  |
| ----------------- | ------- | --------------------------- |
process.
HostInfo.os.desc / major / minor /  string  OS description, major/minor
| build / sp  |     | version, build number, service  |
| ----------- | --- | ------------------------------- |
pack.
HostInfo.ifaces.name / mac / ip /  number  Network interface name, MAC
| type  |     | address, IP address, interface  |
| ----- | --- | ------------------------------- |
type.
Response example
{
  "jsonapi": {
    "version": "1.0"
  },
  "meta": {
    "totalResourceCount": 2,
    "totalHosts": 13
  },
  "data": [
Trellix Endpoint Detection and Response Product Guide 19

1| Trellix EDR APIs
{
"id": "fd3c5a73fcb4485d67350052f2b51cd0",
"type": "realTimeSearchResults",
"attributes": {
"created": "2021-07-24T07:29:45.895Z",
"HostInfo.hostname": "EDR-20-W2K_4",
"HostInfo.ip_address": "10.54.1.26",
"HostInfo.os": "Microsoft Windows [Version 6.3.9600]",
"HostInfo.connection_status": "Online",
"HostInfo.platform": "Windows",
"BrowserHistory.url": "https://www.google.com/
search?q=adobe+reader&oq=adobe&aqs=chrome.1.69i57j0l5.9188j0j8&sourceid=chrome&ie=UTF-8",
"BrowserHistory.title": "adobe reader - Buscar con Google",
"BrowserHistory.last_visit_time": "2019-11-26T19:20:29.000Z",
"BrowserHistory.visit_count": 2,
"BrowserHistory.visit_from": 0,
"BrowserHistory.browser": "Google Chrome",
"BrowserHistory.user_profile": "Administrator",
"BrowserHistory.browser_profile": "Default",
"BrowserHistory.url_length": 110,
"BrowserHistory.hidden": 0,
"BrowserHistory.typed_count": 0
}
}
],
"links": {
"self": "/edr/v2/searches/realtime/rts-5432/results?page[offset]=3&page[limit]=1",
"first": "/edr/v2/searches/realtime/rts-5432/results?page[offset]=1&page[limit]=1",
"prev": "/edr/v2/searches/realtime/rts-5432/results?page[offset]=2&page[limit]=1",
"next": "/edr/v2/searches/realtime/rts-5432/results?page[offset]=4&page[limit]=1",
"last": "/edr/v2/searches/realtime/rts-5432/results?page[offset]=13&page[limit]=1"
}
}
Response codes
Status Response Description
200 OK Your request was processed successfully. The server has returned the
requested data.
400 Bad request The server couldn't understand your request, likely due to a syntax error
or an invalid parameter.
401 Access denied request Your request was rejected because it lacks valid authentication
credentials. Check your API key and token.
403 Forbidden You are not authorized to access this resource. While your credentials
may be valid, you don't have the necessary permissions.
20 Trellix Endpoint Detection and Response Product Guide

1| Trellix EDR APIs
Status Response Description
404 Not Found The specific resource or endpoint you requested does not exist.
415 Unsupported Media Type The server rejected your request because the data format (Content-
Type) is not supported.
429 Too Many Requests You've exceeded the rate limit by sending too many requests in a short
period. The Retry-After header in the response will tell you how long to
wait before trying again.
500 Internal Server Error Something went wrong on the server's end. This is not an issue with
your request.
Get result — file export
Overview
This endpoint retrieves the complete results of a finished search and delivers them as a downloadable CSV file. Once a search
job has completed, you call this endpoint with the unique search-id and include the output and format query parameters. The
API then returns the full dataset from all queried endpoints formatted as a CSV file in the response body.
You should use this API as the final step in a search workflow, after polling the job status endpoint has confirmed that the search
is complete. It is the correct endpoint to use when you need to export the entire result set for offline analysis, archiving, or
ingestion into other security tools and reporting platforms.
Authentication
Authentication type: Bearer Token, API Key.
You can create a token using client credentials obtained through the developer portal. The API Key (x-api-key) is provided in
your onboarding email or on the API Access Management page.
Path (or URL)
GET https://{Trellix EDR_gateway_URL}/edr/v2/searches/realtime/{search-id}/results?output=file&format=csv
Trellix Endpoint Detection and Response Product Guide 21

1| Trellix EDR APIs
Example — {search-id}: rts-12212
Request
Request headers
Authorization: Bearer <your_bearer_token>
Content-Type: application/vnd.api+json
x-api-key: <your_api_key>
Accept-Encoding: gzip
• Authorization: This header is used to authenticate your request. You need to replace <your_bearer_token> with the actual
token you generate.
• Content-Type: This header tells the server that the request body format is json:api. Even though this specific call has no
request body, the API requires this header.
• x-api-key: This is a custom header required by the Trellix API for authentication. You'll need to replace <your_api_key> with
the key from your onboarding email or the API Access Management page.
• Accept-Encoding: This is an optional header you can include to tell the server you can accept a compressed response (using
gzip), which can make the data transfer faster.
Request parameters
Parameters Data type/Values Description
page[offset] Integer Number of records to skip (starts from 0th record)
page[limit] Integer Number of records to fetch on a page
output "file" Sets the response as a file
format "csv" Sets the export file format to CSV
22 Trellix Endpoint Detection and Response Product Guide

1| Trellix EDR APIs
Note
If you don't add 'output' and 'format' parameters to the endpoint URL, the results are displayed in the paginated format
instead of the file format. For fetching results in the file format, it is mandatory to provide both output and format
parameters.
For more details about the Real-time Search APIs, see Trellix Developer Portal.
Response
Response codes
Status Response Description
200 OK Your request was processed successfully. The server has returned the
requested data.
400 Bad request The server couldn't understand your request, likely due to a syntax error
or an invalid parameter.
401 Access denied request Your request was rejected because it lacks valid authentication
credentials. Check your API key and token.
403 Forbidden You are not authorized to access this resource. While your credentials
may be valid, you don't have the necessary permissions.
404 Not Found The specific resource or endpoint you requested does not exist.
415 Unsupported Media Type The server rejected your request because the data format (Content-
Type) is not supported.
429 Too Many Requests You've exceeded the rate limit by sending too many requests in a short
period. The Retry-After header in the response will tell you how long to
wait before trying again.
500 Internal Server Error Something went wrong on the server's end. This is not an issue with
your request.
Trellix Endpoint Detection and Response Product Guide 23

1| Trellix EDR APIs
The Real-time Search API response objects or artifacts
You can create the Real-time Search queries using the Trellix EDR collectors and the respective response objects or artifacts.
Artifact (collector) Attributes
Processes
• name
• id
• threadcount
• parentid
• parentname
• parentimagepath
• file_reputation
• process_reputation
• started_at
• content_size
• content
• content_file
• execution_mode
• size
• md5
• sha1
• cmdline
• imagepath
• kerneltime
• usertime
• uptime
• user
• user_id
• sha256
• normalized_cmdline
• parent_cmdline
ProcessHistory
• name
• id
• threadcount
• parentid
• parentname
• parentimagepath
24 Trellix Endpoint Detection and Response Product Guide

1| Trellix EDR APIs
Artifact (collector) Attributes
• file_reputation
• started_at
• finished_at
• status
• content_size
• content
• content_file
• execution_mode
• exitstatus
• size
• md5
• sha1
• cmdline
• imagepath
• kerneltime
• usertime
• uptime
• user
• user_id
• sha256
• normalized_cmdline
• parent_cmdline
Files
• name
• dir
• full_name
• size
• last_write
• md5
• sha1
• sha256
• created_at
• deleted_at
• status
• create_process_pid
• create_process_sha256
• create_process_full_path
• modify_process_pid
Trellix Endpoint Detection and Response Product Guide 25

1| Trellix EDR APIs
Artifact (collector) Attributes
• modify_process_sha256
• modify_process_full_path
• delete_process_pid
• delete_process_sha256
• delete_process_full_path
• create_user_domain
• create_user_name
• create_user_id
• modify_user_domain
• modify_user_name
• modify_user_id
• delete_user_domain
• delete_user_name
• delete_user_id
NetworkFlow
• time
• direction
• src_ip
• src_port
• dst_ip
• dst_port
• status
• proto
• ip_class
• seq_number
• src_mac
• dst_mac
• process
• process_id
• md5
• sha1
• user
• user_id
• sha256
CurrentFlow
• disk
• model
26 Trellix Endpoint Detection and Response Product Guide

1| Trellix EDR APIs
Artifact (collector) Attributes
• disk_size
• logical_sector
• physical_sector
• virtual_loc
• disk_flags
• partition
• volume
• partition_size
• partition_freespace
• filesystem
• type
• partition_flags
WinRegistry
• keypath
• keyvalue
• valuedata
• valuetype
Software
• displayname
• installdate
• publisher
• version
LoggedInUsers
• id
• userdomain
• username
NetworkInterfaces
• bssid
• displayname
• gwipaddress
• gwmacaddress
• ipaddress
• ipprefix
• macaddress
• name
Trellix Endpoint Detection and Response Product Guide 27

1| Trellix EDR APIs
Artifact (collector) Attributes
• ssid
• type
• wifisecurity
HostEntries
• ipaddress
• hostname
HostInfo
• hostname
• ip_address
• os
• connection_status
• platform
InstalledUpdates
• description
• hotfix_id
• install_date
• installed_by
• source
• version
LocalGroups
• groupname
• groupdomain
• groupdescription
• islocal
• sid
UserProfiles
• accountdisabled
• domain
• fullname
• installdate
• localaccount
• lockedout
• accountname
• sid
• passwordexpires
28 Trellix Endpoint Detection and Response Product Guide

1| Trellix EDR APIs
Artifact (collector) Attributes
• groups
Services
• description
• name
• startuptype
• status
• user
Startup
• caption
• command
• description
• name
• user
InteractiveSessions
• userid
• name
InstalledDrivers
• displayname
• description
• last_modified_date
• name
• servicetype
• startmode
• state
• path
DNSCache
• hostname
• ipaddress
UsbConnectedStorageDevices
• vendor_id
• product_id
• serial_number
• device_type
• guid
Trellix Endpoint Detection and Response Product Guide 29

1| Trellix EDR APIs
Artifact (collector) Attributes
• last_connection_time
• user_name
• last_time_used_by_user
NetworkShares
• name
• description
• path
NetworkSessions
• computer
• user
• client
• file
• idletime
EnvironmentVariables
• username
• process_id
• name
• value
CommandLineHistory
• user
• id
• command_line
InstalledCertificates
• issued_to
• issued_by
• expiration_date
• purposes
• purposes_extended
• friendly_name
ScheduledTasks
• folder
• taskname
• next_run_time
• last_run
30 Trellix Endpoint Detection and Response Product Guide

1| Trellix EDR APIs
Artifact (collector) Attributes
• status
• taskrun
• username
• schedule_on
• logon_type
• recurrence
• task_source
DisksAndPartitions
• disk
• model
• disk_size
• logical_sector
• physical_sector
• virtual_loc
• disk_flags
• partition
• volume
• partition_size
• partition_freespace
• filesystem
• type
• partition_flags
LoadedModules
• process_id
• process_name
• process_imagepath
• module_name
• module_imagepath
• module_reputation
• module_md5
• module_sha1
• module_sha256
AutoRun
• entry_location
• entry
• enabled
Trellix Endpoint Detection and Response Product Guide 31

1| Trellix EDR APIs
Artifact (collector) Attributes
• category
• profile
• description
• publisher
• image_path
• version
• launch_string
BrowserDownload
• file_path
• start_time
• end_time
• received_bytes
• total_bytes
• state
• referrer
• site_url
• mime_type
• browser
• user_profile
• browser_profile
BrowserHistory
• url
• title
• last_visit_time
• visit_count
• visit_from
• browser
• user_profile
• browser_profile
• url_length
• hidden
• typed_count
NSACryptEvents
• id
• process_id
• thread_id
32 Trellix Endpoint Detection and Response Product Guide

1| Trellix EDR APIs
Artifact (collector) Attributes
• time_created
• message
TwinFiles
• name
• dir
• full_name
• size
• last_write
• md5
• sha1
• sha256
• created_at
• deleted_at
• status
• create_process_pid
• create_process_sha256
• create_process_full_path
• modify_process_pid
• modify_process_sha256
• modify_process_full_path
• delete_process_pid
• delete_process_sha256
• delete_process_full_path
• create_user_domain
• create_user_name
• create_user_id
• modify_user_domain
• modify_user_name
• modify_user_id
• delete_user_domain
• delete_user_name
• delete_user_id
API sample for historical search
The historical search APIs let you query stored endpoint telemetry over a defined time range. Use these endpoints to investigate
past activity, hunt for indicators of compromise (IOCs), and reconstruct incident timelines. Historical search queries data that
Trellix Endpoint Detection and Response Product Guide 33

1| Trellix EDR APIs
endpoints have already reported.
Endpoints
Endpoint Description
POST request Use this to submit a query and start a historical
search job.
Get status Use this to check whether a search job has finished.
Get result Use this to retrieve completed results as paginated
JSON.
Get result — file export Use this to download the full result set as a CSV file.
Common reference
All endpoints use the same authentication and request headers. Responses use the s0–s5 severity scale. For details, see Security
levels.
POST request
Overview
This endpoint starts an asynchronous search of historical telemetry from managed endpoints. Define the search with a query,
startTime, and endTime to receive a job ID for polling status and retrieving results. Use this API to investigate past events and
hunt for threats. It is the primary tool for querying historical data to find indicators of compromise (IOCs) or to reconstruct
incident timelines.
Authentication
Authentication type: Bearer Token, API Key.
You can create a token using client credentials obtained through the developer portal. The API Key (x-api-key) is provided in
your onboarding email or on the API Access Management page.
34 Trellix Endpoint Detection and Response Product Guide

1| Trellix EDR APIs
Path (or URL)
POST https://{Trellix EDR_gateway_URL}/edr/v2/searches/historical
You can get the gateway URL from the Trellix on-boarding email. For example, https://api.manage.trellix.com
Request
Request headers
Authorization: Bearer <your_bearer_token>
Content-Type: application/vnd.api+json
x-api-key: <your_api_key>
• Authorization: This header is used to authenticate your request. You need to replace <your_bearer_token> with the actual
token you generate.
• Content-Type: This header tells the server that the request body format is json:api. Even though this specific call has no
request body, the API requires this header.
• x-api-key: This is a custom header required by the Trellix API for authentication. You'll need to replace <your_api_key> with
the key from your onboarding email or the API Access Management page.
Request parameters
Parameters Data type/Values Description
query string Define the query.
startTime and string The time period for the results to be fetched.
endTime Format: YYYY-MM-DDThh:mm:ssZ.
Note:
The error code returns for the invalid timestamp format.
sort string Single column to be sorted by value.
Trellix Endpoint Detection and Response Product Guide 35

1| Trellix EDR APIs
Parameters Data type/Values Description
Default sort field: Time.
Below is the list of allowed values for the sort request parameter:
• 'Time', 'DetectionDate', 'Activity', 'DeviceName',
'Tags', 'Process_Name'
• 'User_Name', 'File_Path', 'Network_Protocol',
'Network_DstIp', 'Network_DstPort',
'Registry_KeyValue_Path'
• 'Registry_KeyValueName',
'RelatedProcess_ProcessName', 'Api_Name',
'Dns_Name', 'Pipe_Name', 'Score', 'Module_Name'
• 'SchedTask_Name', 'Service_Name', 'Ppid', 'Pid',
'Integrity', 'Author', 'Command_Line', 'File_MD5',
'Process_MD5'
• 'File_Sha256', 'Process_Sha256', 'Module_Sha256',
'File_Sha1', 'Process_Sha1', 'File_Name', 'File_Size',
'Network_AccessType'
• 'Network_Direction', 'Network_DnsName',
'ScheduledTask_Commands', 'Action',
'Registry_KeyValue', 'Registry_KeyValueType',
'Registry_KeyOldValue'
• 'Logon_Success', 'User_Domain', 'Logon_LogonType',
'Logon_Domain', 'Logon_Name', 'Logon_LogonId',
'Logon_Ip', 'Logon_Port'
• 'Logon_WorkstationName', 'Api_Arguments',
'Api_Result', 'Api_ModuleName', 'Api_TargetPid',
'Modules', 'RuleId', 'Parent_Process_Name'
• 'Service_Executable_Path', 'Service_Username',
'ScheduledTask_User', 'File_Type', 'File_NewPath',
'Registry_Key_Name', 'Injection_Apis'
• 'Network_HTTP_URL', 'Network_HTTP_Request',
'Network_HTTP_Response'
• 'Network_Sent_Bytes', 'Network_Received_Bytes',
'Process_Path', 'Process_Original_Name',
'Service_Action', 'ScheduledTask_Action'
• 'User_Logon_Name', 'Process_TargetPid',
'Process_TargetTraceID', 'Process_Type',
36 Trellix Endpoint Detection and Response Product Guide

1| Trellix EDR APIs
Parameters Data type/Values Description
'Process_Status', 'Process_TargetProcessName',
'ComApis'
export boolean Applicable only for specific related historical/device searches.
If set to True, this parameter must be used in the following APIs:
• /edr/vv2/searches/historical
• /edr/v2/searches/queue-jobs/{searchId}
• /edr/v2/searches/historical/{searchId}/results
Default value: False.
maxResults integer The maximum number of rows to include in the response.
Default value: 5000.
Available values: 5000, 10000, 25000, 50000, and 100000.
Request body fields
Field Data type Description
data.type string Must be historicalSearches
data.attributes.query string Search query (1–20000 chars).
For example, DeviceName equals
"W7x64" and CommandLine
contains "exe"
data.attributes.startTime string (date-time) Start of time range (ISO 8601)
data.attributes.endTime string (date-time) End of time range (ISO 8601)
data.attributes.maguid string (uuid) The Agent GUID uniquely
identifies the device.
Trellix Endpoint Detection and Response Product Guide 37

1| Trellix EDR APIs
Request example
Example 1: Standard Historical Search
{
"data": {
"type": "historicalSearches",
"attributes": {
"query": "IpAddress contains 10",
"startTime": "2021-07-05",
"endTime": "2021-12-15"
}
}
}
Example 2: Device Search with maguid
Note
For Device Search, include the DeviceName collector in the query with an optional maguid parameter.
{
"data": {
"type": "historicalSearches",
"attributes": {
"query": "DeviceName contains DESKTOP",
"startTime": "2021-07-05T02:00:28Z",
"endTime": "2021-12-15T06:00:28Z",
"maguid": "A2C39241-BED9-49F0-BB8B-68F8902EE55C"
}
}
}
Response
Response example
{
"data": {
"type": "queue-jobs",
"id": "hs-01b5865f-0905-0572-002a-7003d239d812.346565425a0b6b2b7174aa555f67a043",
"attributes": {
"status": "in-progress"
},
"links": {
"self": "/edr/v2/searches/queue-jobs/
hs-01b5865f-0905-0572-002a-7003d239d812.346565425a0b6b2b7174aa555f67a043"
}
}
}
38 Trellix Endpoint Detection and Response Product Guide

1| Trellix EDR APIs
Response codes
Status Response Description
201 Created Your request was successful, and a new resource was created as a
result. Your request was successful, and a new resource was created.
The response includes details such as the resource ID, which you can
use to track or manage the resource.
400 Bad request The server couldn't understand your request, likely due to a syntax error
or an invalid parameter.
401 Access denied request Your request was rejected because it lacks valid authentication
credentials. Check your API key and token.
403 Forbidden You are not authorized to access this resource. While your credentials
may be valid, you don't have the necessary permissions.
404 Not Found The specific resource or endpoint you requested does not exist.
415 Unsupported Media Type The server rejected your request because the data format (Content-
Type) is not supported.
429 Too Many Requests You've exceeded the rate limit by sending too many requests in a short
period. The Retry-After header in the response will tell you how long to
wait before trying again.
500 Internal Server Error Something went wrong on the server's end. This is not an issue with
your request.
Get status
Overview
This endpoint retrieves the current status of a previously initiated asynchronous search. By providing the unique search-id in
the path, you can poll this endpoint to track the progress of a real-time or historical search. While the job is running, the API
Trellix Endpoint Detection and Response Product Guide 39

1| Trellix EDR APIs
returns the current status; once complete, it provides a redirect to the location where the final results can be retrieved.
You should use this API after initiating a search to monitor its progress. It is designed to be polled periodically within a script or
automated workflow to determine when the search results are ready for collection.
Authentication
Authentication type: Bearer Token, API Key.
You can create a token using client credentials obtained through the developer portal. The API Key (x-api-key) is provided in
your onboarding email or on the API Access Management page.
Path (or URL)
GET https://{Trellix EDR_gateway_URL}/edr/v2/searches/queue-jobs/{search-id}
Example — {search-id}: hs-12212
Request
Request headers
Authorization: Bearer <your_bearer_token>
Content-Type: application/vnd.api+json
x-api-key: <your_api_key>
Accept-Encoding: gzip
• Authorization: This header is used to authenticate your request. You need to replace <your_bearer_token> with the actual
token you generate.
• Content-Type: This header tells the server that the request body format is json:api. Even though this specific call has no
request body, the API requires this header.
• x-api-key: This is a custom header required by the Trellix API for authentication. You'll need to replace <your_api_key> with
the key from your onboarding email or the API Access Management page.
• Accept-Encoding: This is an optional header you can include to tell the server you can accept a compressed response (using
gzip), which can make the data transfer faster.
40 Trellix Endpoint Detection and Response Product Guide

1| Trellix EDR APIs
Request parameters
Parameters Data type/Values Description
searchId string Search id of the search in progress.
export boolean Applicable only for specific related historical/device searches.
If set to True, this parameter must be used in the following APIs:
• /edr/vv2/searches/historical
• /edr/v2/searches/queue-jobs/{searchId}
• /edr/v2/searches/historical/{searchId}/results
Default value: False.
Response
Response example
{
"data": {
"type": "queue-jobs",
"id": "hs-01b5865f-0905-0572-002a-7003d239d812.346565425a0b6b2b7174aa555f67a043",
"attributes": {
"status": "in-progress"
}
}
}
Response codes
Status Response Description
200 OK Your request was successful. The response contains the current job
status. The search is still in progress, and you must wait until it finishes
before retrieving the results.
303 See Other The search job has completed. The response includes a redirect
Trellix Endpoint Detection and Response Product Guide 41

1| Trellix EDR APIs
Status Response Description
(Location header) to the results endpoint, where you can retrieve the
final search data.
400 Bad request The server couldn't understand your request, likely due to a syntax error
or an invalid parameter.
401 Access denied request Your request was rejected because it lacks valid authentication
credentials. Check your API key and token.
403 Forbidden You are not authorized to access this resource. While your credentials
may be valid, you don't have the necessary permissions.
404 Not Found The specific resource or endpoint you requested does not exist.
415 Unsupported Media Type The server rejected your request because the data format (Content-
Type) is not supported.
429 Too Many Requests You've exceeded the rate limit by sending too many requests in a short
period. The Retry-After header in the response will tell you how long to
wait before trying again.
500 Internal Server Error Something went wrong on the server's end. This is not an issue with
your request.
Get result
Overview
This endpoint retrieves the results of a completed historical search in a paginated JSON:API format. It's designed for applications
that need to programmatically process historical data, one page at a time. By providing the search-id and using pagination
parameters, you can systematically iterate through the entire result set.
You should use this API when your application needs to programmatically process historical search results record by record. It's
the ideal method for integrating historical data into an automated workflow, a custom analytics platform, or for ingesting results
into a Security Information and Event Management (SIEM) system without downloading a full file.
42 Trellix Endpoint Detection and Response Product Guide

1| Trellix EDR APIs
Authentication
Authentication type: Bearer Token, API Key.
You can create a token using client credentials obtained through the developer portal. The API Key (x-api-key) is provided in
your onboarding email or on the API Access Management page.
Path (or URL)
GET https://{Trellix EDR_gateway_URL}/edr/v2/searches/historical/{search-id}/results
Note
You might also find the endpoint in the Location field of the headers tab of the status call's response after the search is
finished.
Example — {search-id}: hs-12212
Request
Request headers
Authorization: Bearer <your_bearer_token>
Content-Type: application/vnd.api+json
x-api-key: <your_api_key>
Accept-Encoding: gzip
• Authorization: This header is used to authenticate your request. You need to replace <your_bearer_token> with the actual
token you generate.
• Content-Type: This header tells the server that the request body format is json:api. Even though this specific call has no
request body, the API requires this header.
• x-api-key: This is a custom header required by the Trellix API for authentication. You'll need to replace <your_api_key> with
the key from your onboarding email or the API Access Management page.
• Accept-Encoding: This is an optional header you can include to tell the server you can accept a compressed response (using
gzip), which can make the data transfer faster.
Trellix Endpoint Detection and Response Product Guide 43

1| Trellix EDR APIs
Request parameters
| Parameters  | Data type/Values  |     | Description                           |     |
| ----------- | ----------------- | --- | ------------------------------------- | --- |
| searchId    | string            |     | Search id of the search in progress.  |     |
page[offset]  integer  Number of records to skip (starts from 0th record).
| page[limit]  | integer  |     | Number of records to fetch on a page.  |     |
| ------------ | -------- | --- | -------------------------------------- | --- |
| sort         | string   |     | Single column to sort by value.        |     |
Default sort field: Time.
export  boolean  Applicable only for specific related historical/device searches.
If set to True, this parameter must be used in the following APIs:
•  /edr/vv2/searches/historical
•  /edr/v2/searches/queue-jobs/{searchId}
•  /edr/v2/searches/historical/{searchId}/results
Default value: False.
Accept- string  Enable GZIP Compression to return compressed data.
| Encoding  |     |     | Example: gzip, deflate, br  |     |
| --------- | --- | --- | --------------------------- | --- |
Response
Response parameters
| Parameter      |     | Data type  |     | Description                     |
| -------------- | --- | ---------- | --- | ------------------------------- |
| Time           |     | string     |     | Event timestamp                 |
| DetectionDate  |     | string     |     | Date the event was detected in  |
EDR cloud.
| 44  |     |     | Trellix Endpoint Detection and Response Product Guide |     |
| --- | --- | --- | ----------------------------------------------------- | --- |

1| Trellix EDR APIs
| Parameter    | Data type  | Description                        |
| ------------ | ---------- | ---------------------------------- |
| Activity     | string     | Activity type                      |
| DeviceName   | string     | Name of the device.                |
| CommandLine  | string     | Full command line of the process.  |
| ProcessName  | string     | Name of the process that           |
triggered the event/rule.
| Severity  | string  | BANF rule severity: potential  |
| --------- | ------- | ------------------------------ |
impact of detection. For details,
see Security levels.
| Score   | integer  | Trellix Agent calculated rank    |
| ------- | -------- | -------------------------------- |
| RuleId  | string   | BANF rule ID that triggered the  |
detection.
Detection_Tags  array[string]  MITRE ATT&CK tags (for example,
@ATA.Execution,
@ATE.T1059.001)
| Trace_Id  | string  | Autogenerated GUID for the  |
| --------- | ------- | --------------------------- |
event.
| Parent_Trace_Id  | string  | TraceId of the Process Created  |
| ---------------- | ------- | ------------------------------- |
event for the detection process.
| Root_Trace_Id  | string  | Root trace ID of the process  |
| -------------- | ------- | ----------------------------- |
group for this threat.
Related_Trace_Id  array[string]  TraceIds representing events
responsible for detection.
Parents_Trace_Id  array[string]  TraceIds of all ancestor processes
(first = parentTraceId).
Trellix Endpoint Detection and Response Product Guide 45

1| Trellix EDR APIs
| Parameter  | Data type  | Description                       |
| ---------- | ---------- | --------------------------------- |
| Hash_Id    | string     | Detection ID — identical for two  |
detections sharing same data
except detectionDate/traceId.
| MAGUID  | string  | Endpoint MA (formerly McAfee  |
| ------- | ------- | ----------------------------- |
Agent) GUID — uniquely
identifies the device.
| Host_Name  | string  | Host name of the device.           |
| ---------- | ------- | ---------------------------------- |
| Host_OS    | string  | Host OS: windows, linux, or mac    |
| Artifact   | string  | Event type (for example, Process,  |
Threat, File)
| Pid  | integer  | Process ID  |
| ---- | -------- | ----------- |
File_Sha256 / Process_Sha256  string  SHA-256 of file or process image.
File_MD5 / Process_MD5  string  MD5 of file or process image.
File_Sha1 / Process_Sha1  string  SHA-1 of file or process image.
| Tags  | array[string]  | Event tags  |
| ----- | -------------- | ----------- |
User_Name / User  string / object  User associated with the event.
Object form: { "domain": "...",
"name": "..." }
Network_Protocol /  string / integer  Network connection details
Network_DstPort / Network_SrcIp
/ Network_SrcPort
Registry_KeyValue_Path /  string  Windows registry event fields
Registry_KeyValueName /
Registry_Key_Name
| 46  | Trellix Endpoint Detection and Response Product Guide |     |
| --- | ----------------------------------------------------- | --- |

1| Trellix EDR APIs
Parameter Data type Description
Api_Name / Api_Arguments / string API call details
Api_ModuleName
Service_Name / Service_Path / string Windows service event fields
Service_Type
Logon_LogonType / Logon_Name string Logon event fields
/ Logon_Ip
Process_Path / string Process path and start time
Process_Start_Time
OS string Operating system
Event_Date string Earliest timestamp for related
traces (endpoint clock, UTC)
Response example
{
"jsonapi": {
"version": "1.0"
},
"meta": {
"totalResourceCount": 5000
},
"data": [
{
"id": "2D80E1F0-E3FD-4EBA-AAE6-BAC2EF2F870C_86e7e5ba-a6d0-4f52-8192-44838d14e03a",
"type": "historicalSearchResults",
"attributes": {
"Context_Trace_Id": "01a99f7c-4906-4226-8f05-2319fc91a8b7",
"Process_Start_Time": "2017-09-29T16:41:43.280Z",
"Pid": 10092,
"Process_Sha1": "771752657259429f516ea092515c6468ee88ea6b",
"ProcessName": "PROD_E2E_43076187.EXE",
"Tags": [
"@AC.ProcessCreated"
],
"DetectionDate": "2021-07-21T10:11:04Z",
"DeviceName": "EDR-20-W10_1",
"Process_Sha256": "bef87c6f64b7b20b49aae71ad3b229a7735a87a047268ecbec618d7c49ae7010",
"Trace_Id": "51ba26ec-286d-11ef-a554-157d81051918",
"MAGUID": "51BA26ED-286D-11EF-A554-157D81051918",
"Integrity": 4,
Trellix Endpoint Detection and Response Product Guide 47

1| Trellix EDR APIs
"Process_MD5": "0845715fedc1d4012911840177d7fc52",
"Artifact": "Process",
"OS": "windows",
"Process_File_Name": "PROD_E2E_43076187.EXE",
"Process_Path": "C:\\\\WINDOWS\\\\SYSTEM32\\\\WINDOWSPOWERSHELL\\\\V1.0\\\\PROD_E2E_43076187.EXE",
"Parent_Trace_Id": "f33712f0-fd5c-4798-985b-3cd751acb06a",
"CommandLine": "xyz.exe",
"Activity": "Process Created",
"Time": "2024-06-12T03:39:05.000+00:00"
}
}
],
"links": {
"self": "/edr/v2/searches/historical/
hs-01b53d66-0904-c5df-0067-3a0311d594a2.82a69b2e7d17f78748ac706bf4efb8d4/
results?page[offset]=20&page[limit]=100",
"first": "/edr/v2/searches/historical/
hs-01b53d66-0904-c5df-0067-3a0311d594a2.82a69b2e7d17f78748ac706bf4efb8d4/
results?page[offset]=0&page[limit]=100",
"prev": "/edr/v2/searches/historical/
hs-01b53d66-0904-c5df-0067-3a0311d594a2.82a69b2e7d17f78748ac706bf4efb8d4/
results?page[offset]=0&page[limit]=100",
"next": "/edr/v2/searches/historical/
hs-01b53d66-0904-c5df-0067-3a0311d594a2.82a69b2e7d17f78748ac706bf4efb8d4/
results?page[offset]=120&page[limit]=100",
"last": "/edr/v2/searches/historical/
hs-01b53d66-0904-c5df-0067-3a0311d594a2.82a69b2e7d17f78748ac706bf4efb8d4/
results?page[offset]=4900&page[limit]=100"
}
}
Response codes
Status Response Description
200 OK Your request was processed successfully. The server has returned the
requested data.
400 Bad request The server couldn't understand your request, likely due to a syntax error
or an invalid parameter.
401 Access denied request Your request was rejected because it lacks valid authentication
credentials. Check your API key and token.
403 Forbidden You are not authorized to access this resource. While your credentials
may be valid, you don't have the necessary permissions.
404 Not Found The specific resource or endpoint you requested does not exist.
48 Trellix Endpoint Detection and Response Product Guide

1| Trellix EDR APIs
Status Response Description
415 Unsupported Media Type The server rejected your request because the data format (Content-
Type) is not supported.
429 Too Many Requests You've exceeded the rate limit by sending too many requests in a short
period. The Retry-After header in the response will tell you how long to
wait before trying again.
500 Internal Server Error Something went wrong on the server's end. This is not an issue with
your request.
Get result — file export
Overview
This endpoint retrieves the complete results of a finished search and delivers them as a downloadable CSV file. Once a search
job has completed, you call this endpoint with the unique search-id and include the output and format query parameters. The
API then returns the full dataset from all queried endpoints formatted as a CSV file in the response body.
You should use this API as the final step in a search workflow, after polling the job status endpoint has confirmed that the search
is complete. It is the correct endpoint to use when you need to export the entire result set for offline analysis, archiving, or
ingestion into other security tools and reporting platforms.
Authentication
Authentication type: Bearer Token, API Key.
You can create a token using client credentials obtained through the developer portal. The API Key (x-api-key) is provided in
your onboarding email or on the API Access Management page.
Path (or URL)
GET https://{Trellix EDR_gateway_URL}/edr/v2/searches/historical/{search-id}/results?output=file&format=csv
Example — {search-id}: hs-12212
Trellix Endpoint Detection and Response Product Guide 49

1| Trellix EDR APIs
Request
Request headers
Authorization: Bearer <your_bearer_token>
Content-Type: application/vnd.api+json
x-api-key: <your_api_key>
Accept-Encoding: gzip
• Authorization: This header is used to authenticate your request. You need to replace <your_bearer_token> with the actual
token you generate.
• Content-Type: This header tells the server that the request body format is json:api. Even though this specific call has no
request body, the API requires this header.
• x-api-key: This is a custom header required by the Trellix API for authentication. You'll need to replace <your_api_key> with
the key from your onboarding email or the API Access Management page.
• Accept-Encoding: This is an optional header you can include to tell the server you can accept a compressed response (using
gzip), which can make the data transfer faster.
Request parameters
Parameters Data type/Values Description
page[offset] Integer Number of records to skip (starts from 0th record)
page[limit] Integer Number of records to fetch on a page
output "file" Sets the response as a file
format "csv" Sets the export file format to CSV
Note
If you don't add 'output' and 'format' parameters to the endpoint URL, the results are displayed in the paginated format
instead of the file format. For fetching results in the file format, it is mandatory to provide both output and format
parameters.
50 Trellix Endpoint Detection and Response Product Guide

1| Trellix EDR APIs
For more details about the Real-time Search APIs, see Trellix Developer Portal.
Response
Response codes
Status Response Description
200 OK Your request was processed successfully. The server has returned the
requested data.
400 Bad request The server couldn't understand your request, likely due to a syntax error
or an invalid parameter.
401 Access denied request Your request was rejected because it lacks valid authentication
credentials. Check your API key and token.
403 Forbidden You are not authorized to access this resource. While your credentials
may be valid, you don't have the necessary permissions.
404 Not Found The specific resource or endpoint you requested does not exist.
415 Unsupported Media Type The server rejected your request because the data format (Content-
Type) is not supported.
429 Too Many Requests You've exceeded the rate limit by sending too many requests in a short
period. The Retry-After header in the response will tell you how long to
wait before trying again.
500 Internal Server Error Something went wrong on the server's end. This is not an issue with
your request.
Trellix Endpoint Detection and Response Product Guide 51

1| Trellix EDR APIs
API sample for investigation
POST request
Overview
This endpoint creates a new investigation case. By providing initial details like a case name, priority, and a key piece of evidence
(such as an IP address or endpoint name), you can trigger the platform's automated data collection and analysis workflows. The
API responds immediately with the full object of the newly created investigation, including its unique ID and current status.
You should use this API to programmatically trigger an investigation from an external tool like a Security Information and Event
Management (SIEM) or a Security Orchestration, Automation, and Response (SOAR) platform. It's the primary method for
automating the first step of an incident response workflow, allowing you to automatically create a case based on an alert from
another system.
Authentication
Authentication type: Bearer Token, API Key.
You can create a token using client credentials obtained through the developer portal. The API Key (x-api-key) is provided in
your onboarding email or on the API Access Management page.
Path (or URL)
POST https://{Trellix EDR_gateway_URL}/edr/v2/investigations
You can get the gateway URL from the Trellixon-boarding email. For example, https://api.manage.trellix.com
Request
Request headers
Authorization: Bearer <your_bearer_token>
Content-Type: application/vnd.api+json
x-api-key: <your_api_key>
• Authorization: This header is used to authenticate your request. You need to replace <your_bearer_token> with the actual
token you generate.
52 Trellix Endpoint Detection and Response Product Guide

1| Trellix EDR APIs
• Content-Type: This header tells the server that the request body format is json:api. Even though this specific call has no
request body, the API requires this header.
• x-api-key: This is a custom header required by the Trellix API for authentication. You'll need to replace <your_api_key> with
the key from your onboarding email or the API Access Management page.
Request body
Example 1:
{
"data": {
"type": "investigations",
"attributes": {
"caseType": "Malware",
"caseName": "Test Incident Name",
"caseHint": "hostname",
"casePriority": "High",
"evidenceType": "IP",
"address": "123.123.123.123"
}
}
}
Example 2:
{
"data": {
"type": "investigations",
"attributes": {
"eventSrc": "TrellixESM",
"caseType": "Malware",
"caseName": "Trellix API - EDR Investigations Demo 10 August 2020 - 4",
"caseHint": "hostname4-10-08-2020",
"casePriority": "Low",
"evidenceType": "Device",
"name": "es",
"hostName": "EMB-0BXXXE9-P08_20161003101947"
}
}
Request parameters
There are no request parameters.
Trellix Endpoint Detection and Response Product Guide 53

1| Trellix EDR APIs
Response
Response example
{
"data": {
"id": "9e576c20-c526-11ea-abc6-000000000001",
"type": "investigations",
"attributes": {
"name": "Test Incident Name",
"summary": "Test Incident Summary",
"created": "2020-07-13T16:33:44.418Z",
"owner": "testuser@email.com",
"source": "unknown",
"isAutomatic": true,
"hint": "hostname",
"caseType": "malware",
"lastModified": "2020-07-13T16:33:44.418Z",
"investigated": true,
"status": "In progress",
"priority": "high"
}
}
}
Response codes
Status Response Description
201 Created Your request was successful, and a new resource was created as a
result. Your request was successful, and a new resource was created.
The response includes details such as the resource ID, which you can
use to track or manage the resource.
400 Bad request The server couldn't understand your request, likely due to a syntax error
or an invalid parameter.
401 Access denied request Your request was rejected because it lacks valid authentication
credentials. Check your API key and token.
403 Forbidden You are not authorized to access this resource. While your credentials
may be valid, you don't have the necessary permissions.
54 Trellix Endpoint Detection and Response Product Guide

1| Trellix EDR APIs
Status Response Description
404 Not Found The specific resource or endpoint you requested does not exist.
415 Unsupported Media Type The server rejected your request because the data format (Content-
Type) is not supported.
429 Too Many Requests You've exceeded the rate limit by sending too many requests in a short
period. The Retry-After header in the response will tell you how long to
wait before trying again.
500 Internal Server Error Something went wrong on the server's end. This is not an issue with
your request.
Get Investigations
Overview
This endpoint retrieves a paginated list of all investigation cases. Use query parameters to sort and paginate the results, and
include related data to gather a comprehensive overview in a single call. You should use this API when you need to retrieve a
collection of investigations, for example, to display a list of all open cases in a custom dashboard or to feed data into a reporting
engine. It's the primary method for getting a high-level overview of all investigations or for periodically polling the system to
discover newly created cases.
Authentication
Authentication type: Bearer Token, API Key.
You can create a token using client credentials obtained through the developer portal. The API Key (x-api-key) is provided in
your onboarding email or on the API Access Management page.
Path (or URL)
GET https://{Trellix EDR_gateway_URL}/edr/v2/investigations
Trellix Endpoint Detection and Response Product Guide 55

1| Trellix EDR APIs
Request
Request headers
Authorization: Bearer <your_bearer_token>
Content-Type: application/vnd.api+json
x-api-key: <your_api_key>
Accept-Encoding: gzip
• Authorization: This header is used to authenticate your request. You need to replace <your_bearer_token> with the actual
token you generate.
• Content-Type: This header tells the server that the request body format is json:api. Even though this specific call has no
request body, the API requires this header.
• x-api-key: This is a custom header required by the Trellix API for authentication. You'll need to replace <your_api_key> with
the key from your onboarding email or the API Access Management page.
• Accept-Encoding: This is an optional header you can include to tell the server you can accept a compressed response (using
gzip), which can make the data transfer faster.
Request parameters
Parameters Data type/Values Description
page[offset] integer Number of records to skip (starts from 0th record).
page[limit] integer Number of records to fetch on a page.
sort string Single column to sort by value. By default, the records are sorted in
ascending order.
Example: sort by the "created" column
include string Specifies related resources to include in the response payload. Use this
parameter to retrieve associated data in a single API call, reducing the
need for subsequent requests.
Example: When retrieving an investigation, including evidence will
return both the investigation details and the related evidence data.
56 Trellix Endpoint Detection and Response Product Guide

1| Trellix EDR APIs
Parameters Data type/Values Description
Accept- string Enable GZIP Compression to return compressed data.
Encoding Example: gzip, deflate, br
Response
Response example
{
"jsonapi": {
"version": "1.0"
},
"meta": {
"totalResourceCount": 45
},
"data": [
{
"type": "investigations",
"id": "0dc44100-430f-11ee-8b79-000000000000",
"attributes": {
"created": "2023-08-25T06:17:22.960Z",
"lastModified": "2023-08-25T06:17:22.960Z",
"name": "MVISION_API_EDR_BVT_00_2023-08-25T10:45:09.966333",
"owner": "unknown",
"summary": "",
"source": "unknown",
"isAutomatic": true,
"hint": "MVISION_API_EDR_vaii00_{{date}}{{int}}",
"caseType": "Malware",
"investigated": true,
"status": "In progress",
"priority": "Unspecified"
}
}
],
"links": {
"self": "/edr/v2/investigations?page[offset]=0&page[limit]=1",
"first": "/edr/v2/investigations?page[offset]=0&page[limit]=1",
"prev": "/edr/v2/investigations?page[offset]=1&page[limit]=1",
"next": "/edr/v2/investigations?page[offset]=1&page[limit]=1",
"last": "/edr/v2/investigations?page[offset]=44&page[limit]=1"
}
}
Trellix Endpoint Detection and Response Product Guide 57

1| Trellix EDR APIs
Response codes
Status Response Description
200 OK Your request was processed successfully. The server has returned the
requested data.
400 Bad request The server couldn't understand your request, likely due to a syntax error
or an invalid parameter.
401 Access denied request Your request was rejected because it lacks valid authentication
credentials. Check your API key and token.
403 Forbidden You are not authorized to access this resource. While your credentials
may be valid, you don't have the necessary permissions.
404 Not Found The specific resource or endpoint you requested does not exist.
415 Unsupported Media Type The server rejected your request because the data format (Content-
Type) is not supported.
429 Too Many Requests You've exceeded the rate limit by sending too many requests in a short
period. The Retry-After header in the response will tell you how long to
wait before trying again.
500 Internal Server Error Something went wrong on the server's end. This is not an issue with
your request.
Get Investigations by ID
Overview
This endpoint retrieves the complete details for a single investigation case by its unique ID. By providing the investigations-id
in the path, you can fetch a full snapshot of the case, including its attributes and relationships to other resources. You can also
use the optional include parameter to efficiently pull in related data, like evidence, within the same API call. You should use this
API whenever you need to fetch the current state and all associated details of a specific investigation.
58 Trellix Endpoint Detection and Response Product Guide

1| Trellix EDR APIs
Authentication
Authentication type: Bearer Token, API Key.
You can create a token using client credentials obtained through the developer portal. The API Key (x-api-key) is provided in
your onboarding email or on the API Access Management page.
Path (or URL)
GET https://{Trellix EDR_gateway_URL}/edr/v2/investigations/{investigations-id}
Example — {investigations-id}: f61dd2a0-37e9-11ec-982e-000000000000
Request
Request headers
Authorization: Bearer <your_bearer_token>
Content-Type: application/vnd.api+json
x-api-key: <your_api_key>
Accept-Encoding: gzip
• Authorization: This header is used to authenticate your request. You need to replace <your_bearer_token> with the actual
token you generate.
• Content-Type: This header tells the server that the request body format is json:api. Even though this specific call has no
request body, the API requires this header.
• x-api-key: This is a custom header required by the Trellix API for authentication. You'll need to replace <your_api_key> with
the key from your onboarding email or the API Access Management page.
• Accept-Encoding: This is an optional header you can include to tell the server you can accept a compressed response (using
gzip), which can make the data transfer faster.
Request parameters
Parameters Data type/Values Description
Trellix Endpoint Detection and Response Product Guide 59

1| Trellix EDR APIs
Parameters Data type/Values Description
investigationI string Unique identifier for investigation case.
d
include string Specifies related resources to include in the response payload. Use this
parameter to retrieve associated data in a single API call, reducing the
need for subsequent requests.
Example: When retrieving an investigation, including evidence will
return both the investigation details and the related evidence data.
Accept- string Enable GZIP Compression to return compressed data.
Encoding Example: gzip, deflate, br
Response
Response example
{
"jsonapi": {
"version": "1.0"
},
"meta": {
"totalResourceCount": 1
},
"data": {
"type": "investigations",
"id": "0dc44100-430f-11ee-8b79-000000000000",
"attributes": {
"created": "2023-08-25T06:17:22.960Z",
"lastModified": "2023-08-25T06:17:22.960Z",
"name": "MVISION_API_EDR_BVT_00_2023-08-25T10:45:09.966333",
"owner": "unknown",
"summary": "",
"source": "unknown",
"isAutomatic": true,
"hint": "MVISION_API_EDR_vaii00_{{date}}{{int}}",
"caseType": "Malware",
"investigated": true,
"status": "In progress",
"priority": "Unspecified"
},
"relationships": {
"evidenceInfo": {
"data": [
{
"evidenceType": "device",
60 Trellix Endpoint Detection and Response Product Guide

1| Trellix EDR APIs
"evidenceValue": {
"attributes": {
"name": "MVISION_API_EDR_BVT_IP_0008",
"hostName": "Vais9999-vm",
"rawData": "",
"__clue": "true",
"__fromThreat": ""
},
"created": "2023-08-25T06:17:23.055Z"
}
}
],
"links": {
"self": "/edr/v2/investigations/0dc44100-430f-11ee-8b79-000000000000/
evidence?page[offset]=0&page[limit]=100",
"first": "/edr/v2/investigations/0dc44100-430f-11ee-8b79-000000000000/
evidence?page[offset]=0&page[limit]=100",
"prev": "/edr/v2/investigations/0dc44100-430f-11ee-8b79-000000000000/
evidence?page[offset]=0&page[limit]=100",
"next": "/edr/v2/investigations/0dc44100-430f-11ee-8b79-000000000000/
evidence?page[offset]=0&page[limit]=100",
"last": "/edr/v2/investigations/0dc44100-430f-11ee-8b79-000000000000/
evidence?page[offset]=0&page[limit]=100"
}
}
}
}
}
Response codes
Status Response Description
200 OK Your request was processed successfully. The server has returned the
requested data.
400 Bad request The server couldn't understand your request, likely due to a syntax error
or an invalid parameter.
401 Access denied request Your request was rejected because it lacks valid authentication
credentials. Check your API key and token.
403 Forbidden You are not authorized to access this resource. While your credentials
may be valid, you don't have the necessary permissions.
404 Not Found The specific resource or endpoint you requested does not exist.
Trellix Endpoint Detection and Response Product Guide 61

1| Trellix EDR APIs
Status Response Description
415 Unsupported Media Type The server rejected your request because the data format (Content-
Type) is not supported.
429 Too Many Requests You've exceeded the rate limit by sending too many requests in a short
period. The Retry-After header in the response will tell you how long to
wait before trying again.
500 Internal Server Error Something went wrong on the server's end. This is not an issue with
your request.
Patch investigations
Overview
This endpoint modifies an existing investigation case. Provide the unique investigations-id in the path to update details like
the case's name, summary, status, or priority. Include only the fields you want to change in the request body; the API will return
the full, updated investigation object. Use this API to programmatically manage an investigation's lifecycle. It is essential for
workflows that change a case's status, update its priority, or synchronize its state with an external ticketing or case management
system.
Authentication
Authentication type: Bearer Token, API Key.
You can create a token using client credentials obtained through the developer portal. The API Key (x-api-key) is provided in
your onboarding email or on the API Access Management page.
Path (or URL)
PATCH https://{Trellix EDR_gateway_URL}/edr/v2/investigations/{investigations-id}
Example — {investigations-id}: f61dd2a0-37e9-11ec-982e-000000000000
62 Trellix Endpoint Detection and Response Product Guide

1| Trellix EDR APIs
Request
Request headers
Authorization: Bearer <your_bearer_token>
Content-Type: application/vnd.api+json
x-api-key: <your_api_key>
• Authorization: This header is used to authenticate your request. You need to replace <your_bearer_token> with the actual
token you generate.
• Content-Type: This header tells the server that the request body format is json:api. Even though this specific call has no
request body, the API requires this header.
• x-api-key: This is a custom header required by the Trellix API for authentication. You'll need to replace <your_api_key> with
the key from your onboarding email or the API Access Management page.
Request body
{
"data": {
"id": "53555d40-458e-11ee-98ee-000000000000",
"type": "investigations",
"attributes": {
"caseName": "Malware",
"caseSummary": "Test Incident Name",
"caseStatus": "New",
"casePriority": "High"
}
}
}
Request parameters
Parameters Data type/Values Description
investigationI string Unique identifier for investigation case.
d
Trellix Endpoint Detection and Response Product Guide 63

1| Trellix EDR APIs
Response
Response example
{
"data": {
"type": "investigations",
"id": "53555d40-458e-11ee-98ee-000000000000",
"attributes": {
"created": "2023-08-28T10:33:28.084Z",
"lastModified": "2023-08-29T09:08:26Z",
"name": "Malware",
"owner": "unknown",
"summary": "Test Incident Name",
"source": "unknown",
"isAutomatic": true,
"hint": "hostname3145",
"caseType": "Malware",
"investigated": true,
"status": "New",
"priority": "High"
}
}
}
Response codes
Status Response Description
200 OK Your request was processed successfully. The server has returned the
requested data.
400 Bad request The server couldn't understand your request, likely due to a syntax error
or an invalid parameter.
401 Access denied request Your request was rejected because it lacks valid authentication
credentials. Check your API key and token.
403 Forbidden You are not authorized to access this resource. While your credentials
may be valid, you don't have the necessary permissions.
404 Not Found The specific resource or endpoint you requested does not exist.
64 Trellix Endpoint Detection and Response Product Guide

1| Trellix EDR APIs
Status Response Description
415 Unsupported Media Type The server rejected your request because the data format (Content-
Type) is not supported.
429 Too Many Requests You've exceeded the rate limit by sending too many requests in a short
period. The Retry-After header in the response will tell you how long to
wait before trying again.
500 Internal Server Error Something went wrong on the server's end. This is not an issue with
your request.
Delete investigations
Overview
This endpoint permanently deletes an investigation case and its associated data. Use the unique investigations-id to target a
case for removal. A successful request is irreversible and returns a 204 No Content response. Use this API for removing old cases
after a retention period or deleting confirmed false positives that no longer require review. This API helps enforce data retention
policies and reduces clutter, keeping your investigation queue focused on active threats.
Authentication
Authentication type: Bearer Token, API Key.
You can create a token using client credentials obtained through the developer portal. The API Key (x-api-key) is provided in
your onboarding email or on the API Access Management page.
Path (or URL)
DELETE https://{Trellix EDR_gateway_URL}/edr/v2/investigations/{investigations-id}
Example — {investigations-id}: f61dd2a0-37e9-11ec-982e-000000000000
Trellix Endpoint Detection and Response Product Guide 65

1| Trellix EDR APIs
Request
Request headers
Authorization: Bearer <your_bearer_token>
Content-Type: application/vnd.api+json
x-api-key: <your_api_key>
• Authorization: This header is used to authenticate your request. You need to replace <your_bearer_token> with the actual
token you generate.
• Content-Type: This header tells the server that the request body format is json:api. Even though this specific call has no
request body, the API requires this header.
• x-api-key: This is a custom header required by the Trellix API for authentication. You'll need to replace <your_api_key> with
the key from your onboarding email or the API Access Management page.
Request parameters
Parameters Data type/Values Description
investigationId string Unique identifier for investigation
case.
Response
Response codes
Status Response Description
204 No Content The investigation, along with its associated data was permanently
deleted.
66 Trellix Endpoint Detection and Response Product Guide

1| Trellix EDR APIs
Status Response Description
400 Bad request The server couldn't understand your request, likely due to a syntax error
or an invalid parameter.
401 Access denied request Your request was rejected because it lacks valid authentication
credentials. Check your API key and token.
403 Forbidden You are not authorized to access this resource. While your credentials
may be valid, you don't have the necessary permissions.
404 Not Found The specific resource or endpoint you requested does not exist.
415 Unsupported Media Type The server rejected your request because the data format (Content-
Type) is not supported.
429 Too Many Requests You've exceeded the rate limit by sending too many requests in a short
period. The Retry-After header in the response will tell you how long to
wait before trying again.
500 Internal Server Error Something went wrong on the server's end. This is not an issue with
your request.
POST - Metadata
Overview
This endpoint performs a bulk lookup to retrieve internal system metadata, like the hostId, for a given list of endpoint
hostnames. You provide an array of hostnames, and the API returns a multi-status response that explicitly lists which hostnames
were successfully found and which failed. This allows you to efficiently translate human-readable names into the system
identifiers required for other API operations.
Authentication
Authentication type: Bearer Token, API Key.
You can create a token using client credentials obtained through the developer portal. The API Key (x-api-key) is provided in
Trellix Endpoint Detection and Response Product Guide 67

1| Trellix EDR APIs
your onboarding email or on the API Access Management page.
Path (or URL)
POST https://{Trellix EDR_gateway_URL}/edr/v2/investigations/metadata
Request
Request headers
Authorization: Bearer <your_bearer_token>
Content-Type: application/vnd.api+json
x-api-key: <your_api_key>
• Authorization: This header is used to authenticate your request. You need to replace <your_bearer_token> with the actual
token you generate.
• Content-Type: This header tells the server that the request body format is json:api. Even though this specific call has no
request body, the API requires this header.
• x-api-key: This is a custom header required by the Trellix API for authentication. You'll need to replace <your_api_key> with
the key from your onboarding email or the API Access Management page.
Request body
{
"data": {
"type": "metadata",
"attributes": {
"hostNames": [
"77NSUSE15SP201",
"DESKTOP-2HS9OV4"
]
}
}
}
Request parameters
There are no request parameters.
68 Trellix Endpoint Detection and Response Product Guide

1| Trellix EDR APIs
Response
Response example
{
"jsonapi": {
"version": "1.0"
},
"meta": {
"totalResourceCount": 1
},
"data": {
"id": "aeaf39ef-1ae6-4b57-9097-f92cd2eb7627",
"type": "metadata",
"attributes": {
"success": [
{
"status": "200",
"message": "success",
"hostInfo": [
{
"hostName": "77NSUSE15SP201",
"hostId": "EC9B574D-DE1E-ED11-87C6-005056ACB455"
}
]
}
],
"failed": [
{
"status": "404",
"message": "Not Found",
"hostNames": [
"DESKTOP-2HS9OV4"
]
}
]
}
}
}
Response codes
Status Response Description
207 Successful Your request was processed. The body will contain separate lists for the
hostnames that were found successfully and those that failed.
400 Bad request The server couldn't understand your request, likely due to a syntax error
or an invalid parameter.
Trellix Endpoint Detection and Response Product Guide 69

1| Trellix EDR APIs
Status Response Description
401 Access denied request Your request was rejected because it lacks valid authentication
credentials. Check your API key and token.
403 Forbidden You are not authorized to access this resource. While your credentials
may be valid, you don't have the necessary permissions.
404 Not Found The specific resource or endpoint you requested does not exist.
415 Unsupported Media Type The server rejected your request because the data format (Content-
Type) is not supported.
429 Too Many Requests You've exceeded the rate limit by sending too many requests in a short
period. The Retry-After header in the response will tell you how long to
wait before trying again.
500 Internal Server Error Something went wrong on the server's end. This is not an issue with
your request.
GET - Evidence
Overview
This endpoint retrieves a paginated list of all evidence associated with a specific investigation. By providing the investigationId,
you can fetch all related artifacts, and you can use query parameters to filter by evidence type and navigate through the results.
Use this API to retrieve the specific artifacts (like devices, IPs, or file hashes) linked to an investigation. It's the next logical step
after identifying a case of interest, allowing your workflow to extract the raw data needed for enrichment, correlation with other
systems, or direct remediation actions.
Authentication
Authentication type: Bearer Token, API Key.
You can create a token using client credentials obtained through the developer portal. The API Key (x-api-key) is provided in
your onboarding email or on the API Access Management page.
70 Trellix Endpoint Detection and Response Product Guide

1| Trellix EDR APIs
Path (or URL)
GET https://{Trellix EDR_gateway_URL}/edr/v2/investigations/{investigationId}/evidence
Request
Request headers
Authorization: Bearer <your_bearer_token>
Content-Type: application/vnd.api+json
x-api-key: <your_api_key>
Accept-Encoding: gzip
• Authorization: This header is used to authenticate your request. You need to replace <your_bearer_token> with the actual
token you generate.
• Content-Type: This header tells the server that the request body format is json:api. Even though this specific call has no
request body, the API requires this header.
• x-api-key: This is a custom header required by the Trellix API for authentication. You'll need to replace <your_api_key> with
the key from your onboarding email or the API Access Management page.
• Accept-Encoding: This is an optional header you can include to tell the server you can accept a compressed response (using
gzip), which can make the data transfer faster.
Request parameters
Parameters Data type/Values Description
investigationI string Unique identifier for investigation case.
d
evidenceType string evidence Type for investigation case.
page[offset] integer Number of records to skip (starts from 0th record).
page[limit] integer Number of records to fetch on a page.
Trellix Endpoint Detection and Response Product Guide 71

1| Trellix EDR APIs
Parameters Data type/Values Description
Accept- string Enable GZIP Compression to return compressed data.
Encoding Example: gzip, deflate, br
Response
Response example
{
"meta": {
"totalResourceCount": 7
},
"jsonapi": {
"version": "1.0"
},
"data": {
"type": "evidence",
"id": "0dc44100-430f-11ee-8b79-000000000000",
"attributes": {
"investigationInfo": {
"name": "MVISION_API_EDR_BVT_00_2023-08-25T10:45:09.966333",
"owner": "unknown",
"summary": "",
"created": "2023-08-25T06:17:22.960Z",
"lastModified": "2023-08-25T06:17:22.960Z",
"investigated": true
},
"evidenceInfo": [
{
"evidenceType": "device",
"evidenceValue": {
"attributes": {
"name": "MVISION_API_EDR_BVT_IP_0008",
"hostName": "Vais9999-vm",
"rawData": "",
"__clue": "true",
"__fromThreat": ""
},
"created": "2023-08-25T06:17:23.055Z"
}
}
]
}
},
"links": {
"self": "/edr/v2/investigations/0dc44100-430f-11ee-8b79-000000000000/
evidence?page[offset]=0&page[limit]=1",
"first": "/edr/v2/investigations/0dc44100-430f-11ee-8b79-000000000000/
evidence?page[offset]=0&page[limit]=1",
"prev": "/edr/v2/investigations/0dc44100-430f-11ee-8b79-000000000000/
evidence?page[offset]=1&page[limit]=1",
"next": "/edr/v2/investigations/0dc44100-430f-11ee-8b79-000000000000/
72 Trellix Endpoint Detection and Response Product Guide

1| Trellix EDR APIs
evidence?page[offset]=1&page[limit]=1",
"last": "/edr/v2/investigations/0dc44100-430f-11ee-8b79-000000000000/
evidence?page[offset]=6&page[limit]=1"
}
}
Response codes
Status Response Description
200 OK Your request was processed successfully. The server has returned the
requested data.
400 Bad request The server couldn't understand your request, likely due to a syntax error
or an invalid parameter.
401 Access denied request Your request was rejected because it lacks valid authentication
credentials. Check your API key and token.
403 Forbidden You are not authorized to access this resource. While your credentials
may be valid, you don't have the necessary permissions.
404 Not Found The specific resource or endpoint you requested does not exist.
415 Unsupported Media Type The server rejected your request because the data format (Content-
Type) is not supported.
429 Too Many Requests You've exceeded the rate limit by sending too many requests in a short
period. The Retry-After header in the response will tell you how long to
wait before trying again.
500 Internal Server Error Something went wrong on the server's end. This is not an issue with
your request.
Trellix Endpoint Detection and Response Product Guide 73

1| Trellix EDR APIs
API sample for remediation
POST - Host Remediation
Overview
This endpoint executes a specific command, like quarantining or killing a process, on one or more endpoints. Provide the action,
target hostIds, and any required actionInputs. The API creates an asynchronous job and returns an ID for tracking the
outcome. Use this API for urgent, manual interventions, like an analyst quarantining a compromised endpoint, or for playbooks
that perform specific system tasks outside of a formal threat response. This API provides granular, command-level control,
offering a flexible response capability that is not limited to pre-defined threat detections.
Authentication
Authentication type: Bearer Token, API Key.
You can create a token using client credentials obtained through the developer portal. The API Key (x-api-key) is provided in
your onboarding email or on the API Access Management page.
Path (or URL)
POST https://{Trellix EDR_gateway_URL}/edr/v2/remediation/host
You can get the gateway URL from the Trellix on-boarding email. For example, https://api.manage.trellix.com.
Request
Request headers
Authorization: Bearer <your_bearer_token>
Content-Type: application/vnd.api+json
x-api-key: <your_api_key>
X-MVEDR-Source: <source_region>
X-Trace-Id: <trace_id_value>
• Authorization: This header is used to authenticate your request. You need to replace <your_bearer_token> with the actual
token you generate.
• Content-Type: This header tells the server that the request body format is json:api. Even though this specific call has no
74 Trellix Endpoint Detection and Response Product Guide

1| Trellix EDR APIs
request body, the API requires this header.
• x-api-key: This is a custom header required by the Trellix API for authentication. You'll need to replace <your_api_key> with
the key from your onboarding email or the API Access Management page.
• X-MVEDR-Source (Optional): Indicates the region or source of the event data using the format xdrsoar:<region>. For
example, xdrsoar:us-west.
• X-Trace-Id (Optional): Supports tracking headers trace using the format workflow-id:task/step-id. For example,
execution-id:task/step-id.
Request body
Example 1:
{
"data": {
"type": "hostRemediation",
"attributes": {
"action": "quarantineHost",
"hostIds": [
"C6C4B1D2-1EDD-11ED-178D-005056AC6A75",
"C6C4B1D2-1EDD-11ED-178D-005056AC6A76"
]
}
}
}
Example 2:
{
"data": {
"type": "hostRemediation",
"attributes": {
"action": "killProcessByName",
"hostIds": [
"E4F47D88-BB73-11EF-0ABE-005056A48646"
],
"actionInputs": [
{
"name": "name",
"value": "explorer.exe"
}
]
}
}
}
Note
Name and value pair combination is unique for the provided action. Any incorrect combination results in the API showing an
error.
Trellix Endpoint Detection and Response Product Guide 75

1| Trellix EDR APIs
Example 3:
{
"data": {
"type": "hostRemediation",
"attributes": {
"action": "_create_file_win",
"actionInputs": [
{
"name": "full_path",
"value": "C:/Users/cdaauto/AppData/Local/Temp/MVAPITest_HR.txt"
}
],
"hostIds": [
"51C07FCA-08AD-11F1-04E0-005056AC90E3"
]
}
}
}
Note
Custom reactions are prefixed with _.
Request parameters
There are no request parameters.
Response
Response example
{
"data": {
"type": "hostRemediation",
"id": "hr-5432",
"attributes": {
"success": [
{
"status": "200",
"message": "in-progress",
"hostIds": [
"902F4237-B838-ED11-87C6-005056A4B536",
"902F4237-B838-ED11-87C6-005056A4B537"
]
}
],
"failed": [
{
"status": "409",
"message": "conflict, Either Some operation is going on Agent guid or its already
inQuarantineHoststate",
76 Trellix Endpoint Detection and Response Product Guide

1| Trellix EDR APIs
"hostIds": [
"902F4237-B838-ED11-87C6-005056A4B534",
"902F4237-B838-ED11-87C6-005056A4B535"
]
}
]
},
"links": {
"self": "/edr/v2/remediation/queue-jobs/rem-5432"
}
}
}
Response codes
Status Response Description
207 Created Your request to create a remediation job was accepted and is being
processed. The response body will detail which parts of the submission
succeeded or failed.
400 Bad request The server couldn't understand your request, likely due to a syntax error
or an invalid parameter.
401 Access denied request Your request was rejected because it lacks valid authentication
credentials. Check your API key and token.
403 Forbidden You are not authorized to access this resource. While your credentials
may be valid, you don't have the necessary permissions.
404 Not Found The specific resource or endpoint you requested does not exist.
415 Unsupported Media Type The server rejected your request because the data format (Content-
Type) is not supported.
429 Too Many Requests You've exceeded the rate limit by sending too many requests in a short
period. The Retry-After header in the response will tell you how long to
wait before trying again.
500 Internal Server Error Something went wrong on the server's end. This is not an issue with
your request.
Trellix Endpoint Detection and Response Product Guide 77

1| Trellix EDR APIs
POST - Search Remediation
Overview
This endpoint creates an asynchronous remediation job based on specific results from a previous search. Provide a searchId,
the target rowIds , and the action to perform. The API returns a job ID for tracking the outcome. Use this API to complete a "hunt
and respond" workflow. After searching to identify endpoints exhibiting specific behavior, use this endpoint to take immediate
action on those findings. This API directly connects detection with response, enabling remediation based on live search results,
not just pre-defined threat signatures.
Authentication
Authentication type: Bearer Token, API Key.
You can create a token using client credentials obtained through the developer portal. The API Key (x-api-key) is provided in
your onboarding email or on the API Access Management page.
Path (or URL)
POST https://{Trellix EDR_gateway_URL}/edr/v2/remediation/search
Request
Request headers
Authorization: Bearer <your_bearer_token>
Content-Type: application/vnd.api+json
x-api-key: <your_api_key>
X-MVEDR-Source: <source_region>
X-Trace-Id: <trace_id_value>
• Authorization: This header is used to authenticate your request. You need to replace <your_bearer_token> with the actual
token you generate.
• Content-Type: This header tells the server that the request body format is json:api. Even though this specific call has no
request body, the API requires this header.
• x-api-key: This is a custom header required by the Trellix API for authentication. You'll need to replace <your_api_key> with
the key from your onboarding email or the API Access Management page.
78 Trellix Endpoint Detection and Response Product Guide

1| Trellix EDR APIs
• X-MVEDR-Source (Optional): Indicates the region or source of the event data using the format xdrsoar:<region>. For
example, xdrsoar:us-west.
• X-Trace-Id (Optional): Supports tracking headers trace using the format workflow-id:task/step-id. For example,
execution-id:task/step-id.
Request body
Example 1:
{
"data": {
"type": "searchRemediation",
"attributes": {
"action": "killProcess",
"searchId": "rts-3167",
"rowIds": [
"ff5c00e2fcc56bf166c61dea28a1c8d0",
"385a2b8bb9b533407c996069231c3824"
],
"actionInputs": [
{
"name": "pid",
"value": "23451"
}
]
}
}
}
Example 2:
{
"data": {
"type": "searchRemediation",
"attributes": {
"action": "_create_file_win",
"searchId": "rts-342746",
"rowIds": [
"20ed4679fb089e2a6483c0b5198a179c"
],
"actionInputs": [
{
"name": "full_path",
"value": "C:/Users/cdaauto/AppData/Local/Temp/MVAPITest_SR.txt"
}
]
}
}
}
Request parameters
There are no request parameters.
Trellix Endpoint Detection and Response Product Guide 79

1| Trellix EDR APIs
Response
Response example
{
"data": {
"type": "searchRemediation",
"id": "sr-9132",
"attributes": {
"success": [
{
"status": "200",
"message": "in-progress"
}
],
"failed": [
{
"status": "500",
"message": "Internal Server Error while submitting the remediation request"
}
]
},
"links": {
"self": "/edr/v2/remediation/queue-jobs/sr-9132"
}
}
Response codes
Status Response Description
207 Created Your request to create a remediation job was accepted and is being
processed. The response body will detail which parts of the submission
succeeded or failed.
400 Bad request The server couldn't understand your request, likely due to a syntax error
or an invalid parameter.
401 Access denied request Your request was rejected because it lacks valid authentication
credentials. Check your API key and token.
403 Forbidden You are not authorized to access this resource. While your credentials
may be valid, you don't have the necessary permissions.
80 Trellix Endpoint Detection and Response Product Guide

1| Trellix EDR APIs
Status Response Description
404 Not Found The specific resource or endpoint you requested does not exist.
415 Unsupported Media Type The server rejected your request because the data format (Content-
Type) is not supported.
429 Too Many Requests You've exceeded the rate limit by sending too many requests in a short
period. The Retry-After header in the response will tell you how long to
wait before trying again.
500 Internal Server Error Something went wrong on the server's end. This is not an issue with
your request.
POST - Threat Remediation
Overview
This endpoint initiates a remediation action against a specified threat on one or more endpoints. By defining an action,
threatId, and a list of affectedHostIds, you can trigger a response like stopping and removing a malicious process. The API
creates an asynchronous job and returns an ID for tracking its progress and final status. Use this API as the action component in
a SOAR playbook to automatically contain threats upon detection, or to apply a remediation action across many endpoints for a
scaled response. This API closes the loop from detection to response, enabling automated containment at scale to dramatically
reduce threat impact.
Authentication
Authentication type: Bearer Token, API Key.
You can create a token using client credentials obtained through the developer portal. The API Key (x-api-key) is provided in
your onboarding email or on the API Access Management page.
Path (or URL)
POST https://{Trellix EDR_gateway_URL}/edr/v2/remediation/threat
Trellix Endpoint Detection and Response Product Guide 81

1| Trellix EDR APIs
Request
Request headers
Authorization: Bearer <your_bearer_token>
Content-Type: application/vnd.api+json
x-api-key: <your_api_key>
X-MVEDR-Source: <source_region>
X-Trace-Id: <trace_id_value>
• Authorization: This header is used to authenticate your request. You need to replace <your_bearer_token> with the actual
token you generate.
• Content-Type: This header tells the server that the request body format is json:api. Even though this specific call has no
request body, the API requires this header.
• x-api-key: This is a custom header required by the Trellix API for authentication. You'll need to replace <your_api_key> with
the key from your onboarding email or the API Access Management page.
• X-MVEDR-Source (Optional): Indicates the region or source of the event data using the format xdrsoar:<region>. For
example, xdrsoar:us-west.
• X-Trace-Id (Optional): Supports tracking headers trace using the format workflow-id:task/step-id. For example,
execution-id:task/step-id.
Request body
Example:
{
"data": {
"type": "threatRemediation",
"attributes": {
"action": "StopAndRemove",
"threatId": "3500",
"processName": "Keep-Running.exe",
"affectedHostIds": [
"99848",
"99849"
]
}
}
}
82 Trellix Endpoint Detection and Response Product Guide

1| Trellix EDR APIs
Request parameters
There are no request parameters.
Response
Response example
{
"data": {
"type": "threatRemediation",
"id": "tr-5432",
"attributes": {
"success": [
{
"status": "200",
"message": "in-progress",
"affectedHostIds": [
"99848"
]
}
],
"failed": [
{
"status": "404",
"message": "Not Found",
"affectedHostIds": [
"99849"
]
}
]
},
"links": {
"self": "/edr/v2/remediation/queue-jobs/tr-5432"
}
}
}
Response codes
Status Response Description
207 Created Your request to create a remediation job was accepted and is being
processed. The response body will detail which parts of the submission
succeeded or failed.
Trellix Endpoint Detection and Response Product Guide 83

1| Trellix EDR APIs
Status Response Description
400 Bad request The server couldn't understand your request, likely due to a syntax error
or an invalid parameter.
401 Access denied request Your request was rejected because it lacks valid authentication
credentials. Check your API key and token.
403 Forbidden You are not authorized to access this resource. While your credentials
may be valid, you don't have the necessary permissions.
404 Not Found The specific resource or endpoint you requested does not exist.
415 Unsupported Media Type The server rejected your request because the data format (Content-
Type) is not supported.
429 Too Many Requests You've exceeded the rate limit by sending too many requests in a short
period. The Retry-After header in the response will tell you how long to
wait before trying again.
500 Internal Server Error Something went wrong on the server's end. This is not an issue with
your request.
POST - Global-Threats
Overview
This endpoint performs a global action on a threat record itself, rather than on an endpoint. Provide an action (e.g.,
"DismissThreat") and a threatId to create a job that applies the change system-wide. Use this API to manage the lifecycle of a
threat detection. It is primarily used to globally dismiss a threat that has been investigated and confirmed as a false positive. This
API helps reduce alert fatigue by providing a programmatic way to close out irrelevant or benign detections, keeping analyst
queues focused on active threats.
Authentication
Authentication type: Bearer Token, API Key.
84 Trellix Endpoint Detection and Response Product Guide

1| Trellix EDR APIs
You can create a token using client credentials obtained through the developer portal. The API Key (x-api-key) is provided in
your onboarding email or on the API Access Management page.
Path (or URL)
POST https://{Trellix EDR_gateway_URL}/edr/v2/remediation/global-threat
Request
Request headers
Authorization: Bearer <your_bearer_token>
Content-Type: application/vnd.api+json
x-api-key: <your_api_key>
X-MVEDR-Source: <source_region>
X-Trace-Id: <trace_id_value>
• Authorization: This header is used to authenticate your request. You need to replace <your_bearer_token> with the actual
token you generate.
• Content-Type: This header tells the server that the request body format is json:api. Even though this specific call has no
request body, the API requires this header.
• x-api-key: This is a custom header required by the Trellix API for authentication. You'll need to replace <your_api_key> with
the key from your onboarding email or the API Access Management page.
• X-MVEDR-Source (Optional): Indicates the region or source of the event data using the format xdrsoar:<region>. For
example, xdrsoar:us-west.
• X-Trace-Id (Optional): Supports tracking headers trace using the format workflow-id:task/step-id. For example,
execution-id:task/step-id.
Request body
Example:
{
"data": {
"type": "globalThreatRemediation",
"attributes": {
"action": "DismissThreat",
"threatActionArguments": {
"threatId": "string"
}
Trellix Endpoint Detection and Response Product Guide 85

1| Trellix EDR APIs
}
}
}
Request parameters
There are no request parameters.
Response
Response example
{
"data": {
"type": "globalThreatRemediation",
"id": "gtr-36267",
"attributes": {
"status": "COMPLETED"
},
"links": {
"self": "/edr/v2/remediation/queue-jobs/gtr-36267"
}
}
}
Response codes
Status Response Description
201 Created Your request was successful, and a new resource was created as a
result. Your request was successful, and a new resource was created.
The response includes details such as the resource ID, which you can
use to track or manage the resource.
400 Bad request The server couldn't understand your request, likely due to a syntax error
or an invalid parameter.
401 Access denied request Your request was rejected because it lacks valid authentication
credentials. Check your API key and token.
86 Trellix Endpoint Detection and Response Product Guide

1| Trellix EDR APIs
Status Response Description
403 Forbidden You are not authorized to access this resource. While your credentials
may be valid, you don't have the necessary permissions.
404 Not Found The specific resource or endpoint you requested does not exist.
415 Unsupported Media Type The server rejected your request because the data format (Content-
Type) is not supported.
429 Too Many Requests You've exceeded the rate limit by sending too many requests in a short
period. The Retry-After header in the response will tell you how long to
wait before trying again.
500 Internal Server Error Something went wrong on the server's end. This is not an issue with
your request.
POST - Exclusions
Overview
This endpoint creates a detection exclusion based on specific criteria. Provide a name, description, and exclusionArguments (like
a SHA-256 hash or file path). The API registers the new rule and returns a job ID along with the unique exclusionId. Use this API
to prevent a known, legitimate application from triggering future alerts. It's the primary method for programmatically allowing
trusted internal tools or specific business software to operate without being flagged. This API enables the automated tuning of
detection logic, reducing alert noise and ensuring that security operations can focus on genuine threats.
Authentication
Authentication type: Bearer Token, API Key.
You can create a token using client credentials obtained through the developer portal. The API Key (x-api-key) is provided in
your onboarding email or on the API Access Management page.
Trellix Endpoint Detection and Response Product Guide 87

1| Trellix EDR APIs
Path (or URL)
POST https://{Trellix EDR_gateway_URL}/edr/v2/remediation/exclusions
Request
Request headers
Authorization: Bearer <your_bearer_token>
Content-Type: application/vnd.api+json
x-api-key: <your_api_key>
X-MVEDR-Source: <source_region>
X-Trace-Id: <trace_id_value>
• Authorization: This header is used to authenticate your request. You need to replace <your_bearer_token> with the actual
token you generate.
• Content-Type: This header tells the server that the request body format is json:api. Even though this specific call has no
request body, the API requires this header.
• x-api-key: This is a custom header required by the Trellix API for authentication. You'll need to replace <your_api_key> with
the key from your onboarding email or the API Access Management page.
• X-MVEDR-Source (Optional): Indicates the region or source of the event data using the format xdrsoar:<region>. For
example, xdrsoar:us-west.
• X-Trace-Id (Optional): Supports tracking headers trace using the format workflow-id:task/step-id. For example,
execution-id:task/step-id.
Request body
Example:
{
"data": {
"type": "threatExclusion",
"attributes": {
"exclusionName": "Datagenerator.exe",
"description": "SHA256 Hash for Datagenerator executable",
"exclusionArguments": [
{
"name": "SHA-256",
"value": "51c8e205f3cb6fece20c38e75f5602f9b602c76cb0cd1c008afde60d8aebbba0"
},
{
"name": "file_path",
88 Trellix Endpoint Detection and Response Product Guide

1| Trellix EDR APIs
"value": "C:\\testing-linux\\spichap-01.exe"
},
{
"name": "command_line",
"value": "C:\\WINDOWS\\SYSTEM32\\WINDOWSPOWERSHELL\\V1.0\\POWERSHELL.EXE"
}
]
}
}
}
Request parameters
There are no request parameters.
Response
Response example
{
"data": {
"type": "queue-jobs",
"id": "te-5432",
"attributes": {
"status": "completed",
"exclusionId": "8e63d190-51e5-4f10-8367-e84f58795e4d"
},
"links": {
"self": "/edr/v2/remediation/queue-jobs/te-5432"
}
}
}
Response codes
Status Response Description
201 Created Your request was successful, and a new resource was created as a
result. Your request was successful, and a new resource was created.
The response includes details such as the resource ID, which you can
use to track or manage the resource.
400 Bad request The server couldn't understand your request, likely due to a syntax error
Trellix Endpoint Detection and Response Product Guide 89

1| Trellix EDR APIs
Status Response Description
or an invalid parameter.
401 Access denied request Your request was rejected because it lacks valid authentication
credentials. Check your API key and token.
403 Forbidden You are not authorized to access this resource. While your credentials
may be valid, you don't have the necessary permissions.
404 Not Found The specific resource or endpoint you requested does not exist.
415 Unsupported Media Type The server rejected your request because the data format (Content-
Type) is not supported.
429 Too Many Requests You've exceeded the rate limit by sending too many requests in a short
period. The Retry-After header in the response will tell you how long to
wait before trying again.
500 Internal Server Error Something went wrong on the server's end. This is not an issue with
your request.
GET - Exclusions
Overview
This endpoint retrieves a paginated list of all detection exclusions configured in the system. The response is an array of exclusion
objects, each detailing the rule's name, description, and the specific expression used to prevent alerts. Use this API to review and
audit your current exclusion set. It's the primary method for programmatically listing all active tuning rules to verify their scope,
or to identify a specific exclusion's ID for a future update or deletion. This API provides a centralized, programmatic view of all
detection tuning rules, enabling automated auditing and management of your Trellix EDR policy.
Authentication
Authentication type: Bearer Token, API Key.
You can create a token using client credentials obtained through the developer portal. The API Key (x-api-key) is provided in
90 Trellix Endpoint Detection and Response Product Guide

1| Trellix EDR APIs
your onboarding email or on the API Access Management page.
Path (or URL)
GET https://{Trellix EDR_gateway_URL}/edr/v2/remediation/exclusions
Request
Request headers
Authorization: Bearer <your_bearer_token>
Content-Type: application/vnd.api+json
x-api-key: <your_api_key>
Accept-Encoding: gzip
• Authorization: This header is used to authenticate your request. You need to replace <your_bearer_token> with the actual
token you generate.
• Content-Type: This header tells the server that the request body format is json:api. Even though this specific call has no
request body, the API requires this header.
• x-api-key: This is a custom header required by the Trellix API for authentication. You'll need to replace <your_api_key> with
the key from your onboarding email or the API Access Management page.
• Accept-Encoding: This is an optional header you can include to tell the server you can accept a compressed response (using
gzip), which can make the data transfer faster.
Request parameters
Parameters Data type/Values Description
page[offset] integer Number of records to skip (starts from 0th record).
page[limit] integer Number of records to fetch on a page.
Accept- string Enable GZIP Compression to return compressed data.
Encoding Example: gzip, deflate, br
Trellix Endpoint Detection and Response Product Guide 91

1| Trellix EDR APIs
Response
Response example
{
"jsonapi": {
"version": "1.0"
},
"meta": {
"totalResourceCount": 1
},
"data": [
{
"type": "threatExclusion",
"id": "666ccb51-a80c-4536-80c1-f658a1b89b73",
"attributes": {
"name": "RuntimeBroker.exe",
"description": "CMDLINE for Datagenerator executable",
"expression": [
"[process:command_line='C:\\Windows\\System32\\gsdhfagsf.exe -Embedding']"
],
"created": "2023-08-29T09:23:08.025273",
"updated": "2023-08-29T09:23:08.025273"
}
}
],
"links": {
"self": "/edr/v2/remediation/exclusions?page[offset]=0&page[limit]=20",
"first": "/edr/v2/remediation/exclusions?page[offset]=0&page[limit]=20",
"prev": "/edr/v2/remediation/exclusions?page[offset]=0&page[limit]=20",
"next": "/edr/v2/remediation/exclusions?page[offset]=0&page[limit]=20",
"last": "/edr/v2/remediation/exclusions?page[offset]=0&page[limit]=20"
}
}
Response codes
Status Response Description
200 OK Your request was processed successfully. The server has returned the
requested data.
400 Bad request The server couldn't understand your request, likely due to a syntax error
or an invalid parameter.
401 Access denied request Your request was rejected because it lacks valid authentication
credentials. Check your API key and token.
92 Trellix Endpoint Detection and Response Product Guide

1| Trellix EDR APIs
Status Response Description
403 Forbidden You are not authorized to access this resource. While your credentials
may be valid, you don't have the necessary permissions.
404 Not Found The specific resource or endpoint you requested does not exist.
415 Unsupported Media Type The server rejected your request because the data format (Content-
Type) is not supported.
429 Too Many Requests You've exceeded the rate limit by sending too many requests in a short
period. The Retry-After header in the response will tell you how long to
wait before trying again.
500 Internal Server Error Something went wrong on the server's end. This is not an issue with
your request.
GET - Exclusions by ID
Overview
This endpoint retrieves the full details for a single detection exclusion using its unique ID. Target a specific rule by its
exclusionId in the path. The response is a single object containing all settings for that exclusion, including its name, description,
and expression. Use this API to verify the exact criteria of a specific exclusion. It's the standard method for fetching the current
state of a rule before you update it, or to confirm that a new exclusion was created with the correct parameters. This API
provides on-demand access to individual exclusion rules, enabling precise and automated validation within your policy
management workflows.
Authentication
Authentication type: Bearer Token, API Key.
You can create a token using client credentials obtained through the developer portal. The API Key (x-api-key) is provided in
your onboarding email or on the API Access Management page.
Trellix Endpoint Detection and Response Product Guide 93

1| Trellix EDR APIs
Path (or URL)
GET https://{Trellix EDR_gateway_URL}/edr/v2/remediation/exclusions/{exclusionId}
Example — {exclusionId}: 8e63d190-51e5-4f10-8367-e84f58795e4d
Request
Request headers
Authorization: Bearer <your_bearer_token>
Content-Type: application/vnd.api+json
x-api-key: <your_api_key>
Accept-Encoding: gzip
• Authorization: This header is used to authenticate your request. You need to replace <your_bearer_token> with the actual
token you generate.
• Content-Type: This header tells the server that the request body format is json:api. Even though this specific call has no
request body, the API requires this header.
• x-api-key: This is a custom header required by the Trellix API for authentication. You'll need to replace <your_api_key> with
the key from your onboarding email or the API Access Management page.
• Accept-Encoding: This is an optional header you can include to tell the server you can accept a compressed response (using
gzip), which can make the data transfer faster.
Request parameters
Parameters Data type/Values Description
exclusionId string Unique identifier for threat exclusion.
Accept- string Enable GZIP Compression to return compressed data.
Encoding Example: gzip, deflate, br
94 Trellix Endpoint Detection and Response Product Guide

1| Trellix EDR APIs
Response
Response example
{
"jsonapi": {
"version": "1.0"
},
"meta": {
"totalResourceCount": 1
},
"data": {
"type": "threatExclusion",
"id": "666ccb51-a80c-4536-80c1-f658a1b89b73",
"attributes": {
"name": "RuntimeBroker.exe",
"description": "CMDLINE for Datagenerator executable",
"expression": [
"[process:command_line='C:\\Windows\\System32\\gsdhfagsf.exe -Embedding']"
],
"created": "2023-08-29T09:23:08.025273",
"updated": "2023-08-29T09:23:08.025273"
}
}
}
Response codes
Status Response Description
200 OK Your request was processed successfully. The server has returned the
requested data.
400 Bad request The server couldn't understand your request, likely due to a syntax error
or an invalid parameter.
401 Access denied request Your request was rejected because it lacks valid authentication
credentials. Check your API key and token.
403 Forbidden You are not authorized to access this resource. While your credentials
may be valid, you don't have the necessary permissions.
404 Not Found The specific resource or endpoint you requested does not exist.
Trellix Endpoint Detection and Response Product Guide 95

1| Trellix EDR APIs
Status Response Description
415 Unsupported Media Type The server rejected your request because the data format (Content-
Type) is not supported.
429 Too Many Requests You've exceeded the rate limit by sending too many requests in a short
period. The Retry-After header in the response will tell you how long to
wait before trying again.
500 Internal Server Error Something went wrong on the server's end. This is not an issue with
your request.
PATCH - Exclusions by ID
Overview
This endpoint updates an existing detection exclusion. Target an exclusion using its exclusionId in the path and provide the new
or modified attributes in the request body. The API applies the changes and returns a job ID confirming the update. Use this API
to modify an exclusion as your environment changes. This is necessary when a trusted application is updated (requiring a new
hash) or its file path changes. This API ensures your detection tuning remains accurate over time, preventing previously-created
exclusions from becoming outdated and ineffective.
Authentication
Authentication type: Bearer Token, API Key.
You can create a token using client credentials obtained through the developer portal. The API Key (x-api-key) is provided in
your onboarding email or on the API Access Management page.
Path (or URL)
PATCH https://{Trellix EDR_gateway_URL}/edr/v2/remediation/exclusions/{exclusionId}
Example — {exclusionId}: 8e63d190-51e5-4f10-8367-e84f58795e4d
96 Trellix Endpoint Detection and Response Product Guide

1| Trellix EDR APIs
Request
Request headers
Authorization: Bearer <your_bearer_token>
Content-Type: application/vnd.api+json
x-api-key: <your_api_key>
• Authorization: This header is used to authenticate your request. You need to replace <your_bearer_token> with the actual
token you generate.
• Content-Type: This header tells the server that the request body format is json:api. Even though this specific call has no
request body, the API requires this header.
• x-api-key: This is a custom header required by the Trellix API for authentication. You'll need to replace <your_api_key> with
the key from your onboarding email or the API Access Management page.
Request body
{
"data": {
"id": "79cd8e83-4af1-4887-8d69-3d6282e4247f",
"type": "threatExclusion",
"attributes": {
"exclusionName": "Datagenerator.exe",
"description": "SHA256 Hash for Datagenerator executable",
"exclusionArguments": [
{
"name": "SHA-256",
"value": "51c8e205f3cb6fece20c38e75f5602f9b602c76cb0cd1c008afde60d8aebbba0"
},
{
"name": "file_path",
"value": "C:\\testing-linux\\spichap-01.exe"
},
{
"name": "command_line",
"value": "C:\\WINDOWS\\SYSTEM32\\WINDOWSPOWERSHELL\\V1.0\\POWERSHELL.EXE"
}
]
}
}
}
Trellix Endpoint Detection and Response Product Guide 97

1| Trellix EDR APIs
Request parameters
Parameters Data type/Values Description
exclusionId string Unique identifier for threat exclusion
Response
Response example
{
"data": {
"type": "queue-jobs",
"id": "te-5432",
"attributes": {
"status": "completed",
"exclusionId": "8e63d190-51e5-4f10-8367-e84f58795e4d"
},
"links": {
"self": "/edr/v2/remediation/queue-jobs/te-5432"
}
}
}
Response codes
Status Response Description
200 OK Your request was processed successfully. The server has returned the
requested data.
400 Bad request The server couldn't understand your request, likely due to a syntax error
or an invalid parameter.
401 Access denied request Your request was rejected because it lacks valid authentication
credentials. Check your API key and token.
98 Trellix Endpoint Detection and Response Product Guide

1| Trellix EDR APIs
Status Response Description
403 Forbidden You are not authorized to access this resource. While your credentials
may be valid, you don't have the necessary permissions.
404 Not Found The specific resource or endpoint you requested does not exist.
415 Unsupported Media Type The server rejected your request because the data format (Content-
Type) is not supported.
429 Too Many Requests You've exceeded the rate limit by sending too many requests in a short
period. The Retry-After header in the response will tell you how long to
wait before trying again.
500 Internal Server Error Something went wrong on the server's end. This is not an issue with
your request.
DELETE - Exclusions by ID
Overview
This endpoint permanently deletes a detection exclusion. Target the rule by its exclusionId in the path. The action is irreversible
and a successful response returns 204 No Content. Use this API to remove an obsolete exclusion, such as when an application is
decommissioned or a false positive has been resolved by a software update. This API helps maintain the integrity of your security
policy by ensuring that detection capabilities are fully enabled and not suppressed by outdated rules.
Authentication
Authentication type: Bearer Token, API Key.
You can create a token using client credentials obtained through the developer portal. The API Key (x-api-key) is provided in
your onboarding email or on the API Access Management page.
Path (or URL)
DELETE https://{Trellix EDR_gateway_URL}/edr/v2/remediation/exclusions/{exclusionId}
Trellix Endpoint Detection and Response Product Guide 99

1| Trellix EDR APIs
Example — {exclusionId}: 8e63d190-51e5-4f10-8367-e84f58795e4d
Request
Request headers
Authorization: Bearer <your_bearer_token>
Content-Type: application/vnd.api+json
x-api-key: <your_api_key>
• Authorization: This header is used to authenticate your request. You need to replace <your_bearer_token> with the actual
token you generate.
• Content-Type: This header tells the server that the request body format is json:api. Even though this specific call has no
request body, the API requires this header.
• x-api-key: This is a custom header required by the Trellix API for authentication. You'll need to replace <your_api_key> with
the key from your onboarding email or the API Access Management page.
Request parameters
Parameters Data type/Values Description
exclusionId string Unique identifier for threat exclusion
Response
Response codes
Status Response Description
204 No Content The specified exclusion was permanently deleted.
400 Bad request The server couldn't understand your request, likely due to a syntax error
100 Trellix Endpoint Detection and Response Product Guide

1| Trellix EDR APIs
Status Response Description
or an invalid parameter.
401 Access denied request Your request was rejected because it lacks valid authentication
credentials. Check your API key and token.
403 Forbidden You are not authorized to access this resource. While your credentials
may be valid, you don't have the necessary permissions.
404 Not Found The specific resource or endpoint you requested does not exist.
415 Unsupported Media Type The server rejected your request because the data format (Content-
Type) is not supported.
429 Too Many Requests You've exceeded the rate limit by sending too many requests in a short
period. The Retry-After header in the response will tell you how long to
wait before trying again.
500 Internal Server Error Something went wrong on the server's end. This is not an issue with
your request.
GET - Remediation status
Overview
This endpoint retrieves the current status of any asynchronous remediation job. By providing the remediationId returned when
you initiated an action, you can poll this endpoint to track its progress. The response includes the job's overall status and a count
of successful and failed endpoint responses. Use this API after initiating any remediation action that returns a job ID. It's the
required method for programmatically determining when a long-running task is complete and whether it succeeded or failed on
the target endpoints. This API provides a non-blocking mechanism to track long-running jobs, allowing your applications to
manage asynchronous response actions efficiently.
Authentication
Authentication type: Bearer Token, API Key.
Trellix Endpoint Detection and Response Product Guide 101

1| Trellix EDR APIs
You can create a token using client credentials obtained through the developer portal. The API Key (x-api-key) is provided in
your onboarding email or on the API Access Management page.
Path (or URL)
GET https://{Trellix EDR_gateway_URL}/edr/v2/remediation/queue-jobs/{remediationId}
Request
Request headers
Authorization: Bearer <your_bearer_token>
Content-Type: application/vnd.api+json
x-api-key: <your_api_key>
Accept-Encoding: gzip
• Authorization: This header is used to authenticate your request. You need to replace <your_bearer_token> with the actual
token you generate.
• Content-Type: This header tells the server that the request body format is json:api. Even though this specific call has no
request body, the API requires this header.
• x-api-key: This is a custom header required by the Trellix API for authentication. You'll need to replace <your_api_key> with
the key from your onboarding email or the API Access Management page.
• Accept-Encoding: This is an optional header you can include to tell the server you can accept a compressed response (using
gzip), which can make the data transfer faster.
Request parameters
Parameters Data type/Values Description
remediationId string ID of the particular remediation whose status is needed.
Example:
• hr-5431 — sample host-remediation ID
• sr-5432 — sample search-remediation ID
• tr-5433 — sample threat-remediation ID
102 Trellix Endpoint Detection and Response Product Guide

1| Trellix EDR APIs
Parameters Data type/Values Description
• te-5434 — sample threat-exclusion ID
Response
Response example
{
"data": {
"type": "queue-jobs",
"id": "hr-5432",
"attributes": {
"status": "in-progress",
"successHostResponses": 0,
"errorHostResponses": 1
}
}
}
Response codes
Status Response Description
200 OK Your request was processed successfully. The server has returned the
requested data.
400 Bad request The server couldn't understand your request, likely due to a syntax error
or an invalid parameter.
401 Access denied request Your request was rejected because it lacks valid authentication
credentials. Check your API key and token.
403 Forbidden You are not authorized to access this resource. While your credentials
may be valid, you don't have the necessary permissions.
404 Not Found The specific resource or endpoint you requested does not exist.
Trellix Endpoint Detection and Response Product Guide 103

1| Trellix EDR APIs
Status Response Description
415 Unsupported Media Type The server rejected your request because the data format (Content-
Type) is not supported.
429 Too Many Requests You've exceeded the rate limit by sending too many requests in a short
period. The Retry-After header in the response will tell you how long to
wait before trying again.
500 Internal Server Error Something went wrong on the server's end. This is not an issue with
your request.
GET - Actions
Overview
This endpoint retrieves a paginated audit log of all remediation actions taken within the Trellix EDR platform. The response is an
array of action objects, each detailing a past event, including the action taken, its status, the user who initiated it, and relevant
timestamps. Use this API to review or audit historical response activities. It's the primary method for programmatically tracking
what actions were taken, by whom, and when. This is essential for compliance reporting, internal reviews of analyst actions, or
for understanding the history of a response to a long-running incident.
Authentication
Authentication type: Bearer Token, API Key.
You can create a token using client credentials obtained through the developer portal. The API Key (x-api-key) is provided in
your onboarding email or on the API Access Management page.
Path (or URL)
GET https://{Trellix EDR_gateway_URL}/edr/v2/remediation/actions
104 Trellix Endpoint Detection and Response Product Guide

1| Trellix EDR APIs
Request
Request headers
Authorization: Bearer <your_bearer_token>
Content-Type: application/vnd.api+json
x-api-key: <your_api_key>
Accept-Encoding: gzip
• Authorization: This header is used to authenticate your request. You need to replace <your_bearer_token> with the actual
token you generate.
• Content-Type: This header tells the server that the request body format is json:api. Even though this specific call has no
request body, the API requires this header.
• x-api-key: This is a custom header required by the Trellix API for authentication. You'll need to replace <your_api_key> with
the key from your onboarding email or the API Access Management page.
• Accept-Encoding: This is an optional header you can include to tell the server you can accept a compressed response (using
gzip), which can make the data transfer faster.
Request parameters
Parameters Data type/Values Description
page[offset] integer Number of records to skip (starts from 0th record).
page[limit] integer Number of records to fetch on a page.
sort string To sort the records based on a column.
By default, the column data is in the descending order of "creationDate"
Accept- string Enable GZIP Compression to return compressed data.
Encoding Example: gzip, deflate, br
Trellix Endpoint Detection and Response Product Guide 105

1| Trellix EDR APIs
Response
Response example
{
"jsonapi": {
"version": "1.0"
},
"meta": {
"totalResourceCount": 1
},
"data": [
{
"type": "actions",
"id": "4106",
"attributes": {
"action": "DismissThreat",
"threatId": "181287",
"threatName": "Threat-Sample2.exe",
"status": "COMPLETED",
"errorCode": "",
"creationDate": "2023-08-03T09:47:48.742+0000",
"userId": "mvapi2-test-tenant-1@yopmail.com",
"hostsAffected": "",
"investigationName": "",
"errorDescription": "",
"investigationId": "9340e9a0-2717-11ee-80d4-000000000000"
}
}
],
"links": {
"self": "/edr/v2/remediation/actions?page[offset]=0&page[limit]=1",
"first": "/edr/v2/remediation/actions?page[offset]=0&page[limit]=1",
"prev": "/edr/v2/remediation/actions?page[offset]=0&page[limit]=1",
"next": "/edr/v2/remediation/actions?page[offset]=0&page[limit]=1",
"last": "/edr/v2/remediation/actions?page[offset]=0&page[limit]=1"
}
}
Response codes
Status Response Description
200 OK Your request was processed successfully. The server has returned the
requested data.
400 Bad request The server couldn't understand your request, likely due to a syntax error
or an invalid parameter.
106 Trellix Endpoint Detection and Response Product Guide

1| Trellix EDR APIs
Status Response Description
401 Access denied request Your request was rejected because it lacks valid authentication
credentials. Check your API key and token.
403 Forbidden You are not authorized to access this resource. While your credentials
may be valid, you don't have the necessary permissions.
404 Not Found The specific resource or endpoint you requested does not exist.
415 Unsupported Media Type The server rejected your request because the data format (Content-
Type) is not supported.
429 Too Many Requests You've exceeded the rate limit by sending too many requests in a short
period. The Retry-After header in the response will tell you how long to
wait before trying again.
500 Internal Server Error Something went wrong on the server's end. This is not an issue with
your request.
GET - host-info
Overview
This endpoint retrieves detailed inventory information for managed endpoints. You can query for specific endpoints using their
agent GUID (aGuid) or search for a set of endpoints using a full or partial hostName. The response is a paginated array of endpoint
objects, each containing details like OS version and network interfaces. Use this API to gather context about a specific endpoint
or to map a known hostname to its aGuid. It's a fundamental step in many workflows, used to enrich alerts with endpoint details
or to verify an endpoint's identity before targeting it for a search or remediation action.
Authentication
Authentication type: Bearer Token, API Key.
You can create a token using client credentials obtained through the developer portal. The API Key (x-api-key) is provided in
your onboarding email or on the API Access Management page.
Trellix Endpoint Detection and Response Product Guide 107

1| Trellix EDR APIs
Path (or URL)
GET https://{Trellix EDR_gateway_URL}/edr/v2/remediation/host-info
Request
Request headers
Authorization: Bearer <your_bearer_token>
Content-Type: application/vnd.api+json
x-api-key: <your_api_key>
Accept-Encoding: gzip
• Authorization: This header is used to authenticate your request. You need to replace <your_bearer_token> with the actual
token you generate.
• Content-Type: This header tells the server that the request body format is json:api. Even though this specific call has no
request body, the API requires this header.
• x-api-key: This is a custom header required by the Trellix API for authentication. You'll need to replace <your_api_key> with
the key from your onboarding email or the API Access Management page.
• Accept-Encoding: This is an optional header you can include to tell the server you can accept a compressed response (using
gzip), which can make the data transfer faster.
Request parameters
Parameters Data type/Values Description
aGuid string Agent guid of the endpoint
hostName string Accepts a full or partial hostname. The API performs a prefix search and
returns all host records where the name begins with the provided input
string.
page[offset] integer Number of records to skip (starts from 0th record).
page[limit] integer Number of records to fetch on a page.
108 Trellix Endpoint Detection and Response Product Guide

1| Trellix EDR APIs
Parameters Data type/Values Description
Accept- string Enable GZIP Compression to return compressed data.
Encoding Example: gzip, deflate, br
Response
Response example
{
"jsonapi": {
"version": "1.0"
},
"meta": {
"totalResourceCount": 1
},
"data": [
{
"type": "hostInfo",
"attributes": {
"aGuid": "5825467E-86FA-11EF-1610-005056A431D9",
"hostname": "3M4W10RS5X64",
"os": {
"major": 10,
"minor": 0,
"build": 17763,
"sp": "",
"desc": "Windows 10"
},
"lastBootTime": "2024-10-10T11:51:04Z",
"netInterfaces": [
{
"name": "Ethernet0",
"macAddress": "00:50:56:a4:31:d9",
"ip": "10.26.22.121",
"type": 6
},
{
"name": "Primary",
"ip": ""
}
],
"traceExtendedVisibility": 0,
"hostOs": "windows"
}
}
],
"links": {
"self": "/edr/v2/remediation/host-info?page[offset]=0&page[limit]=20",
"first": "/edr/v2/remediation/host-info?page[offset]=0&page[limit]=20",
"prev": "/edr/v2/remediation/host-info?page[offset]=0&page[limit]=20",
"next": "/edr/v2/remediation/host-info?page[offset]=0&page[limit]=20",
"last": "/edr/v2/remediation/host-info?page[offset]=0&page[limit]=20"
Trellix Endpoint Detection and Response Product Guide 109

1| Trellix EDR APIs
}
}
Response codes
Status Response Description
200 OK Your request was processed successfully. The server has returned the
requested data.
400 Bad request The server couldn't understand your request, likely due to a syntax error
or an invalid parameter.
401 Access denied request Your request was rejected because it lacks valid authentication
credentials. Check your API key and token.
403 Forbidden You are not authorized to access this resource. While your credentials
may be valid, you don't have the necessary permissions.
404 Not Found The specific resource or endpoint you requested does not exist.
415 Unsupported Media Type The server rejected your request because the data format (Content-
Type) is not supported.
429 Too Many Requests You've exceeded the rate limit by sending too many requests in a short
period. The Retry-After header in the response will tell you how long to
wait before trying again.
500 Internal Server Error Something went wrong on the server's end. This is not an issue with
your request.
API sample for threats and alerts
The threats and alerts APIs let you retrieve detected threats, the endpoints they affect, the individual detections that make up
each threat, and the raw security alerts behind them. Use these endpoints to feed threat data into incident response workflows,
SIEM correlation, or long-term archival.
Endpoints
110 Trellix Endpoint Detection and Response Product Guide

1| Trellix EDR APIs
Endpoint Description
GET - Threats Use this to retrieve a filtered, paginated list of
threats.
GET - Threats by ID Use this to retrieve full details for a single threat.
GET - Affected hosts by threat id Use this to list every endpoint where a threat was
detected.
GET - Detections by threat id Use this to retrieve the individual detection events
within a threat.
Get Alerts (v2) Use this to retrieve raw security alerts.
Get Alerts (v3) Use this to retrieve raw security alerts with enriched
host data.
Common reference
All endpoints return a severity value on the s0–s5 scale. For details, see Security levels.
GET - Threats
Overview
This endpoint retrieves a paginated list of threats with powerful filtering and sorting capabilities. Use query parameters to
narrow results by time, severity, and other criteria. The response includes a list of threat objects, and you can request related
data like detections to be included in the same call. Use this API as the primary entry point for threat data in your security
workflows. It's essential for periodically polling for new, high-priority threats to trigger incident response, or for feeding threat
alerts into a SIEM for correlation and long-term storage.
Authentication
Authentication type: Bearer Token, API Key.
Trellix Endpoint Detection and Response Product Guide 111

1| Trellix EDR APIs
You can create a token using client credentials obtained through the developer portal. The API Key (x-api-key) is provided in
your onboarding email or on the API Access Management page.
Path (or URL)
<HTTPS Method>
GET https://{Trellix EDR_gateway_URL}/edr/v2/threats
Request
Request headers
Authorization: Bearer <your_bearer_token>
Content-Type: application/vnd.api+json
x-api-key: <your_api_key>
Accept-Encoding: gzip
• Authorization: This header is used to authenticate your request. You need to replace <your_bearer_token> with the actual
token you generate.
• Content-Type: This header tells the server that the request body format is json:api. Even though this specific call has no
request body, the API requires this header.
• x-api-key: This is a custom header required by the Trellix API for authentication. You'll need to replace <your_api_key> with
the key from your onboarding email or the API Access Management page.
• Accept-Encoding: This is an optional header you can include to tell the server you can accept a compressed response (using
gzip), which can make the data transfer faster.
Request parameters
Parameters Data type/Values Description
sort string Specifies the order (ascending/descending) for the returned results.
from integer Sets the start of the time frame to search, in epoch milliseconds.
to integer Sets the end of the time frame to search, in epoch milliseconds.
112 Trellix Endpoint Detection and Response Product Guide

1| Trellix EDR APIs
| Parameters  | Data type/Values  |     | Description  |     |
| ----------- | ----------------- | --- | ------------ | --- |
filter  string  Narrows down results based on criteria like severity, name, or rank.
page[offset]  integer  Skips a specified number of records; used for pagination.
page[limit]  integer  Sets the maximum number of records to return per page.
include  string  Requests additional related data like detections or affectedhosts.
Response
Response parameters
| Parameter       |     | Data Type  |     | Description                |
| --------------- | --- | ---------- | --- | -------------------------- |
| aggregationKey  |     | string     |     | Internal ID / key used to  |
aggregate related threat events.
severity  string (enum: s0–s5)  Severity rating of the threat. For
details, see Security levels.
| rank   |     | integer  |     | Priority rank order of the threat.  |
| ------ | --- | -------- | --- | ----------------------------------- |
| score  |     | integer  |     | Numerical risk or confidence        |
score.
| name  |     | string  |     | Name of the detected threat or  |
| ----- | --- | ------- | --- | ------------------------------- |
malware family.
| type  |     | string (enum)  |     | Classification type such as pe,  |
| ----- | --- | -------------- | --- | -------------------------------- |
non-pe-file, non-pe-cmd, user,
host.
Trellix Endpoint Detection and Response Product Guide 113

1| Trellix EDR APIs
| Parameter  | Data Type      | Description                         |
| ---------- | -------------- | ----------------------------------- |
| status     | string (enum)  | Lifecycle status of threat triage:  |
new, updated, viewed, handled,
expired.
firstDetected  string (date-time)  Timestamp of when the threat
was first seen (UTC, ISO-8601).
lastDetected  string (date-time)  Timestamp of the most recent
occurrence (UTC, ISO-8601).
| edrUiUrl  | string  | Deep link to the threat in the EDR  |
| --------- | ------- | ----------------------------------- |
UI console.
| hashes.sha256  | string  | SHA-256 cryptographic checksum  |
| -------------- | ------- | ------------------------------- |
of the malicious payload.
| hashes.sha1       | string  | SHA-1 checksum                 |
| ----------------- | ------- | ------------------------------ |
| hashes.md5        | string  | MD5 checksum                   |
| interpreter.name  | string  | Script interpreter name, (for  |
example, PowerShell, Python) —
omitted if null.
| interpreter.hashes  | object  | Hashes (sha256, sha1, md5) of  |
| ------------------- | ------- | ------------------------------ |
the interpreter binary.
relationships.affectedhosts  object  Embedded affected hosts (when
include=affectedhosts).
| relationships.detections  | object  | Embedded detections (when  |
| ------------------------- | ------- | -------------------------- |
include=detections).
Response example
{
| 114 | Trellix Endpoint Detection and Response Product Guide |     |
| --- | ----------------------------------------------------- | --- |

1| Trellix EDR APIs
"jsonapi": {
"version": "1.0"
},
"meta": {
"totalResourceCount": 84
},
"data": [
{
"type": "threats",
"id": "182612",
"attributes": {
"aggregationKey": "P_6E2918727CBB836F4D8E3404BDE9AEAF5D4DED5DD1F6916AAD3F3B956E6D8A17",
"severity": "s4",
"rank": 270,
"score": 70,
"name": "POWERSHELL_56039776.EXE",
"type": "pe",
"status": "new",
"firstDetected": "2023-08-27T05:34:29Z",
"lastDetected": "2023-08-27T05:34:29Z",
"edrUiUrl": "https://xconsole.trellix.com/edr/#/monitoring/#/workspace/2160,TOTAL_THREATS,8112",
"hashes": {
"sha256": "6E2918727CBB836F4D8E3404BDE9AEAF5D4DED5DD1F6916AAD3F3B956E6D8A17",
"sha1": "D9FBB3BD6269FE3D5F349A7569964DCD1AA229B5",
"md5": "6FEE39009EA5B1110C5DA6DF2B7BDC43"
}
},
"relationships": {
"affectedhosts": {
"data": [
{
"type": "affected-hosts",
"id": "649889",
"attributes": {
"detectionsCount": 1,
"severity": "s4",
"rank": 270,
"firstDetected": "2023-08-27T05:34:29Z",
"host": {
"os": {},
"netInterfaces": [],
"traceExtendedVisibility": 0,
"hostOs": "",
"aGuid": "6D0A37A8-B5B7-4414-9444-A2B17721642B"
}
}
}
],
"links": {
"self": "/edr/v2/threats/182612/affectedhosts?page[offset]=0&page[limit]=100",
"first": "/edr/v2/threats/182612/affectedhosts?page[offset]=0&page[limit]=100",
"prev": "/edr/v2/threats/182612/affectedhosts?page[offset]=0&page[limit]=100",
"next": "/edr/v2/threats/182612/affectedhosts?page[offset]=0&page[limit]=100",
"last": "/edr/v2/threats/182612/affectedhosts?page[offset]=0&page[limit]=100"
}
},
"detections": {
"data": [
{
"type": "detections",
"id": "652404",
"attributes": {
"traceId": "9a718cc6-d8f6-46da-b3cc-fc4dbbd60151",
"firstDetected": "2023-08-27T05:34:29Z",
Trellix Endpoint Detection and Response Product Guide 115

1| Trellix EDR APIs
"severity": "s4",
"rank": 270,
"tags": [
"@ATA.PrivilegeEscalation",
"@ATA.Persistence",
"@ATE.T1546.012",
"@MSI._reg_ep0130_imageexecution_high",
"@ATA.DefenseEvasion",
"@ATE.T1112"
],
"host": {
"os": {},
"netInterfaces": [],
"traceExtendedVisibility": 0,
"hostOs": "",
"aGuid": "6D0A37A8-B5B7-4414-9444-A2B17721642B"
},
"sha256": "6E2918727CBB836F4D8E3404BDE9AEAF5D4DED5DD1F6916AAD3F3B956E6D8A17"
}
}
],
"links": {
"self": "/edr/v2/threats/182612/detections?page[offset]=0&page[limit]=100",
"first": "/edr/v2/threats/182612/detections?page[offset]=0&page[limit]=100",
"prev": "/edr/v2/threats/182612/detections?page[offset]=0&page[limit]=100",
"next": "/edr/v2/threats/182612/detections?page[offset]=0&page[limit]=100",
"last": "/edr/v2/threats/182612/detections?page[offset]=0&page[limit]=100"
}
}
}
}
],
"links": {
"self": "/edr/v2/threats?page[offset]=0&page[limit]=1",
"first": "/edr/v2/threats?page[offset]=0&page[limit]=1",
"prev": "/edr/v2/threats?page[offset]=0&page[limit]=1",
"next": "/edr/v2/threats?page[offset]=1&page[limit]=1",
"last": "/edr/v2/threats?page[offset]=83&page[limit]=1"
}
}
Response codes
Status Response Description
200 OK Your request was processed successfully. The server has returned the
requested data.
400 Bad request The server couldn't understand your request, likely due to a syntax error
or an invalid parameter.
401 Access denied request Your request was rejected because it lacks valid authentication
116 Trellix Endpoint Detection and Response Product Guide

1| Trellix EDR APIs
Status Response Description
credentials. Check your API key and token.
403 Forbidden You are not authorized to access this resource. While your credentials
may be valid, you don't have the necessary permissions.
404 Not Found The specific resource or endpoint you requested does not exist.
415 Unsupported Media Type The server rejected your request because the data format (Content-
Type) is not supported.
429 Too Many Requests You've exceeded the rate limit by sending too many requests in a short
period. The Retry-After header in the response will tell you how long to
wait before trying again.
500 Internal Server Error Something went wrong on the server's end. This is not an issue with
your request.
GET - Threats by ID
Overview
This endpoint retrieves the complete details for a single threat using its unique ID. Target a threat by its threat_id in the path to
get all its attributes and relationships. You can also use the include parameter to fetch related data, like detections and
affectedhosts, in the same call. Use this API as a primary data gathering step in an incident response workflow. After an alert
provides a threat_id, call this endpoint to get the rich context—such as file hashes and affected endpoints—needed for deeper
investigation or to inform a remediation decision.
Authentication
Authentication type: Bearer Token, API Key.
You can create a token using client credentials obtained through the developer portal. The API Key (x-api-key) is provided in
your onboarding email or on the API Access Management page.
Trellix Endpoint Detection and Response Product Guide 117

1| Trellix EDR APIs
Path (or URL)
<HTTPS Method>
GET https://{Trellix EDR_gateway_URL}/edr/v2/threats/{threat_id}GET {Trellix EDR_gateway_URL}/edr/v2/
threats/{threat_id}
Request
Request headers
Authorization: Bearer <your_bearer_token>
Content-Type: application/vnd.api+json
x-api-key: <your_api_key>
Accept-Encoding: gzip
• Authorization: This header is used to authenticate your request. You need to replace <your_bearer_token> with the actual
token you generate.
• Content-Type: This header tells the server that the request body format is json:api. Even though this specific call has no
request body, the API requires this header.
• x-api-key: This is a custom header required by the Trellix API for authentication. You'll need to replace <your_api_key> with
the key from your onboarding email or the API Access Management page.
• Accept-Encoding: This is an optional header you can include to tell the server you can accept a compressed response (using
gzip), which can make the data transfer faster.
Request parameters
Parameters Data type/Values Description
include string This is an optional parameter. Use this to get additional information,
such as detections or affectedhosts.
118 Trellix Endpoint Detection and Response Product Guide

1| Trellix EDR APIs
Response
Response parameters
| Parameter       | Data Type  | Description                |
| --------------- | ---------- | -------------------------- |
| aggregationKey  | string     | Internal ID / key used to  |
aggregate related threat events.
severity  string (enum: s0–s5)  Severity rating of the threat. For
details, see Security levels.
| rank   | integer  | Priority rank order of the threat.  |
| ------ | -------- | ----------------------------------- |
| score  | integer  | Numerical risk or confidence        |
score.
| name  | string  | Name of the detected threat or  |
| ----- | ------- | ------------------------------- |
malware family.
| type  | string (enum)  | Classification type such as pe,  |
| ----- | -------------- | -------------------------------- |
non-pe-file, non-pe-cmd, user,
host.
| status  | string (enum)  | Lifecycle status of threat triage:  |
| ------- | -------------- | ----------------------------------- |
new, updated, viewed, handled,
expired.
firstDetected  string (date-time)  Timestamp of when the threat
was first seen (UTC, ISO-8601).
lastDetected  string (date-time)  Timestamp of the most recent
occurrence (UTC, ISO-8601).
| edrUiUrl  | string  | Deep link to the threat in the EDR  |
| --------- | ------- | ----------------------------------- |
UI console.
Trellix Endpoint Detection and Response Product Guide 119

1| Trellix EDR APIs
| Parameter      | Data Type  | Description                     |
| -------------- | ---------- | ------------------------------- |
| hashes.sha256  | string     | SHA-256 cryptographic checksum  |
of the malicious payload.
| hashes.sha1       | string  | SHA-1 checksum                 |
| ----------------- | ------- | ------------------------------ |
| hashes.md5        | string  | MD5 checksum                   |
| interpreter.name  | string  | Script interpreter name, (for  |
example, PowerShell, Python) —
omitted if null.
| interpreter.hashes  | object  | Hashes (sha256, sha1, md5) of  |
| ------------------- | ------- | ------------------------------ |
the interpreter binary.
relationships.affectedhosts  object  Embedded affected hosts (when
include=affectedhosts).
| relationships.detections  | object  | Embedded detections (when  |
| ------------------------- | ------- | -------------------------- |
include=detections).
| threat_id  | string  | A unique identifier to a specific,  |
| ---------- | ------- | ----------------------------------- |
aggregated threat incident. It
serves as the primary record key.
This key links a single malicious
entity, such as the
POWERSHELL_56039776.EXE file,
to its associated host detections,
execution traces, and metadata.
Response example
{
  "jsonapi": {
    "version": "1.0"
  },
  "meta": {
    "totalResourceCount": 1
  },
  "data": {
| 120 | Trellix Endpoint Detection and Response Product Guide |     |
| --- | ----------------------------------------------------- | --- |

1| Trellix EDR APIs
"type": "threats",
"id": "182612",
"attributes": {
"aggregationKey": "P_6E2918727CBB836F4D8E3404BDE9AEAF5D4DED5DD1F6916AAD3F3B956E6D8A17",
"severity": "s4",
"rank": 270,
"score": 70,
"name": "POWERSHELL_56039776.EXE",
"type": "pe",
"status": "new",
"firstDetected": "2023-08-27T05:34:29Z",
"lastDetected": "2023-08-27T05:34:29Z",
"edrUiUrl": "https://xconsole.trellix.com/edr/#/monitoring/#/workspace/2160,TOTAL_THREATS,8112",
"hashes": {
"sha256": "6E2918727CBB836F4D8E3404BDE9AEAF5D4DED5DD1F6916AAD3F3B956E6D8A17",
"sha1": "D9FBB3BD6269FE3D5F349A7569964DCD1AA229B5",
"md5": "6FEE39009EA5B1110C5DA6DF2B7BDC43"
}
},
"relationships": {
"affectedhosts": {
"data": [
{
"type": "affected-hosts",
"id": "649889",
"attributes": {
"detectionsCount": 1,
"severity": "s4",
"rank": 270,
"firstDetected": "2023-08-27T05:34:29Z",
"host": {
"os": {},
"netInterfaces": [],
"traceExtendedVisibility": 0,
"hostOs": "",
"aGuid": "6D0A37A8-B5B7-4414-9444-A2B17721642B"
}
}
}
],
"links": {
"self": "/edr/v2/threats/182612/affectedhosts?page[offset]=0&page[limit]=100",
"first": "/edr/v2/threats/182612/affectedhosts?page[offset]=0&page[limit]=100",
"prev": "/edr/v2/threats/182612/affectedhosts?page[offset]=0&page[limit]=100",
"next": "/edr/v2/threats/182612/affectedhosts?page[offset]=0&page[limit]=100",
"last": "/edr/v2/threats/182612/affectedhosts?page[offset]=0&page[limit]=100"
}
},
"detections": {
"data": [
{
"type": "detections",
"id": "652404",
"attributes": {
"traceId": "9a718cc6-d8f6-46da-b3cc-fc4dbbd60151",
"firstDetected": "2023-08-27T05:34:29Z",
"severity": "s4",
"rank": 270,
"tags": [
"@ATA.DefenseEvasion",
"@ATA.PrivilegeEscalation",
"@MSI._reg_ep0130_imageexecution_high",
"@ATE.T1546.012",
"@ATE.T1112",
Trellix Endpoint Detection and Response Product Guide 121

1| Trellix EDR APIs
"@ATA.Persistence"
],
"host": {
"os": {},
"netInterfaces": [],
"traceExtendedVisibility": 0,
"hostOs": "",
"aGuid": "6D0A37A8-B5B7-4414-9444-A2B17721642B"
},
"sha256": "6E2918727CBB836F4D8E3404BDE9AEAF5D4DED5DD1F6916AAD3F3B956E6D8A17"
}
}
],
"links": {
"self": "/edr/v2/threats/182612/detections?page[offset]=0&page[limit]=100",
"first": "/edr/v2/threats/182612/detections?page[offset]=0&page[limit]=100",
"prev": "/edr/v2/threats/182612/detections?page[offset]=0&page[limit]=100",
"next": "/edr/v2/threats/182612/detections?page[offset]=0&page[limit]=100",
"last": "/edr/v2/threats/182612/detections?page[offset]=0&page[limit]=100"
}
}
}
}
}
Response codes
Status Response Description
200 OK Your request was processed successfully. The server has returned the
requested data.
400 Bad request The server couldn't understand your request, likely due to a syntax error
or an invalid parameter.
401 Access denied request Your request was rejected because it lacks valid authentication
credentials. Check your API key and token.
403 Forbidden You are not authorized to access this resource. While your credentials
may be valid, you don't have the necessary permissions.
404 Not Found The specific resource or endpoint you requested does not exist.
415 Unsupported Media Type The server rejected your request because the data format (Content-
Type) is not supported.
122 Trellix Endpoint Detection and Response Product Guide

1| Trellix EDR APIs
Status Response Description
429 Too Many Requests You've exceeded the rate limit by sending too many requests in a short
period. The Retry-After header in the response will tell you how long to
wait before trying again.
500 Internal Server Error Something went wrong on the server's end. This is not an issue with
your request.
GET - Affected hosts by threat id
Overview
This endpoint retrieves a paginated list of all endpoints where a specific threat has been detected. Target a threat by its
threat_id in the path. The response contains an array of endpoint objects, which can be sorted and filtered by time. Use this API
to determine the scope of an incident. After a threat is identified, call this endpoint to get the full list of affected endpoints. This
list is the basis for scoping your investigation and for creating a target list for remediation actions.
Authentication
Authentication type: Bearer Token, API Key.
You can create a token using client credentials obtained through the developer portal. The API Key (x-api-key) is provided in
your onboarding email or on the API Access Management page.
Path (or URL)
<HTTPS Method>
GET https://{Trellix EDR_gateway_URL}/edr/v2/threats/{threat_id}/affectedhosts
Request
Request headers
Authorization: Bearer <your_bearer_token>
Trellix Endpoint Detection and Response Product Guide 123

1| Trellix EDR APIs
Content-Type: application/vnd.api+json
x-api-key: <your_api_key>
Accept-Encoding: gzip
• Authorization: This header is used to authenticate your request. You need to replace <your_bearer_token> with the actual
token you generate.
• Content-Type: This header tells the server that the request body format is json:api. Even though this specific call has no
request body, the API requires this header.
• x-api-key: This is a custom header required by the Trellix API for authentication. You'll need to replace <your_api_key> with
the key from your onboarding email or the API Access Management page.
• Accept-Encoding: This is an optional header you can include to tell the server you can accept a compressed response (using
gzip), which can make the data transfer faster.
Request parameters
Parameters Data type/Values Description
sort string Specifies the order (ascending/descending) for the returned results.
from integer Sets the start of the time frame to search, in epoch milliseconds.
to integer Sets the end of the time frame to search, in epoch milliseconds.
page[offset] integer Skips a specified number of records; used for pagination.
page[limit] integer Sets the maximum number of records to return per page.
124 Trellix Endpoint Detection and Response Product Guide

1| Trellix EDR APIs
Response
Response parameters
| Parametrs        | Data Type  | Description             |
| ---------------- | ---------- | ----------------------- |
| detectionsCount  | integer    | Total number of threat  |
detections flagged on this host.
severity  string (enum: s0–s5)  Highest aggregated severity level
currently affecting the host. For
details, see Security levels.
| rank  | integer  | Priority ranking of this host  |
| ----- | -------- | ------------------------------ |
relative to other affected entities.
firstDetected  string (date-time)  Timestamp of when the first
malicious activity was detected
on this host.
| host.aGuid  | string  | The Agent GUID uniquely  |
| ----------- | ------- | ------------------------ |
identifies the device.
| host.hostname  | string  | Host name of the device.  |
| -------------- | ------- | ------------------------- |
host.epoTags  array[string]  List of ePO tags associated with
the host.
host.os.desc / major / minor /  string / integer  OS description, major/minor
| build / sp  |     | version, build number, service  |
| ----------- | --- | ------------------------------- |
pack.
host.netInterfaces  array[object]  Network interfaces such as
name, macAddress, ip, type.
host.lastBootTime  string (date-time)  Last boot time of the host.
Trellix Endpoint Detection and Response Product Guide 125

1| Trellix EDR APIs
Parametrs Data Type Description
host.traceExtendedVisibility integer Bitmask — each set bit indicates
a trace rule enabled for extended
visibility.
host.hostOs string Operating system string
description.
Response example
{
"jsonapi": {
"version": "1.0"
},
"meta": {
"totalResourceCount": 1
},
"data": [
{
"type": "affected-hosts",
"id": "649889",
"attributes": {
"detectionsCount": 1,
"severity": "s4",
"rank": 270,
"firstDetected": "2023-08-27T05:34:29Z",
"host": {
"os": {},
"netInterfaces": [],
"traceExtendedVisibility": 0,
"hostOs": "",
"aGuid": "6D0A37A8-B5B7-4414-9444-A2B17721642B"
}
}
}
],
"links": {
"self": "/edr/v2/threats/182612/affectedhosts?page[offset]=0&page[limit]=20",
"first": "/edr/v2/threats/182612/affectedhosts?page[offset]=0&page[limit]=20",
"prev": "/edr/v2/threats/182612/affectedhosts?page[offset]=0&page[limit]=20",
"next": "/edr/v2/threats/182612/affectedhosts?page[offset]=0&page[limit]=20",
"last": "/edr/v2/threats/182612/affectedhosts?page[offset]=0&page[limit]=20"
}
}
126 Trellix Endpoint Detection and Response Product Guide

1| Trellix EDR APIs
Response codes
Status Response Description
200 OK Your request was processed successfully. The server has returned the
requested data.
400 Bad request The server couldn't understand your request, likely due to a syntax error
or an invalid parameter.
401 Access denied request Your request was rejected because it lacks valid authentication
credentials. Check your API key and token.
403 Forbidden You are not authorized to access this resource. While your credentials
may be valid, you don't have the necessary permissions.
404 Not Found The specific resource or endpoint you requested does not exist.
415 Unsupported Media Type The server rejected your request because the data format (Content-
Type) is not supported.
429 Too Many Requests You've exceeded the rate limit by sending too many requests in a short
period. The Retry-After header in the response will tell you how long to
wait before trying again.
500 Internal Server Error Something went wrong on the server's end. This is not an issue with
your request.
GET - Detections by threat id
Overview
This endpoint retrieves a paginated list of the individual detection events that constitute a specific threat. Target a threat by its
threat_id in the path. The response is an array of detection objects, each containing granular data like trace IDs and MITRE
ATT&CK tags. Use this API to conduct a deep-dive investigation of a threat. After a high-level threat is identified, call this endpoint
to retrieve the specific, low-level events. This data is essential for understanding the root cause and the specific tactics,
Trellix Endpoint Detection and Response Product Guide 127

1| Trellix EDR APIs
techniques, and procedures used.
Authentication
Authentication type: Bearer Token, API Key.
You can create a token using client credentials obtained through the developer portal. The API Key (x-api-key) is provided in
your onboarding email or on the API Access Management page.
Path (or URL)
<HTTPS Method>
GET https://{Trellix EDR_gateway_URL}/edr/v2/threats/{threat_id}/detections
Request
Request headers
Authorization: Bearer <your_bearer_token>
Content-Type: application/vnd.api+json
x-api-key: <your_api_key>
Accept-Encoding: gzip
• Authorization: This header is used to authenticate your request. You need to replace <your_bearer_token> with the actual
token you generate.
• Content-Type: This header tells the server that the request body format is json:api. Even though this specific call has no
request body, the API requires this header.
• x-api-key: This is a custom header required by the Trellix API for authentication. You'll need to replace <your_api_key> with
the key from your onboarding email or the API Access Management page.
• Accept-Encoding: This is an optional header you can include to tell the server you can accept a compressed response (using
gzip), which can make the data transfer faster.
128 Trellix Endpoint Detection and Response Product Guide

1| Trellix EDR APIs
Request parameters
Parameters Data type/Values Description
sort string Specifies the order (ascending/descending) for the returned results.
from integer Sets the start of the time frame to search, in epoch milliseconds.
to integer Sets the end of the time frame to search, in epoch milliseconds.
filter string Narrows down results based on criteria like severity, name, or rank.
page[offset] integer Skips a specified number of records; used for pagination.
page[limit] integer Sets the maximum number of records to return per page.
Response
Response parameters
Parameter Data Type Description
traceId string Correlation / distributed tracing
ID associated with the execution
path.
sha256 string SHA-256 of the primary file
payload involved in the detection.
firstDetected string (date-time) Timestamp when the malicious
behavior was first observed.
lastDetected string (date-time) Timestamp of the most recent
observation of this behavior.
Trellix Endpoint Detection and Response Product Guide 129

1| Trellix EDR APIs
Parameter Data Type Description
severity string (enum: s0–s5) Severity classification for this
detection. For details, see
Security levels.
rank integer Computed analytics rank /
priority sequence identifier.
tags array[string] Collection of metadata tags /
labels assigned to the detection
event.
host object Endpoint context (same structure
as Affected Host host object
above).
Response example
{
"jsonapi": {
"version": "1.0"
},
"meta": {
"totalResourceCount": 1
},
"data": [
{
"type": "detections",
"id": "652404",
"attributes": {
"traceId": "9a718cc6-d8f6-46da-b3cc-fc4dbbd60151",
"firstDetected": "2023-08-27T05:34:29Z",
"lastDetected": "2023-08-27T05:34:29Z",
"severity": "s4",
"rank": 270,
"tags": [
"@ATA.Persistence",
"@ATE.T1112",
"@ATA.PrivilegeEscalation",
"@ATA.DefenseEvasion",
"@MSI._reg_ep0130_imageexecution_high",
"@ATE.T1546.012"
],
"host": {
"os": {},
"netInterfaces": [],
"traceExtendedVisibility": 0,
"hostOs": "",
130 Trellix Endpoint Detection and Response Product Guide

1| Trellix EDR APIs
"aGuid": "6D0A37A8-B5B7-4414-9444-A2B17721642B"
},
"sha256": "6E2918727CBB836F4D8E3404BDE9AEAF5D4DED5DD1F6916AAD3F3B956E6D8A17"
}
}
],
"links": {
"self": "/edr/v2/threats/182612/detections?page[offset]=0&page[limit]=20",
"first": "/edr/v2/threats/182612/detections?page[offset]=0&page[limit]=20",
"prev": "/edr/v2/threats/182612/detections?page[offset]=0&page[limit]=20",
"next": "/edr/v2/threats/182612/detections?page[offset]=0&page[limit]=20",
"last": "/edr/v2/threats/182612/detections?page[offset]=0&page[limit]=20"
}
}
Response codes
Status Response Description
200 OK Your request was processed successfully. The server has returned the
requested data.
400 Bad request The server couldn't understand your request, likely due to a syntax error
or an invalid parameter.
401 Access denied request Your request was rejected because it lacks valid authentication
credentials. Check your API key and token.
403 Forbidden You are not authorized to access this resource. While your credentials
may be valid, you don't have the necessary permissions.
404 Not Found The specific resource or endpoint you requested does not exist.
415 Unsupported Media Type The server rejected your request because the data format (Content-
Type) is not supported.
429 Too Many Requests You've exceeded the rate limit by sending too many requests in a short
period. The Retry-After header in the response will tell you how long to
wait before trying again.
500 Internal Server Error Something went wrong on the server's end. This is not an issue with
your request.
Trellix Endpoint Detection and Response Product Guide 131

1| Trellix EDR APIs
Get Alerts
Overview
This endpoint retrieves a paginated list of raw security alerts. Use query parameters to filter, sort, and define a time range for
your query. To retrieve all results for a large query, you must follow the next link in the response until it is null. Use this API as
the foundation for data ingestion pipelines. It's the ideal source for forwarding all raw security alerts to a SIEM for correlation, a
data lake for long-term archival, or a custom detection engine that operates on granular event data.
Authentication
Authentication type: Bearer Token, API Key.
You can create a token using client credentials obtained through the developer portal. The API Key (x-api-key) is provided in
your onboarding email or on the API Access Management page.
Path (or URL)
<HTTPS Method>
GET https://{Trellix EDR_gateway_URL}/edr/v2/alerts
Request
Request headers
Authorization: Bearer <your_bearer_token>
Content-Type: application/vnd.api+json
x-api-key: <your_api_key>
Accept-Encoding: gzip
• Authorization: This header is used to authenticate your request. You need to replace <your_bearer_token> with the actual
token you generate.
• Content-Type: This header tells the server that the request body format is json:api. Even though this specific call has no
request body, the API requires this header.
• x-api-key: This is a custom header required by the Trellix API for authentication. You'll need to replace <your_api_key> with
the key from your onboarding email or the API Access Management page.
• Accept-Encoding: This is an optional header you can include to tell the server you can accept a compressed response (using
132 Trellix Endpoint Detection and Response Product Guide

1| Trellix EDR APIs
gzip), which can make the data transfer faster.
Request parameters
| Parameters  | Data type/Values  |     | Description  |     |
| ----------- | ----------------- | --- | ------------ | --- |
sort  string  Specifies the order (ascending/descending) for the returned results.
from  integer  Sets the start of the time frame to search, in epoch milliseconds.
to  integer  Sets the end of the time frame to search, in epoch milliseconds.
filter  string  Narrows down results based on criteria like severity, name, or rank.
page[offset]  integer  Skips a specified number of records; used for pagination.
page[limit]  integer  Sets the maximum number of records to return per page.
Response
Response parameters
| Parameters  |     | Data type  |     | Description                 |
| ----------- | --- | ---------- | --- | --------------------------- |
| Trace_Id    |     | string     |     | Autogenerated GUID for the  |
event.
| Parent_Trace_Id  |     | string  |     | TraceId of the parent process  |
| ---------------- | --- | ------- | --- | ------------------------------ |
event.
| Root_Trace_Id  |     | string  |     | Root trace ID of the entire  |
| -------------- | --- | ------- | --- | ---------------------------- |
process group.
| DetectionDate  |     | string  |     | Time of detection in EDR cloud.  |
| -------------- | --- | ------- | --- | -------------------------------- |
Trellix Endpoint Detection and Response Product Guide 133

1| Trellix EDR APIs
| Parameters  | Data type  | Description                      |
| ----------- | ---------- | -------------------------------- |
| Event_Date  | string     | Earliest timestamp from related  |
traces (endpoint clock, UTC).
| Activity  | string  | Evet type  |
| --------- | ------- | ---------- |
Severity  string (enum: s0–s5)  BANF rule severity. For details,
see Security levels.
| Score           | integer        | BANF rule confidence score.  |
| --------------- | -------------- | ---------------------------- |
| Detection_Tags  | array[string]  | MITRE ATT&CK tactic and      |
technique IDs.
Related_Trace_Id  array[string]  TraceIds of events responsible
for the detection.
| RuleId  | string  | BANF rule ID that triggered the  |
| ------- | ------- | -------------------------------- |
alert.
| Rank     | integer  | TA calculated rank   |
| -------- | -------- | -------------------- |
| Pid      | integer  | Process ID           |
| Version  | string   | Version information  |
Parents_Trace_Id  array[string]  TraceIds of all ancestor processes
(first = parentTraceId).
| ProcessName  | string  | Name of the process that  |
| ------------ | ------- | ------------------------- |
triggered the rule.
| User  | object  | User name and domain: {  |
| ----- | ------- | ------------------------ |
"domain": "...", "name":
"..." }.
| CommandLine  | string                                                | Full command line of the  |
| ------------ | ----------------------------------------------------- | ------------------------- |
| 134          | Trellix Endpoint Detection and Response Product Guide |                           |

1| Trellix EDR APIs
Parameters Data type Description
triggering process.
Hash_Id string Detection ID — identical across
identical detections (same data,
different date/traceId).
Host_OS string Host OS: windows, linux, or mac.
Host_Name string Host name of the device.
MAGUID string Endpoint MA (formerly McAfee
Agent) GUID — uniquely
identifies the device.
Artifact string Event artifact type
Response example
{
"jsonapi": {
"version": "1.0"
},
"meta": {},
"data": [
{
"type": "alerts",
"id": "01b51c67-0904-c5cf-002a-7003d125b2a2.346565425a0b6b2b7174aa555f67a043",
"attributes": {
"Trace_Id": "71d3a718-9095-494c-ada5-7134dbeaa564",
"Parent_Trace_Id": "ffc4c8eb-6cf9-4b59-8416-b14d55d290dd",
"Root_Trace_Id": "ffc4c8eb-6cf9-4b59-8416-b14d55d290dd",
"DetectionDate": "2024-06-19T07:44:55.708+00:00",
"Event_Date": "2024-06-19T07:43:17.567Z",
"Activity": "Threat Detected",
"Severity": "s0",
"Score": 25,
"Detection_Tags": [
"@ATA.Execution",
"@ATA.Persistence",
"@ATA.PrivilegeEscalation",
"@ATE.T1059",
"@ATE.T1547.009",
"@MSI._file_sysscript"
],
"Related_Trace_Id": [
"22ee44a6-3b26-4bb5-811e-c5e399069a64"
Trellix Endpoint Detection and Response Product Guide 135

1| Trellix EDR APIs
],
"RuleId": "_file_sysscript",
"Rank": 25,
"Pid": 6600,
"Version": "undefined",
"Parents_Trace_Id": [
"ffc4c8eb-6cf9-4b59-8416-b14d55d290dd",
"5824f090-791e-47d5-a5ba-3abcb4f9d2b9",
"599463c2-7f27-41c0-a096-21de1018bfa8",
"5e910e15-c8d4-4724-af28-09be2b48abd9"
],
"ProcessName": "SDXHelper.exe",
"User": {
"domain": "CDA",
"name": "cdaauto"
},
"CommandLine": "\"C:\\Program Files\\Microsoft Office\\Root\\Office16\\SDXHelper.exe\" -Embedding",
"Hash_Id": "h7GhOs3Jm6Buj+LuzOOHBg==",
"Host_OS": "windows",
"Host_Name": "302W1022H264",
"MAGUID": "ADB3C24C-232B-11EF-3D71-005056AC48D2",
"Artifact": "Threat"
}
}
],
"links": {
"self": "/edr/v2/alerts?page[offset]=5&page[limit]=1",
"first": "/edr/v2/alerts?page[offset]=0&page[limit]=1",
"prev": "/edr/v2/alerts?page[offset]=4&page[limit]=1",
"next": "/edr/v2/alerts?page[offset]=6&page[limit]=1"
}
}
Response codes
Status Response Description
200 OK Your request was processed successfully. The server has returned the
requested data.
400 Bad request The server couldn't understand your request, likely due to a syntax error
or an invalid parameter.
401 Access denied request Your request was rejected because it lacks valid authentication
credentials. Check your API key and token.
403 Forbidden You are not authorized to access this resource. While your credentials
may be valid, you don't have the necessary permissions.
136 Trellix Endpoint Detection and Response Product Guide

1| Trellix EDR APIs
Status Response Description
404 Not Found The specific resource or endpoint you requested does not exist.
415 Unsupported Media Type The server rejected your request because the data format (Content-
Type) is not supported.
429 Too Many Requests You've exceeded the rate limit by sending too many requests in a short
period. The Retry-After header in the response will tell you how long to
wait before trying again.
500 Internal Server Error Something went wrong on the server's end. This is not an issue with
your request.
Get Alerts
Overview
This endpoint retrieves a paginated list of raw security alerts. Use query parameters to filter, sort, and define a time range for
your query. This API is functionally identical to the edr/v2/alerts API but provides an enriched response, such as HostInfo data.
Authentication
Authentication type: Bearer Token, API Key.
You can create a token using client credentials obtained through the developer portal. The API Key (x-api-key) is provided in
your onboarding email or on the API Access Management page.
Path (or URL)
<HTTPS Method>
GET https://{Trellix EDR_gateway_URL}/edr/v3/alerts
Trellix Endpoint Detection and Response Product Guide 137

1| Trellix EDR APIs
Request
Request headers
Authorization: Bearer <your_bearer_token>
Content-Type: application/vnd.api+json
x-api-key: <your_api_key>
Accept-Encoding: gzip
• Authorization: This header is used to authenticate your request. You need to replace <your_bearer_token> with the actual
token you generate.
• Content-Type: This header tells the server that the request body format is json:api. Even though this specific call has no
request body, the API requires this header.
• x-api-key: This is a custom header required by the Trellix API for authentication. You'll need to replace <your_api_key> with
the key from your onboarding email or the API Access Management page.
• Accept-Encoding: This is an optional header you can include to tell the server you can accept a compressed response (using
gzip), which can make the data transfer faster.
Request parameters
Parameters Data type/Values Description
sort string Specifies the order (ascending/descending) for the returned results.
from integer Sets the start of the time frame to search, in epoch milliseconds.
to integer Sets the end of the time frame to search, in epoch milliseconds.
filter string Narrows down results based on criteria like severity, name, or rank.
page[offset] integer Skips a specified number of records; used for pagination.
page[limit] integer Sets the maximum number of records to return per page.
138 Trellix Endpoint Detection and Response Product Guide

1| Trellix EDR APIs
Response
Response parameters
| Parameters  | Data type  | Description                 |
| ----------- | ---------- | --------------------------- |
| Trace_Id    | string     | Autogenerated GUID for the  |
event.
| Parent_Trace_Id  | string  | TraceId of the parent process  |
| ---------------- | ------- | ------------------------------ |
event.
| Root_Trace_Id  | string  | Root trace ID of the entire  |
| -------------- | ------- | ---------------------------- |
process group.
| DetectionDate  | string  | Time of detection in EDR cloud.  |
| -------------- | ------- | -------------------------------- |
| Event_Date     | string  | Earliest timestamp from related  |
traces (endpoint clock, UTC).
| Activity  | string  | Evet type  |
| --------- | ------- | ---------- |
Severity  string (enum: s0–s5)  BANF rule severity. For details,
see Security levels.
| Score           | integer        | BANF rule confidence score.  |
| --------------- | -------------- | ---------------------------- |
| Detection_Tags  | array[string]  | MITRE ATT&CK tactic and      |
technique IDs.
Related_Trace_Id  array[string]  TraceIds of events responsible
for the detection.
| RuleId  | string  | BANF rule ID that triggered the  |
| ------- | ------- | -------------------------------- |
alert.
| Rank  | integer  | TA calculated rank  |
| ----- | -------- | ------------------- |
Trellix Endpoint Detection and Response Product Guide 139

1| Trellix EDR APIs
| Parameters  | Data type  | Description          |
| ----------- | ---------- | -------------------- |
| Pid         | integer    | Process ID           |
| Version     | string     | Version information  |
Parents_Trace_Id  array[string]  TraceIds of all ancestor processes
(first = parentTraceId).
| ProcessName  | string  | Name of the process that  |
| ------------ | ------- | ------------------------- |
triggered the rule.
| User  | object  | User name and domain: {  |
| ----- | ------- | ------------------------ |
"domain": "...", "name":
"..." }.
| CommandLine  | string  | Full command line of the  |
| ------------ | ------- | ------------------------- |
triggering process.
| Hash_Id  | string  | Detection ID — identical across  |
| -------- | ------- | -------------------------------- |
identical detections (same data,
different date/traceId).
| Host_OS    | string  | Host OS: windows, linux, or mac.  |
| ---------- | ------- | --------------------------------- |
| Host_Name  | string  | Host name of the device.          |
| MAGUID     | string  | Endpoint MA (formerly McAfee      |
Agent) GUID — uniquely
identifies the device.
| Artifact  | string  | Event artifact type          |
| --------- | ------- | ---------------------------- |
| HostInfo  | string  | Serialized host information  |
including network interfaces and
OS details. For example,
{ifaces=[{ip=10.26.3.39,
mac=00:50:56:AC:80:A3, name=,
| 140 | Trellix Endpoint Detection and Response Product Guide |     |
| --- | ----------------------------------------------------- | --- |

1| Trellix EDR APIs
Parameters Data type Description
type=0.0}], os={build=0.0,
desc=Linux, major=6.0,
minor=4.0,
sp=0-150600.23.22-default}}
Response example
{
"type": "alerts",
"id": "01c0a61a-060a-28e4-002a-7003f431c7aa.fb76269dfabf4fd08385b195064083fa",
"attributes": {
"Severity": "s0",
"Parent_Process_Path": "/usr/bin/bash",
"Process_Integrity": "0.0",
"HostInfo": "{ifaces=[{ip=10.26.3.39, mac=00:50:56:AC:80:A3, name=, type=0.0}, {ip=, mac=, name=Primary,
type=0.0}], os={build=0.0, desc=Linux, major=6.0, minor=4.0, sp=0-150600.23.22-default}}",
"Root_Trace_Id": "fee3fc1b-5fc4-4275-b11b-b55f078ae53b",
"Related_Trace_Id": [
"56cfd2c2-018a-4aca-aa70-d983dd6a7f0e"
],
"Process_Sha256": "81b443c0c5053c0b1124f6ad2474a7e256d9d58ca23d6e533e721a5b90c43479",
"Hash_Id": "j5bX9WlAb2jI/Clfo47ESA==",
"Parent_Process_MD5": "6a61aa11781ccf7ee3a31ce111cb73f4",
"Parents_Trace_Id": [
"b1ed287d-6c28-4762-85a3-7643e93e5490",
"e9cacc53-6100-4a0f-a1dd-a874dcad91b5",
"fee3fc1b-5fc4-4275-b11b-b55f078ae53b",
"00f8900c-911c-4bf8-9a24-111190de3901",
"7968480a-d3da-4e43-9c8d-7b710af4988f",
"96d5fd2e-e69d-4576-89aa-17a7f21bbc05",
"00000000-0000-0000-0000-000000000000"
],
"Detection_Tags": [
"@ATA.DefenseEvasion",
"@ATE.T1070.004",
"@MSI._process_file_remove"
],
"Process_Path": "/usr/lib/cron/run-crons",
"HX_Agent_Id": "3t8gXjwtzaebzEOsqzdTrP",
"CommandLine": "/usr/lib/cron/run-crons",
"P_Parent_TraceId": "e9cacc53-6100-4a0f-a1dd-a874dcad91b5",
"Rank": 30,
"Pid": 23502,
"Parent_Process_Name": "bash",
"Host_Name": "82ZSUSE15SP6",
"DetectionDate": "2025-11-10T05:50:41.464+00:00",
"ProcessName": "run-crons",
"Parent_Process_Sha256": "5148d2d56a9635b925392e4943e2da9a38fcd29e722d3b598e0d656a4fecc19f",
"Trace_Id": "a533a1d0-8a06-4a79-8e40-0e6ff3a0088c",
"MAGUID": "1EE2B999-5AA0-F011-87C6-005056AC80A3",
"Version": "undefined",
"Parent_Process_CmdLine": "/bin/sh -c test -x /usr/lib/cron/run-crons && /usr/lib/cron/run-crons >/dev/
null 2>&1",
Trellix Endpoint Detection and Response Product Guide 141

1| Trellix EDR APIs
"Process_Md5": "878e7ab69c2245e097807ee5c8fbaf50",
"Event_Date": "2025-11-10T05:45:01.000Z",
"Host_OS": "linux",
"Artifact": "Threat",
"Parent_Trace_Id": "b1ed287d-6c28-4762-85a3-7643e93e5490",
"Score": 30,
"User": {
"domain": "",
"name": "root"
},
"Activity": "Threat Detected",
"RuleId": "_process_file_remove"
}
}
Response codes
Status Response Description
200 OK Your request was processed successfully. The server has returned the
requested data.
400 Bad request The server couldn't understand your request, likely due to a syntax error
or an invalid parameter.
401 Access denied request Your request was rejected because it lacks valid authentication
credentials. Check your API key and token.
403 Forbidden You are not authorized to access this resource. While your credentials
may be valid, you don't have the necessary permissions.
404 Not Found The specific resource or endpoint you requested does not exist.
415 Unsupported Media Type The server rejected your request because the data format (Content-
Type) is not supported.
429 Too Many Requests You've exceeded the rate limit by sending too many requests in a short
period. The Retry-After header in the response will tell you how long to
wait before trying again.
500 Internal Server Error Something went wrong on the server's end. This is not an issue with
your request.
142 Trellix Endpoint Detection and Response Product Guide

1| Trellix EDR APIs
API sample for activity feed
Post webhook verification
Overview
This endpoint registers a new webhook to receive the real-time activity feed. Provide your webhookUrl, a publicKey for
verification, and any necessary customHeaders. A successful call creates the webhook configuration and returns its unique ID.
Use this API as the initial setup step for any application that needs to receive live event notifications from the Trellix EDR
platform. This is the required process to configure a destination for real-time data streams, such as new threat alerts or endpoint
status changes. This API enables a push-based data integration, allowing your systems to react instantly to security events rather
than discovering them through periodic polling.
Authentication
Authentication type: Bearer Token, API Key.
You can create a token using client credentials obtained through the developer portal. The API Key (x-api-key) is provided in
your onboarding email or on the API Access Management page.
Path (or URL)
<HTTPS Method>
POST https://{Trellix EDR_gateway_URL}/edr/v2/activity-feed/webhook-verification
Request
Request headers
Authorization: Bearer <your_bearer_token>
Content-Type: application/vnd.api+json
x-api-key: <your_api_key>
• Authorization: This header is used to authenticate your request. You need to replace <your_bearer_token> with the actual
token you generate.
• Content-Type: This header tells the server that the request body format is json:api. Even though this specific call has no
request body, the API requires this header.
Trellix Endpoint Detection and Response Product Guide 143

1| Trellix EDR APIs
• x-api-key: This is a custom header required by the Trellix API for authentication. You'll need to replace <your_api_key> with
the key from your onboarding email or the API Access Management page.
Request parameters
No request parameters
Request example
{
"data": {
"type": "activityFeed",
"attributes": {
"publicKey": "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAJgL2/
s97XHhA5rVSW5OfehDobeGN6O5tj+A1DkBwQySbmXcquwfMj5QohVKmKyvIJALKGiVTzANKh/ogXrDeNcCAwEAAQ==",
"webhookUrl": "https://www.abc.com/webhook",
"customHeaders": {
"key": "value"
}
}
}
}
Response
Response example
{
"jsonapi": {
"version": "1.0"
},
"meta": {
"totalResourceCount": 1
},
"data": {
"id": "ce5cdfff-7818-455a-bc60-841be3513f4a",
"type": "activityFeed",
"attributes": {
"webhookUrl": "****************************hook",
"publicKey": "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAJgL2/
s97XHhA5rVSW5OfehDobeGN6O5tj+A1DkBwQySbmXcquwfMj5QohVKmKyvIJALKGiVTzANKh/ogXrDeNcCAwEAAQ==",
"customHeaders": {
"key": "value"
}
}
}
}
144 Trellix Endpoint Detection and Response Product Guide

1| Trellix EDR APIs
Response codes
Status Response Description
201 Created Your request was successful, and a new resource was created as a
result. The URL to the new resource can be found in the Location
header.
400 Bad request The server couldn't understand your request, likely due to a syntax error
or an invalid parameter.
401 Access denied request Your request was rejected because it lacks valid authentication
credentials. Check your API key and token.
403 Forbidden You are not authorized to access this resource. While your credentials
may be valid, you don't have the necessary permissions.
404 Not Found The specific resource or endpoint you requested does not exist.
415 Unsupported Media Type The server rejected your request because the data format (Content-
Type) is not supported.
429 Too Many Requests You've exceeded the rate limit by sending too many requests in a short
period. The Retry-After header in the response will tell you how long to
wait before trying again.
500 Internal Server Error Something went wrong on the server's end. This is not an issue with
your request.
Post Activity Feed configuration
Overview
This endpoint creates a data feed to stream EDR events to an external system. Specify an event topic and a configType (S3,
Syslog, or Webhook) with the required destination details. A successful call registers the feed and returns its configuration. Use
this API as the final step to activate a continuous data stream to your chosen platform. This is the primary method for forwarding
Trellix Endpoint Detection and Response Product Guide 145

1| Trellix EDR APIs
all threat events to your data lake (S3), sending alerts to your SIEM (Syslog), or pushing notifications to a custom automation tool
(Webhook). This API automates the centralization of your Trellix EDR data, ensuring your other security platforms have the
complete, real-time visibility needed for effective correlation and analysis.
Authentication
Authentication type: Bearer Token, API Key.
You can create a token using client credentials obtained through the developer portal. The API Key (x-api-key) is provided in
your onboarding email or on the API Access Management page.
Path (or URL)
<HTTPS Method>
POST https://{Trellix EDR_gateway_URL}/edr/v2/activity-feed/configurations
{Trellix EDR_gateway_URL}: This is the base URL for your instance, which you can find in your Trellix onboarding email. For
example, https://api.manage.trellix.com.
Request
Request headers
Authorization: Bearer <your_bearer_token>
Content-Type: application/vnd.api+json
x-api-key: <your_api_key>
• Authorization: This header is used to authenticate your request. You need to replace <your_bearer_token> with the actual
token you generate.
• Content-Type: This header tells the server that the request body format is json:api. Even though this specific call has no
request body, the API requires this header.
• x-api-key: This is a custom header required by the Trellix API for authentication. You'll need to replace <your_api_key> with
the key from your onboarding email or the API Access Management page.
Request parameters
No request parameters.
146 Trellix Endpoint Detection and Response Product Guide

1| Trellix EDR APIs
Request example
For this endpoint, you will specify the type of event (topic) to send and the destination details (S3, Syslog, or Webhook).
Before you customize a request for an event type, make sure you have the following information.
• A topic can only be registered with one sink.
• Make sure you have set up the AWS account with the right configurations.
For details, see Set up your AWS account. If no S3 prefix is provided, the threat events or case-management events folder
will be created within the root folder of the S3 bucket.
• Make sure you have set up the Syslog account with right configurations. For details, see Set up your Syslog account.
For the Syslog request body, the entire certificate details (including --BEGIN-- and --END-- for both single and multi-chain)
need to be provided in a base64 encoded format.
'server-cert.pem' generated during the Syslog setup is the certificate data to be base 64 encoded and provided in the
request body.
• Make sure you have set up your Webhook. For more details, see Set up your Webhook.
For a webhook, the self-signed certificate is blocked and only CA-signed is allowed.
{
"data": {
"type": "activityFeed",
"attributes": {
"topic": "threatEvents | case-mgmt-events",
"configType": "s3Config | syslogConfig | webhookConfig",
"clientEmailId": "client@gmail.com",
"enableCompressedOutput": "true",
"s3Config": {
"s3Prefix": "/prefix-path",
"roleARN": "arn:aws:iam::91574147XXXX:role/customer_eaf_s3_cross_account_role",
"s3BucketName": "customer-eaf-bucket",
"awsRegion": "us-west-2"
},
"syslogConfig": {
"syslogServerIP": "10.10.10.10",
"syslogServerPort": "615",
"certificateData":
"LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tDU1JSUN3RENDQWFnQ0FRRXdEUVlKS29aSWh2Y05BUUVMQlFBd0pERWlNQ0FHQTFVRUF3d1pjMlZzWm5OcFoyNWwNWkMxallTMWpaWEowYVdacFkyRjBaVEFlRncweU5EQTBNVGt4TURVd016QmFGdzB6TkRBeU1qWXhNRFV3TXpCYQ1NQ2d4SmpBa0JnTlZCQU1NSFhObGJHWnphV2R1WldRdGMyVnlkbVZ5TFdObGNuUnBabWxqWVhSbE1JSUJJakFODUJna3Foa2lHOXcwQkFRRUZBQU9DQVE4QU1JSUJDZ0tDQVFFQXMxdTQ5blVNblMxQ1NuRzMvaks2eWhuRjQ1eUQNdy9GbnkxVmYzQ2hkd0FKSXlnbnN1SUl4VERmS2VZVjdrK09iVHZKeUlwMmRhRHZPdkI2eEUwQ3hMa2JNVnhWbQ1INnpCeVdYOW5Ha2hxUHY3Sk05aGJjMXFzMFZMTlp0K2tXR0tidCtRUFpIV0ozRlV6cDBuZGNRS1J1RTdlaDVyDVA2WGpVV2FrUmF5TDdJN3YrTUhuaDBmalpnUTZDa2lzK2pHRmpjVlU2cHZ5SEVRNWo0Z2dDMU1uYTZFTjR1Mm8NNm05cVIrQko2OUwwZnlaZkpNMk9zSlZwQTZMZS9BUkJXVGhXdlgyaHVvSVJwbHg5dnppK3JmeEpqUnUwSk8xRg1uaElFWkg2OHRESVFvU04rakIzcDBYTUxKT3o0NXdFQ0JCTGFsWmJmNWlETkZIZDExUnBIRFlZdXlRSURBUUFCDU1BMEdDU3FHU0liM0RRRUJDd1VBQTRJQkFRQnc1L1NoQVExbFNtOTRxZG1wTzJibWE1RlM4TytMRzYzTjhqRksNUjlkT0RRRVBsdllzRVozVGNMT01ENm5GZjEyTE5waVcvMUY1ZmJFSlBWY0NRcW1xNTM1Z1NMb05tZUxtZTlhNQ11ZWJrOVJ3cHBmd0J2UVFwdkY1ODF2Q05NOGdEWC92TWZraEVwUEZzZE9MdHlMRW9OSDVwVE1obkZmVjhMa1Y0DWw0cHFadkxZZEpQMGNTRWwxUGExRzlRK3J6RkZoT0JZWVVRdGZJL2lXbjRHdk1NZ1NpNURLTlViQzUyQ29YSnUNckRpeFJkcFQvdmpSR0VZTWJJYVZ3MWRpUnd3clVxL2FJRzRHSTFGWVFGSHFZQlNHQUJ2bW1IVXE3Yy9uakN2Mw1MVDQ4ak1ZdGhxb1ZZR25naXlWQ28wTndweVN1MjlEMzR2WUZnSE1JQkJpdHlpWTQNLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQ",
"testIgnoreMessage": "TEST-MESSAGE"
},
"webhookConfig": {
"webhookUrl": "https://www.abc.com/webhook",
"testIgnoreMessage": "TEST-MESSAGE",
"customHeaders": {
"key": "value"
}
}
}
}
}
Trellix Endpoint Detection and Response Product Guide 147

1| Trellix EDR APIs
Response
Response example
{
"jsonapi": {
"version": "1.0"
},
"meta": {
"totalResourceCount": 1
},
"data": {
"id": "ce5cdfff-7818-455a-bc60-841be3513f4a",
"type": "activityFeed",
"attributes": {
"topic": "threatEvents",
"clientEmailId": "example@gmail.com",
"configType": "s3Config",
"enableCompressedOutput": "true",
"s3Config": {
"s3Prefix": "/prefix",
"roleARN": "arn:aws:iam::91574147XXX:role/EAF_S3CrossAccountAccess",
"s3BucketName": "example-bucket",
"awsRegion": "us-west-2"
}
}
}
}
Response codes
Status Response Description
201 Created Your request was successful, and a new resource was created as a
result. The URL to the new resource can be found in the Location
header.
400 Bad request The server couldn't understand your request, likely due to a syntax error
or an invalid parameter.
401 Access denied request Your request was rejected because it lacks valid authentication
credentials. Check your API key and token.
403 Forbidden You are not authorized to access this resource. While your credentials
may be valid, you don't have the necessary permissions.
148 Trellix Endpoint Detection and Response Product Guide

1| Trellix EDR APIs
Status Response Description
404 Not Found The specific resource or endpoint you requested does not exist.
415 Unsupported Media Type The server rejected your request because the data format (Content-
Type) is not supported.
429 Too Many Requests You've exceeded the rate limit by sending too many requests in a short
period. The Retry-After header in the response will tell you how long to
wait before trying again.
500 Internal Server Error Something went wrong on the server's end. This is not an issue with
your request.
Get Activity Feed configuration
Overview
This endpoint retrieves a complete list of all active activity feed configurations. The response is an array of configuration objects,
each detailing an event topic and its configured destination (S3, Syslog, or Webhook). Use this API to review and audit your
current data streaming setups. It's the primary method to programmatically verify which data feeds are active before attempting
to create a new one, or to identify a specific configuration's ID for modification or deletion. This API provides a centralized,
programmatic view of all Trellix data export rules, enabling automated configuration management and validation.
Authentication
Authentication type: Bearer Token, API Key.
You can create a token using client credentials obtained through the developer portal. The API Key (x-api-key) is provided in
your onboarding email or on the API Access Management page.
Path (or URL)
<HTTPS Method>
GET https://{Trellix EDR_gateway_URL}/edr/v2/activity-feed/configurations
Trellix Endpoint Detection and Response Product Guide 149

1| Trellix EDR APIs
Request
Request headers
Authorization: Bearer <your_bearer_token>
Content-Type: application/vnd.api+json
x-api-key: <your_api_key>
• Authorization: This header is used to authenticate your request. You need to replace <your_bearer_token> with the actual
token you generate.
• Content-Type: This header tells the server that the request body format is json:api. Even though this specific call has no
request body, the API requires this header.
• x-api-key: This is a custom header required by the Trellix API for authentication. You'll need to replace <your_api_key> with
the key from your onboarding email or the API Access Management page.
Request parameters
No request parameters.
Response
Response example
{
"jsonapi": {
"version": "1.0"
},
"meta": {
"totalResourceCount": 10
},
"data": [
{
"id": "ce5cdfff-7818-455a-bc60-841be3513f4a",
"type": "activityFeed",
"attributes": {
"topic": "threatEvents",
"clientEmailId": "example@gmail.com",
"configType": "s3Config",
"enableCompressedOutput": "true",
"s3Config": {
"s3Prefix": "/prefix",
"roleARN": "arn:aws:iam::91574147XXX:role/EAF_S3CrossAccountAccess",
"s3BucketName": "example-bucket",
"awsRegion": "us-west-2"
150 Trellix Endpoint Detection and Response Product Guide

1| Trellix EDR APIs
}
}
}
]
}
Response codes
Status Response Description
200 OK Your request was processed successfully. The server has returned the
requested data.
400 Bad request The server couldn't understand your request, likely due to a syntax error
or an invalid parameter.
401 Access denied request Your request was rejected because it lacks valid authentication
credentials. Check your API key and token.
403 Forbidden You are not authorized to access this resource. While your credentials
may be valid, you don't have the necessary permissions.
404 Not Found The specific resource or endpoint you requested does not exist.
415 Unsupported Media Type The server rejected your request because the data format (Content-
Type) is not supported.
429 Too Many Requests You've exceeded the rate limit by sending too many requests in a short
period. The Retry-After header in the response will tell you how long to
wait before trying again.
500 Internal Server Error Something went wrong on the server's end. This is not an issue with
your request.
Trellix Endpoint Detection and Response Product Guide 151

1| Trellix EDR APIs
Get Activity feed configuration with ID
Overview
This endpoint retrieves the complete details for a single activity feed configuration. Target a specific configuration by its
configuration-id in the path. The response is a single object containing all settings for that feed, including its topic and
destination details. Use this API to verify the settings of a specific data feed. It's the standard method for fetching the current
state of a configuration before you update it, or to confirm that a new feed was created with the correct parameters. This API
provides on-demand access to individual feed configurations, enabling precise and automated validation within your
management workflows.
Authentication
Authentication type: Bearer Token, API Key.
You can create a token using client credentials obtained through the developer portal. The API Key (x-api-key) is provided in
your onboarding email or on the API Access Management page.
Path (or URL)
<HTTPS Method>
GET https://{Trellix EDR_gateway_URL}/edr/v2/activity-feed/configurations/{configuration-id}
Request
Request headers
Authorization: Bearer <your_bearer_token>
Content-Type: application/vnd.api+json
x-api-key: <your_api_key>
• Authorization: This header is used to authenticate your request. You need to replace <your_bearer_token> with the actual
token you generate.
• Content-Type: This header tells the server that the request body format is json:api. Even though this specific call has no
request body, the API requires this header.
• x-api-key: This is a custom header required by the Trellix API for authentication. You'll need to replace <your_api_key> with
the key from your onboarding email or the API Access Management page.
152 Trellix Endpoint Detection and Response Product Guide

1| Trellix EDR APIs
Request parameters
Parameters Data type/Values Description
configurationI string This is a path parameter. A unique identifier for the configuration.
d
Response
Response example
{
"jsonapi": {
"version": "1.0"
},
"meta": {
"totalResourceCount": 1
},
"data": {
"type": "activityFeed",
"id": "8906193e-383c-4a61-9beb-b692f90e100c",
"attributes": {
"topic": "threatEvents",
"clientEmailId": "test_tenant@yopmail.com",
"configType": "s3Config",
"enableCompressedOutput": true,
"s3Config": {
"s3Prefix": "username",
"roleARN": "arn:aws:iam::0946XXXXXXXXX:role/EAF_Role_of_S3_bucket",
"s3BucketName": "EAF_bucket",
"awsRegion": "us-west-2"
}
}
}
}
Response codes
Status Response Description
200 OK Your request was processed successfully. The server has returned the
requested data.
Trellix Endpoint Detection and Response Product Guide 153

1| Trellix EDR APIs
Status Response Description
400 Bad request The server couldn't understand your request, likely due to a syntax error
or an invalid parameter.
401 Access denied request Your request was rejected because it lacks valid authentication
credentials. Check your API key and token.
403 Forbidden You are not authorized to access this resource. While your credentials
may be valid, you don't have the necessary permissions.
404 Not Found The specific resource or endpoint you requested does not exist.
415 Unsupported Media Type The server rejected your request because the data format (Content-
Type) is not supported.
429 Too Many Requests You've exceeded the rate limit by sending too many requests in a short
period. The Retry-After header in the response will tell you how long to
wait before trying again.
500 Internal Server Error Something went wrong on the server's end. This is not an issue with
your request.
Patch Activity feed configuration with ID
Overview
This endpoint updates an existing activity feed configuration. Target a configuration by its configuration-id and provide only
the attributes you want to change in the request body. The API applies the modifications and returns the complete, updated
configuration object. Use this API to modify the settings of an active data stream. This is the required method for updating
destination details when your infrastructure changes, such as pointing to a new S3 bucket, updating a Syslog server's IP, or
changing a webhook URL.
Authentication
Authentication type: Bearer Token, API Key.
154 Trellix Endpoint Detection and Response Product Guide

1| Trellix EDR APIs
You can create a token using client credentials obtained through the developer portal. The API Key (x-api-key) is provided in
your onboarding email or on the API Access Management page.
Path (or URL)
<HTTPS Method>
PATCH https://{Trellix EDR_gateway_URL}/edr/v2/activity-feed/configurations/{configuration-id}
Request
Request headers
Authorization: Bearer <your_bearer_token>
Content-Type: application/vnd.api+json
x-api-key: <your_api_key>
• Authorization: This header is used to authenticate your request. You need to replace <your_bearer_token> with the actual
token you generate.
• Content-Type: This header tells the server that the request body format is json:api. Even though this specific call has no
request body, the API requires this header.
• x-api-key: This is a custom header required by the Trellix API for authentication. You'll need to replace <your_api_key> with
the key from your onboarding email or the API Access Management page.
Request parameters
Parameters Data type/Values Description
configurationI string This is a path parameter. A unique identifier for the configuration.
d
Request example
The request body must include the resource type and ID. In the attributes object, specify only the fields you want to update.
Fields that are not included remain unchanged.
Trellix Endpoint Detection and Response Product Guide 155

1| Trellix EDR APIs
| Field      | Data type  | Description                             |
| ---------- | ---------- | --------------------------------------- |
| data.type  | String     | Must be activityFeed.                   |
| data.id    | String     | The ID of the configuration to update.  |
data.attribute Object  An object containing the fields to modify.
s
Common Attributes
attributes.clie String  The email address for notifications.
ntEmailId
attributes.ena Boolean  Set to true to receive compressed data.
bleCompresse
dOutput
S3 Configuration Attributes (s3Config)
| s3Config.s3Pr | String  | The folder path within the S3 bucket.  |
| ------------- | ------- | -------------------------------------- |
efix
s3Config.role String  The Amazon Resource Name (ARN) of the IAM role.
ARN
| s3Config.s3Bu | String  | The name of the Amazon S3 bucket.  |
| ------------- | ------- | ---------------------------------- |
cketName
s3Config.awsR String  The AWS region where the bucket is located.
egion
Syslog Configuration Attributes (syslogConfig)
| syslogConfig.s | String  | The IP address of the syslog server.  |
| -------------- | ------- | ------------------------------------- |
yslogServerIP
syslogConfig.s String  The port number for the syslog server.
156 Trellix Endpoint Detection and Response Product Guide

1| Trellix EDR APIs
Field Data type Description
yslogServerPo
rt
syslogConfig.c String The public certificate data for a secure TLS connection.
ertificateData
syslogConfig.t String A message used to test the connection, which the server will ignore.
estIgnoreMes
sage
Webhook Configuration Attributes (webhookConfig)
webhookCon String The destination URL for the webhook.
fig.webhookU
rl
Note:
You must verify the new webhook URL before updating it.
webhookCon Object Key-value pairs of custom headers to send with the webhook.
fig.customHea
ders
webhookCon String A message used to test the webhook connection.
fig.testIgnore
Message
{
"data": {
"id": "998f8e3f-d8ca-4acd-a3bd-d15542bf0e02",
"type": "activityFeed",
"attributes": {
"topic": "threatEvents",
"configType": "s3Config",
"clientEmailId": "example@gmail.com",
"enableCompressedOutput": "true",
"s3Config": {
"s3Prefix": "/prefix",
"roleARN": "arn:aws:iam::91574147XXXX:role/EAF_S3CrossAccountAccess",
"s3BucketName": "test-bucket",
"awsRegion": "us-west-2"
}
}
Trellix Endpoint Detection and Response Product Guide 157

1| Trellix EDR APIs
}
}
Response
Response example
{
"jsonapi": {
"version": "1.0"
},
"meta": {
"totalResourceCount": 1
},
"data": {
"id": "ce5cdfff-7818-455a-bc60-841be3513f4a",
"type": "activityFeed",
"attributes": {
"topic": "threatEvents",
"clientEmailId": "example@gmail.com",
"configType": "s3Config",
"enableCompressedOutput": "true",
"s3Config": {
"s3Prefix": "/prefix",
"roleARN": "arn:aws:iam::91574147XXX:role/EAF_S3CrossAccountAccess",
"s3BucketName": "example-bucket",
"awsRegion": "us-west-2"
}
}
}
}
Response codes
Status Response Description
200 OK Your request was processed successfully. The server has returned the
requested data.
400 Bad request The server couldn't understand your request, likely due to a syntax error
or an invalid parameter.
401 Access denied request Your request was rejected because it lacks valid authentication
credentials. Check your API key and token.
158 Trellix Endpoint Detection and Response Product Guide

1| Trellix EDR APIs
Status Response Description
403 Forbidden You are not authorized to access this resource. While your credentials
may be valid, you don't have the necessary permissions.
404 Not Found The specific resource or endpoint you requested does not exist.
415 Unsupported Media Type The server rejected your request because the data format (Content-
Type) is not supported.
429 Too Many Requests You've exceeded the rate limit by sending too many requests in a short
period. The Retry-After header in the response will tell you how long to
wait before trying again.
500 Internal Server Error Something went wrong on the server's end. This is not an issue with
your request.
Delete Activity feed configuration with ID
Overview
This endpoint permanently deletes an activity feed configuration, which stops the associated data stream. Target the
configuration by its configuration-id in the path. The action is irreversible and a successful response returns 204 No Content.
Use this API to decommission a data feed. This is necessary when the external system receiving the data is retired, or when you
are replacing an existing data pipeline and need to remove the old configuration. This API provides a clean method for
programmatically managing data export rules, ensuring that sensitive security data is only sent to currently approved and active
destinations.
Authentication
Authentication type: Bearer Token, API Key.
You can create a token using client credentials obtained through the developer portal. The API Key (x-api-key) is provided in
your onboarding email or on the API Access Management page.
Trellix Endpoint Detection and Response Product Guide 159

1| Trellix EDR APIs
Path (or URL)
<HTTPS Method>
DELETE https://{Trellix EDR_gateway_URL}/edr/v2/activity-feed/configurations/{configuration-id}
Request
Request headers
Authorization: Bearer <your_bearer_token>
Content-Type: application/vnd.api+json
x-api-key: <your_api_key>
• Authorization: This header is used to authenticate your request. You need to replace <your_bearer_token> with the actual
token you generate.
• Content-Type: This header tells the server that the request body format is json:api. Even though this specific call has no
request body, the API requires this header.
• x-api-key: This is a custom header required by the Trellix API for authentication. You'll need to replace <your_api_key> with
the key from your onboarding email or the API Access Management page.
Request parameters
Parameters Data type/Values Description
configurationI string This is a path parameter. A unique identifier for the configuration.
d
Response codes
Status Response Description
204 No Content The configuration was permanently deleted.
160 Trellix Endpoint Detection and Response Product Guide

1| Trellix EDR APIs
Status Response Description
400 Bad request The server couldn't understand your request, likely due to a syntax error
or an invalid parameter.
401 Access denied request Your request was rejected because it lacks valid authentication
credentials. Check your API key and token.
403 Forbidden You are not authorized to access this resource. While your credentials
may be valid, you don't have the necessary permissions.
404 Not Found The specific resource or endpoint you requested does not exist.
415 Unsupported Media Type The server rejected your request because the data format (Content-
Type) is not supported.
429 Too Many Requests You've exceeded the rate limit by sending too many requests in a short
period. The Retry-After header in the response will tell you how long to
wait before trying again.
500 Internal Server Error Something went wrong on the server's end. This is not an issue with
your request.
Delete all Activity feed configurations for a tenant
Overview
This endpoint permanently deletes an activity feed configuration, which stops the associated data stream. Target the
configuration by its configuration-id in the path. The action is irreversible and a successful response returns 204 No Content.
Use this API to decommission a data feed. This is necessary when the external system receiving the data is retired, or when you
are replacing an existing data pipeline and need to remove the old configuration. This API provides a clean method for
programmatically managing data export rules, ensuring that sensitive security data is only sent to currently approved and active
destinations.
Authentication
Authentication type: Bearer Token, API Key.
Trellix Endpoint Detection and Response Product Guide 161

1| Trellix EDR APIs
You can create a token using client credentials obtained through the developer portal. The API Key (x-api-key) is provided in
your onboarding email or on the API Access Management page.
Path (or URL)
<HTTPS Method>
DELETE https://{Trellix EDR_gateway_URL}/edr/v2/activity-feed/configurations
Request
Request headers
Authorization: Bearer <your_bearer_token>
Content-Type: application/vnd.api+json
x-api-key: <your_api_key>
• Authorization: This header is used to authenticate your request. You need to replace <your_bearer_token> with the actual
token you generate.
• Content-Type: This header tells the server that the request body format is json:api. Even though this specific call has no
request body, the API requires this header.
• x-api-key: This is a custom header required by the Trellix API for authentication. You'll need to replace <your_api_key> with
the key from your onboarding email or the API Access Management page.
Request parameters
Parameters Data type/Values Description
configurationI string This is a path parameter. A unique identifier for the configuration.
d
162 Trellix Endpoint Detection and Response Product Guide

1| Trellix EDR APIs
Response codes
Status Response Description
204 No Content The configuration was permanently deleted.
400 Bad request The server couldn't understand your request, likely due to a syntax error
or an invalid parameter.
401 Access denied request Your request was rejected because it lacks valid authentication
credentials. Check your API key and token.
403 Forbidden You are not authorized to access this resource. While your credentials
may be valid, you don't have the necessary permissions.
404 Not Found The specific resource or endpoint you requested does not exist.
415 Unsupported Media Type The server rejected your request because the data format (Content-
Type) is not supported.
429 Too Many Requests You've exceeded the rate limit by sending too many requests in a short
period. The Retry-After header in the response will tell you how long to
wait before trying again.
500 Internal Server Error Something went wrong on the server's end. This is not an issue with
your request.
Set up your AWS S3
To set up AWS account, you need to perform the following steps.
1. Create S3 bucket with default settings.
2. Create an IAM role to access S3 bucket and provide cross account permission.
a. Select Trusted entity type as AWS account.
b. Provide Trellix AWS account number - 983703175993 in the Another AWS Account section.
Trellix Endpoint Detection and Response Product Guide 163

1| Trellix EDR APIs
c. Create IAM policy with the following JSON format.
{
"Version": "2012-10-17",
"Statement": [
{
"Effect": "Allow",
"Action": [
"s3:ListBucket"
],
"Resource": [
"arn:aws:s3:::customer-eaf-bucket"
]
},
{
"Effect": "Allow",
"Action": [
"s3:GetObject",
"s3:PutObject"
],
"Resource": [
"arn:aws:s3:::customer-eaf-bucket/*"
]
}
]
}
Note
Replace "customer-eaf-bucket name" with your S3 bucket name.
d. Review and create a policy. Also, attach the policy created in step c and create a role.
e. Once the role is created, edit the trust relationship to replace with below content. Also. replace XXXXXXXXXXXX with
the actual Trellix AWS account number.
Note
You can enable External ID within the AWS S3 IAM policy to include the list of tenants whose events can be sent
to the S3 bucket. This allows only the listed tenant configurations and data is sent to the AWS S3 bucket. Also,
make sure External ID is the tenant ID of the customer.
{
"Version": "2012-10-17",
"Statement": [
{
"Effect": "Allow",
"Principal": {
"AWS": "arn:aws:iam::XXXXXXXXXXXX:role/EAF_S3CrossAccountAccess"
},
"Action": "sts:AssumeRole",
"Condition": {
"StringEquals": {
"sts:ExternalId": "315F3DC7-3DE1-4050-ABBA-381BFE83D4DC" }
}
164 Trellix Endpoint Detection and Response Product Guide

1| Trellix EDR APIs
},
{
"Sid": "Statement1",
"Effect": "Allow",
"Principal": {
"Service": "s3.amazonaws.com"
},
"Action": "sts:AssumeRole"
}
]
}
Set up your Syslog
To set up a syslog server with SSL (Secure Sockets Layer) enabled, you need to perform the following steps.
1. Create certs directory to hold the self signed and generated certificates.
cd ~
mkdir certs
cd certs
2. Generate self signed certificates.
For CA and server certificates, give details that are not unique to each other.
openssl genrsa 2048 > ca-key.pem
3. Create CA certificate.
openssl req -new -x509 -nodes -days 3600 -key ca-key.pem -out ca.pem -subj "/CN=selfsigned-ca-certificate"
4. Create server certificate.
openssl req -newkey rsa:2048 -days 3600 -nodes -keyout server-key.pem -out server-req.pem -subj
"/CN=selfsigned-server-certificate"
openssl rsa -in server-key.pem -out server-key.pem
openssl x509 -req -in server-req.pem -days 3600 -CA ca.pem -CAkey ca-key.pem -set_serial 01 -out server-
cert.pem
5. Verify the certificates and you must see in response as "server-cert.pem: OK".
openssl verify -CAfile ca.pem server-cert.pem
6. Install and enable rsyslog.
sudo apt update && sudo apt install rsyslog
Trellix Endpoint Detection and Response Product Guide 165

1| Trellix EDR APIs
sudo apt-get install rsyslog-gnutls
sudo systemctl start rsyslog
sudo systemctl status rsyslog
sudo systemctl enable rsyslog
sudo vi /etc/rsyslog.conf
7. Configure syslog.
sudo vi /etc/rsyslog.conf
module(load="imtcp" StreamDriver.AuthMode="anon" StreamDriver.Mode="1")
module(load="imuxsock") # provides support for local system logging (e.g. via logger command)
module(load="imklog") # provides kernel logging support (previously done by rklogd)
$DefaultNetstreamDriver gtls
$DefaultNetstreamDriverCAFile <path/to/ca.pem>
$DefaultNetstreamDriverCertFile <path/to/server-cert.pem>
$DefaultNetstreamDriverKeyFile <path/to/server-key.pem>
$InputTCPServerRun 6514
$template threatLogs,"/var/log/eaf/threatLogs.log"
*.* ?threatLogs
Note
Make sure to provide the correct path for ca.pem, server-key.pem, and server-cert.pem.
8. Save the file and restart rsyslog.
sudo systemctl restart rsyslog
sudo systemctl status rsyslog
The server certificate details provided in the POST or PATCH configuration must be base64 encoded.
166 Trellix Endpoint Detection and Response Product Guide

1| Trellix EDR APIs
Create syslog server with multiple chain self signed certificate:
1. Create a root key and certificate
openssl req -x509 -newkey rsa:4096 -keyout root.key -out root.crt -days 365 -nodes -subj "/CN=RootCA"
2. Create an Intermediate key and certificate.
openssl req -newkey rsa:4096 -keyout intermediate.key -out intermediate.csr -nodes -subj
"/CN=IntermediateCA"
openssl x509 -req -in intermediate.csr -CA root.crt -CAkey root.key -CAcreateserial -out intermediate.crt
-days 365
3. Combine the root and intermediate certificates into a chain.
cat root.crt intermediate.crt &gt; root_chain.crt
4. Create the server key and certificate.
openssl req -newkey rsa:2048 -keyout server.key -out server.csr -nodes -subj "/CN=SysLogServer"
openssl x509 -req -in server.csr -CA root_chain.crt -CAkey root.key -CAcreateserial -out server.crt -days
365
cat root.crt intermediate.crt server.crt &gt; certificate_chain.crt
module(load="imtcp" StreamDriver.AuthMode="anon" StreamDriver.Mode="1")
module(load="imuxsock") # provides support for local system logging (example, via logger command)
module(load="imklog") # provides kernel logging support (previously done by rklogd)
$DefaultNetstreamDriver gtls
$DefaultNetstreamDriverCAFile /home/appsadm/certs/root.key
$DefaultNetstreamDriverCertFile /home/appsadm/certs/certificate_chain.crt
$DefaultNetstreamDriverKeyFile /home/appsadm/certs/root.key
$InputTCPServerRun 6514
$template threatLogs,"/var/log/eaf/threatLogs.log"
Trellix Endpoint Detection and Response Product Guide 167

1| Trellix EDR APIs
Note
Make sure your syslog server must have a public IP and port enabled for Trellix PODs to access.
Set up your Webhook
1. Register an endpoint with the public key using the initial endpoint details provided within the controller or by directly
invoking the webhook verification endpoint.
https://api.manage.trellix.com/edr/v2/activity-feed/webhook-verification
• Register using the initial endpoint details provided within the controller.
curl --location 'http://localhost:&lt;port&gt;/&lt;webhook_url&gt;/initiate' --header 'Authorization:
&lt;tenant_token&gt;' --header 'server_url: https://api.manage.trellix.com/edr/v2/activity-feed/
webhook-verification' --header 'client_url: https://&lt;webhook_domain&gt;/&lt;webhook_url&gt;' --
header 'Content-Type: application/vnd.api+json' --verbose
• Register by directly invoking the webhook verification endpoint.
{
"data": {
"type": "activityFeed",
"attributes": {
"publicKey": "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJ******************ertKn+6rqJ2/
CCljR5bjyzNfesg1AkcCT553MLUCAwEAAQ==",
"webhookUrl": "https://<webhook_domain>/<webhook_url>"
}
}
}
2. Configure a webhook using the following payload.
https://api.manage.trellix.com/edr/v2/activity-feed/configurations
{
"data": {
"type": "activityFeed",
"attributes": {
"topic": "case-mgmt-events", // topic: case-mgmt-events or threatEvents
"clientEmailId": "tenant@yopmail.com",
"configType": "webhookConfig", // config type: syslogConfig or s3Config or webhookConfig
"enableCompressedOutput": false, // enable/disable compression of data in sinks: true or
false
"webhookConfig": {
"webhookUrl": "https://<webhook_domain>/<webhook_url>",
"testIgnoreMessage": "successful"
}
}
}
}
3. Set up a client controller.
168 Trellix Endpoint Detection and Response Product Guide

1| Trellix EDR APIs
a. Check out a client controller code from the repository.
b. Build a jar file once the changes for the client controller file are done (For example, webhook url, custom headers
etc.)
./gradlew clean build
c. Get the jar file from build/libs/.
cd build/libs/ &gt; trellix-edr-activity-feed-0.0.1-SNAPSHOT.jar
d. Copy the jar file to the server hosting webhook.
e. Run the client controller.
java -Dserver.port=&amp;lt;port_num&amp;gt; -jar trellix-edr-activity-feed-0.0.1-SNAPSHOT.jar
f. Trigger EAF APIs to configure a webhook.
API sample for collectors and reactions
This section includes:
• Create Reaction
• Get Reaction
• Get Reaction with ID
• Patch Reaction
• Delete Reaction
Create Reaction
Overview
This endpoint creates a custom reaction in the Trellix EDR environment. Provide a JSON payload that includes the reaction name,
execution content (such as scripts), and required arguments. The response returns the created reaction with a unique identifier
and associated metadata. Use this endpoint to define response actions that execute specific commands or scripts on endpoints.
Authentication
Authentication type: Bearer Token, API Key.
Trellix Endpoint Detection and Response Product Guide 169

1| Trellix EDR APIs
You can create a token using client credentials obtained through the developer portal. The API Key (x-api-key) is provided in
your onboarding email or on the API Access Management page.
Path (or URL)
<HTTPS Method>
POST https://{Trellix EDR_gateway_URL}/edr/v2/reactions
Request
Request headers
Authorization: Bearer <your_bearer_token>
Content-Type: application/vnd.api+json
x-api-key: <your_api_key>
• Authorization: This header is used to authenticate your request. You need to replace <your_bearer_token> with the actual
token you generate.
• Content-Type: This header tells the server that the request body format is json:api. Even though this specific call has no
request body, the API requires this header.
• x-api-key: This is a custom header required by the Trellix API for authentication. You'll need to replace <your_api_key> with
the key from your onboarding email or the API Access Management page.
Request example
{
"data": {
"type": "reactions",
"attributes": {
"name": "_Check_New_reaction",
"description": "Creating a new reaction",
"contents": [
{
"platform": {
"name": "windows"
},
"capability": {
"name": "Execute Powershell Script"
},
"content": "ls"
}
],
"arguments": [
{
"name": "ABC",
170 Trellix Endpoint Detection and Response Product Guide

1| Trellix EDR APIs
"type": "NUMBER"
}
],
"timeout": 60
}
}
}
Response
Response example
{
"data": {
"id": "587",
"type": "customReactions",
"attributes": {
"catalogVersion": 0,
"metadata": {},
"hidden": false,
"dbVersion": 0,
"description": "Creating a new reaction",
"timeout": 60,
"internalArguments": {},
"internalName": "_Check_New_reaction",
"remediation": false,
"task": "REACTION",
"contents": [
{
"id": "11976",
"platform": {
"catalogVersion": 1307,
"dbVersion": 0,
"id": "1",
"name": "windows",
"topic": "/mcafee/mar/agent/query/windows",
"enabled": true
},
"capability": {
"catalogVersion": 1307,
"dbVersion": 0,
"id": "27",
"name": "Execute PowerShell Script",
"description": "Runs Windows PowerShell Scripts",
"module": "SystemRuntime",
"function": "executePS",
"contentEnabled": true,
"outputs": [],
"formatArgs": {
"hasHeaders": false,
"delimiter": ","
},
"format": "CSV",
"platforms": [
{
"catalogVersion": 1307,
"dbVersion": 0,
"id": "1",
Trellix Endpoint Detection and Response Product Guide 171

1| Trellix EDR APIs
"name": "windows",
"topic": "/mcafee/mar/agent/query/windows",
"enabled": true
}
],
"platformSettings": [
{
"id": "5346",
"platform": {
"catalogVersion": 1307,
"dbVersion": 0,
"id": "1",
"name": "windows",
"topic": "/mcafee/mar/agent/query/windows",
"enabled": true
},
"utf8Sensitive": false
}
],
"itemType": "CUSTOM",
"catalogItems": [
"REACTION",
"COLLECTOR"
]
},
"content": "ls\r\n",
"arguments": [],
"utf8Sensitive": false
}
],
"availableForTrigger": true,
"name": "_Check_New_reaction",
"arguments": [
{
"id": "2946",
"name": "abc",
"type": "NUMBER",
"optional": false
}
],
"availableOffline": false
}
},
"links": {
"self": "/edr/v2/reactions/587"
}
}
Response codes
Status Response Description
201 OK Your request was processed
successfully. The server has
returned the requested data.
172 Trellix Endpoint Detection and Response Product Guide

1| Trellix EDR APIs
Status Response Description
400 Bad request The server couldn't understand
your request, likely due to a
syntax error or an invalid
parameter.
Get Reaction
Overview
This endpoint retrieves a paginated list of reactions available in the environment. Use query parameters such as page[offset],
page[limit], and sort to navigate and organize the results. The response includes both built-in and custom reactions with their
configurations. Use this endpoint to view available response actions and identify reaction IDs for automation workflows.
Authentication
Authentication type: Bearer Token, API Key.
You can create a token using client credentials obtained through the developer portal. The API Key (x-api-key) is provided in
your onboarding email or on the API Access Management page.
Path (or URL)
<HTTPS Method>
GET https://{Trellix EDR_gateway_URL}/edr/v2/reactions
Request
Request headers
Authorization: Bearer <your_bearer_token>
Content-Type: application/vnd.api+json
x-api-key: <your_api_key>
• Authorization: This header is used to authenticate your request. You need to replace <your_bearer_token> with the actual
Trellix Endpoint Detection and Response Product Guide 173

1| Trellix EDR APIs
token you generate.
• Content-Type: This header tells the server that the request body format is json:api. Even though this specific call has no
request body, the API requires this header.
• x-api-key: This is a custom header required by the Trellix API for authentication. You'll need to replace <your_api_key> with
the key from your onboarding email or the API Access Management page.
Request parameters
Parameters Data type/Values Description
page[offset] Integer Number of records to skip (starts
from 0th record)
page[limit] Integer Number of records to fetch in a
page
sort String Single column to be sorted by.
The default sort is ascending.
Response
Response example
{
"jsonapi": {
"version": "1.0"
},
"meta": {
"totalResourceCount": 2
},
"data": [
{
"id": "15",
"type": "builtinReactions",
"attributes": {
"catalogVersion": 1307,
"metadata": {
"contentUpdated": false
},
"hidden": false,
"dbVersion": 0,
"description": "Delete a folder by its full path",
174 Trellix Endpoint Detection and Response Product Guide

1| Trellix EDR APIs
"classification": "REMEDIATION",
"timeout": 60,
"internalArguments": {},
"internalName": "deleteFolder",
"remediation": false,
"task": "REACTION",
"availableForTrigger": true,
"name": "DeleteFolder",
"tenantId": "",
"arguments": [
{
"id": "2924",
"name": "full_path",
"type": "STRING",
"collectorMappings": [
{
"id": "3057",
"name": "Files",
"output": {
"id": "164",
"name": "dir",
"type": "STRING",
"byDefault": false,
"sequence": 2
},
"type": "BUILTIN",
"collectorId": 3
}
],
"optional": false
}
],
"availableOffline": false,
"chainedReactions": []
}
},
{
"id": "554",
"type": "customReactions",
"attributes": {
"catalogVersion": 0,
"metadata": {},
"hidden": false,
"dbVersion": 0,
"description": "Rebootwindows_powershell",
"timeout": 30,
"internalArguments": {},
"internalName": "_Custom_reaction8",
"remediation": false,
"task": "REACTION",
"availableForTrigger": true,
"name": "_Custom_reaction8",
"tenantId": "06ADBB7B-2BD7-4EA7-8380-39C4398BCD3D",
"arguments": [
{
"id": "2873",
"name": "ip_address1",
"type": "STRING",
"collectorMappings": [],
"optional": false
},
{
"id": "2874",
"name": "ip_address2",
Trellix Endpoint Detection and Response Product Guide 175

1| Trellix EDR APIs
"type": "STRING",
"collectorMappings": [],
"optional": false
}
],
"availableOffline": false,
"chainedReactions": []
}
}
],
"links": {
"self": "/edr/v2/reactions?page[offset]=0&page[limit]=20",
"first": "/edr/v2/reactions?page[offset]=0&page[limit]=20",
"prev": null,
"next": "/edr/v2/reactions?page[offset]=20&page[limit]=20",
"last": "/edr/v2/reactions?page[offset]=20&page[limit]=20"
}
}
Response codes
Status Response Description
200 OK Your request was processed
successfully. The server has
returned the requested data.
400 Bad request The server couldn't understand
your request, likely due to a
syntax error or an invalid
parameter.
Get Reaction with ID
Overview
This endpoint retrieves the configuration details of a specific reaction using its unique identifier. The response includes execution
details, supported platforms, and required arguments. Use this endpoint to review a reaction before deploying it.
Authentication
Authentication type: Bearer Token, API Key.
176 Trellix Endpoint Detection and Response Product Guide

1| Trellix EDR APIs
You can create a token using client credentials obtained through the developer portal. The API Key (x-api-key) is provided in
your onboarding email or on the API Access Management page.
Path (or URL)
<HTTPS Method>
Get https://{Trellix EDR_gateway_URL}/edr/v2/reactions/{reaction-id}
Request
Request headers
Authorization: Bearer <your_bearer_token>
Content-Type: application/vnd.api+json
x-api-key: <your_api_key>
• Authorization: This header is used to authenticate your request. You need to replace <your_bearer_token> with the actual
token you generate.
• Content-Type: This header tells the server that the request body format is json:api. Even though this specific call has no
request body, the API requires this header.
• x-api-key: This is a custom header required by the Trellix API for authentication. You'll need to replace <your_api_key> with
the key from your onboarding email or the API Access Management page.
Request parameters
No request parameters.
Response
Response example
{
"data": {
"id": "388",
"type": "customReactions",
"attributes": {
"catalogVersion": 0,
"metadata": {},
"hidden": false,
Trellix Endpoint Detection and Response Product Guide 177

1| Trellix EDR APIs
"dbVersion": 0,
"description": "test Desc",
"timeout": 60,
"internalArguments": {},
"internalName": "_Test_Reaction",
"remediation": false,
"task": "REACTION",
"contents": [
{
"id": "10352",
"platform": {
"catalogVersion": 1100,
"dbVersion": 0,
"id": "1",
"name": "windows",
"topic": "/mcafee/mar/agent/query/windows",
"enabled": true
},
"capability": {
"catalogVersion": 1100,
"dbVersion": 0,
"id": "27",
"name": "Execute PowerShell Script",
"description": "Runs Windows PowerShell Scripts",
"module": "SystemRuntime",
"function": "executePS",
"contentEnabled": true,
"outputs": [],
"formatArgs": {
"hasHeaders": false,
"delimiter": ","
},
"format": "CSV",
"platforms": [
{
"catalogVersion": 1100,
"dbVersion": 0,
"id": "1",
"name": "windows",
"topic": "/mcafee/mar/agent/query/windows",
"enabled": true
}
],
"platformSettings": [
{
"id": "5142",
"platform": {
"catalogVersion": 1100,
"dbVersion": 0,
"id": "1",
"name": "windows",
"topic": "/mcafee/mar/agent/query/windows",
"enabled": true
},
"utf8Sensitive": false
}
],
"itemType": "CUSTOM",
"catalogItems": [
"COLLECTOR",
"REACTION"
]
},
"content": "test\r\n",
178 Trellix Endpoint Detection and Response Product Guide

1| Trellix EDR APIs
"arguments": [],
"utf8Sensitive": false
}
],
"availableForTrigger": true,
"name": "_Test_Reaction",
"arguments": [
{
"id": "2369",
"name": "test",
"type": "STRING",
"collectorMappings": [],
"optional": false
}
],
"availableOffline": false,
"chainedReactions": []
}
},
"jsonapi": {
"version": "1.0"
}
}
Response codes
Status Response Description
200 OK Your request was processed
successfully. The server has
returned the requested data.
400 Bad request The server couldn't understand
your request, likely due to a
syntax error or an invalid
parameter.
Patch Reaction
Overview
This endpoint updates an existing reaction. Provide a JSON payload with the required changes, such as script content,
arguments, or execution settings. Use this endpoint to modify and maintain reaction behavior without recreating it.
Trellix Endpoint Detection and Response Product Guide 179

1| Trellix EDR APIs
Authentication
Authentication type: Bearer Token, API Key.
You can create a token using client credentials obtained through the developer portal. The API Key (x-api-key) is provided in
your onboarding email or on the API Access Management page.
Path (or URL)
<HTTPS Method>
PATCH https://{Trellix EDR_gateway_URL}/edr/v2/reactions/{reaction-id}
Request
Request headers
Authorization: Bearer <your_bearer_token>
Content-Type: application/vnd.api+json
x-api-key: <your_api_key>
• Authorization: This header is used to authenticate your request. You need to replace <your_bearer_token> with the actual
token you generate.
• Content-Type: This header tells the server that the request body format is json:api. Even though this specific call has no
request body, the API requires this header.
• x-api-key: This is a custom header required by the Trellix API for authentication. You'll need to replace <your_api_key> with
the key from your onboarding email or the API Access Management page.
Request example
{
"data": {
"type": "reactions",
"attributes": {
"name": "Check_New_reaction",
"description": "Updating a new reaction",
"contents": [
{
"platform": {
"name": "windows"
},
"capability": {
"name": "Execute Powershell Script"
180 Trellix Endpoint Detection and Response Product Guide

1| Trellix EDR APIs
},
"content": ""
},
{
"platform": {
"name": "windows"
},
"capability": {
"name": "Execute Powershell Script"
},
"content": "ls"
},
{
"platform": {
"name": "windows"
},
"capability": {
"name": "Execute Powershell Script"
},
"content": "ls"
}
],
"arguments": [
{
"name": "ABC",
"type": "NUMBER"
}
],
"timeout": 60
}
}
}
Response codes
Status Response Description
204 OK Your request was processed
successfully. The server has
returned the requested data.
400 Bad request The server couldn't understand
your request, likely due to a
syntax error or an invalid
parameter.
Trellix Endpoint Detection and Response Product Guide 181

1| Trellix EDR APIs
Delete Reaction
Overview
This endpoint deletes a reaction using its unique identifier. The request does not require a payload and returns a success status
when completed. Use this endpoint to remove unused or obsolete reactions from the environment.
Authentication
Authentication type: Bearer Token, API Key.
You can create a token using client credentials obtained through the developer portal. The API Key (x-api-key) is provided in
your onboarding email or on the API Access Management page.
Path (or URL)
<HTTPS Method>
DELETE https://{Trellix EDR_gateway_URL}/edr/v2/reactions/{reaction-id}
Request
Request headers
Authorization: Bearer <your_bearer_token>
Content-Type: application/vnd.api+json
x-api-key: <your_api_key>
• Authorization: This header is used to authenticate your request. You need to replace <your_bearer_token> with the actual
token you generate.
• Content-Type: This header tells the server that the request body format is json:api. Even though this specific call has no
request body, the API requires this header.
• x-api-key: This is a custom header required by the Trellix API for authentication. You'll need to replace <your_api_key> with
the key from your onboarding email or the API Access Management page.
182 Trellix Endpoint Detection and Response Product Guide

1| Trellix EDR APIs
Response codes
| Status  | Response  |     | Description                 |
| ------- | --------- | --- | --------------------------- |
| 204     | OK        |     | Your request was processed  |
successfully. The server has
returned the requested data.
| 400  | Bad request  |     | The server couldn't understand  |
| ---- | ------------ | --- | ------------------------------- |
your request, likely due to a
syntax error or an invalid
parameter.
Trellix EDR API rate limits
 Note
Trellix APIs rate limit on the Trellix API gateway is 2500 calls/SKU quantity/day.
Rate limits
| API                | Method  | Rate limit (requests/seconds)  |     |
| ------------------ | ------- | ------------------------------ | --- |
| Investigations     | POST    | 10/3600                        |     |
|                    | GET     | 60/60                          |     |
| Investigations/id  | PATCH   | 10/3600                        |     |
|                    | GET     | 60/60                          |     |
|                    | DELETE  | 10/3600                        |     |
| Investigations/    | POST    | 10/60                          |     |
metadata
Trellix Endpoint Detection and Response Product Guide 183

1| Trellix EDR APIs
| API                      | Method  | Rate limit (requests/seconds)  |
| ------------------------ | ------- | ------------------------------ |
| Investigations/evidence  | GET     | 60/60                          |
| Searches/historical      | POST    | 10/60                          |
| Searches/realtime        | POST    | 6/60                           |
| Searches/queue-jobs      | GET     | 120/60                         |
| Searches/historical/     | GET     | 60/60                          |
results
| Searches/realtime/ | GET  | 60/60  |
| ------------------ | ---- | ------ |
results
| Remediation/host     | POST  | 10/60  |
| -------------------- | ----- | ------ |
| Remediation/search   | POST  | 10/60  |
| Remediation/actions  | GET   | 60/60  |
| Remediation/queue-   | GET   | 60/60  |
jobs
| Remediation/threat  | POST  | 10/60  |
| ------------------- | ----- | ------ |
| Remediation/global- | POST  | 10/60  |
threat
| Remediation/exclusions  | POST  | 10/60  |
| ----------------------- | ----- | ------ |
|                         | GET   | 60/60  |
| Remediation/            | GET   | 60/60  |
exclusions/id
|     | PATCH  | 10/60  |
| --- | ------ | ------ |
184 Trellix Endpoint Detection and Response Product Guide

1| Trellix EDR APIs
| API                    | Method  | Rate limit (requests/seconds)  |
| ---------------------- | ------- | ------------------------------ |
|                        | DELETE  | 10/60                          |
| Reactions              | GET     | 60/60                          |
|                        | POST    | 10/60                          |
| Reactions/id           | GET     | 60/60                          |
|                        | PATCH   | 10/60                          |
|                        | DELETE  | 10/60                          |
| Threats                | GET     | 60/60                          |
| Threats/id             | GET     | 60/60                          |
| Threats/affectedhosts  | GET     | 60/60                          |
| Threats/detections     | GET     | 60/60                          |
| Alerts                 | GET     | 60/60                          |
| activity-feed          | POST    | 200/60000                      |
|                        | GET     | 200/6000                       |
|                        | DELETE  | 200/60000                      |
| activity-feed/id       | GET     | 200/6000                       |
|                        | PATCH   | 200/60000                      |
|                        | DELETE  | 200/60000                      |
Trellix Endpoint Detection and Response Product Guide 185

COPYRIGHT
Copyright © 2026 Musarubra US LLC.
Trellix and FireEye are the trademarks or registered trademarks of Musarubra US LLC, FireEye Security Holdings US LLC, and their affiliates in the
US and /or other countries. Other names and brands are the property of these companies or may be claimed as the property of others.
