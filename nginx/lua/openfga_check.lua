-- /etc/nginx/lua/openfga_check.lua

local httpc = require("resty.http")
local cjson = require("cjson")

-- In a real scenario, you would extract this from the 'Proxy-Authorization' header
local username = "alice" -- Hardcoded for this example

-- --- FIX STARTS HERE ---

-- 1. Use ngx.var.host to get the destination.
-- This variable is reliably available in the access phase for both CONNECT and standard HTTP requests.
local destination_host = ngx.var.host

if not destination_host then
    ngx.log(ngx.ERR, "Could not determine destination host from ngx.var.host.")
    return ngx.exit(400) -- Bad Request
end

-- 2. Sanitize the host: remove the port number if it exists (e.g., "httpbin.io:443" -> "httpbin.io")
-- This ensures we check against the pure domain in OpenFGA.
local sanitized_host = destination_host:gsub(":%d+$", "")

-- --- FIX ENDS HERE ---


-- 3. Prepare the request to OpenFGA using the sanitized host
local object = "domain:" .. sanitized_host

local openfga_host = "http://172.26.240.1:18080"
local store_id = "01K5Y4R832EZ1E2EK2P4DV2XKC" -- Replace with your actual store ID
local check_url = openfga_host .. "/stores/" .. store_id .. "/check"

local check_body = {
    tuple_key = {
        user = "user:" .. username,
        relation = "connect",
        object = object
    }
}

-- 4. Execute the API call
local http = httpc.new()
local res, err = http:request_uri(check_url, {
    method = "POST",
    headers = { ["Content-Type"] = "application/json" },
    body = cjson.encode(check_body)
})

-- Log the API call result for easier debugging
ngx.log(ngx.WARN, "OpenFGA check for user='", username, "' to object='", object, "'. Response: ",
    res and res.body or "nil")

if not res or res.status ~= 200 then
    ngx.log(ngx.ERR, "Error calling OpenFGA: ", err or (res and res.body))
    return ngx.exit(502) -- Bad Gateway
end

-- 5. Evaluate the response from OpenFGA
local response_body = cjson.decode(res.body)
if response_body.allowed ~= true then
    ngx.log(ngx.WARN, "Access DENIED by OpenFGA.")
    return ngx.exit(403) -- Forbidden
end

-- If allowed, the script finishes, and NGINX proceeds with the request.
ngx.log(ngx.WARN, "Access GRANTED by OpenFGA.")
