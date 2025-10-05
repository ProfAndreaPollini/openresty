local cjson = require("cjson")

local function require_without_global_warning(module_name)
    if module_name ~= "logging" then
        return pcall(require, module_name)
    end

    local globals_mt = getmetatable(_G)
    local original_newindex
    local original_version
    local version_overridden = false

    if globals_mt and type(globals_mt.__newindex) == "function" then
        original_newindex = globals_mt.__newindex
        globals_mt.__newindex = function(tbl, key, value)
            if key == "logging" then
                rawset(tbl, key, value)
                return value
            end
            return original_newindex(tbl, key, value)
        end
    end

    if _G._VERSION == "Lua 5.1" then
        original_version = _G._VERSION
        rawset(_G, "_VERSION", "Lua 5.2")
        version_overridden = true
    end

    local ok, result = pcall(require, module_name)

    if original_newindex then
        globals_mt.__newindex = original_newindex
    end

    if version_overridden and original_version then
        rawset(_G, "_VERSION", original_version)
    end

    return ok, result
end

-- Pre-load required modules to ensure they're available
local function preload_dependencies()
    -- Ensure all basic Lua modules are loaded
    require("io")
    require("os")
    require("string")
    require("table")
    require("math")

    -- Try to pre-load any logging-related modules
    require_without_global_warning("logging")
    pcall(require, "logging.console")
    pcall(require, "logging.file")
end

-- Load Casbin with comprehensive dependency management
local casbin_module = nil
local casbin_load_error = nil

local function get_casbin()
    if casbin_module then
        return true, casbin_module
    end

    if casbin_load_error then
        return false, casbin_load_error
    end

    -- Pre-load dependencies
    preload_dependencies()

    -- Store original global state
    local original_globals = {}
    for k, v in pairs(_G) do
        original_globals[k] = v
    end

    -- Load casbin
    local ok, result = pcall(require, "casbin")

    if ok then
        casbin_module = result

        -- Log any new globals created but don't remove them yet
        -- Casbin might need them for proper operation
        for k, v in pairs(_G) do
            if original_globals[k] == nil then
                ngx.log(ngx.DEBUG, "Casbin created global: ", k)
            end
        end

        local util = package.loaded["src.util.Util"]
        if util and type(util.printTable) == "function" and not util._safe_print_wrapper then
            local function safe_print_table(value)
                if type(value) == "table" then
                    local parts = {}
                    for key, entry in pairs(value) do
                        local prefix = ""
                        if type(key) == "string" then
                            prefix = key .. " = "
                        end
                        parts[#parts + 1] = prefix .. safe_print_table(entry)
                    end
                    return "{ " .. table.concat(parts, ", ") .. " }"
                end
                if type(value) == "boolean" then
                    return value and "true" or "false"
                end
                return tostring(value)
            end

            util.printTable = safe_print_table
            util._safe_print_wrapper = true
        end

        ngx.log(ngx.INFO, "Successfully loaded Casbin module")
        return true, result
    else
        casbin_load_error = result
        ngx.log(ngx.ERR, "Failed to load Casbin module: ", result)
        return false, result
    end
end

-- Enhanced enforcer creation with dependency injection
local function create_enforcer_safe(casbin_class, model_path, policy_path)
    local logging_module = package.loaded.logging
    if logging_module and not casbin_class.logging then
        casbin_class.logging = logging_module
    end

    local approaches = {
        function()
            return casbin_class:new(model_path, policy_path)
        end,
        function()
            local model = casbin_class:newModel(model_path)
            return casbin_class:new(model, policy_path)
        end,
        function()
            local model = casbin_class:newModel(model_path)
            local adapter = require("src.persist.file_adapter.FileAdapter"):new(policy_path)
            return casbin_class:new(model, adapter)
        end
    }

    for i, approach in ipairs(approaches) do
        local ok, result, extra = pcall(approach)
        if ok and result then
            ngx.log(ngx.INFO, "Successfully created Casbin enforcer using approach ", i)
            return result
        end

        local reason = extra or result or "nil result"
        ngx.log(ngx.DEBUG, "Enforcer creation approach ", i, " failed: ", tostring(reason))
    end

    return nil
end

-- ABAC (Attribute-Based Access Control) implementation
local function abac_check()
    -- Configuration paths
    local model_path = "/etc/nginx/conf/access_model.conf"
    local policy_path = "/etc/nginx/conf/access_rules.csv"

    -- Helper function to check file existence
    local function file_exists(path)
        local file = io.open(path, "r")
        if file then
            file:close()
            return true
        end
        return false
    end

    -- Verify configuration files exist
    if not file_exists(model_path) then
        ngx.log(ngx.ERR, "Cannot access model file: ", model_path)
        return ngx.exit(500)
    end

    if not file_exists(policy_path) then
        ngx.log(ngx.ERR, "Cannot access policy file: ", policy_path)
        return ngx.exit(500)
    end

    -- Extract user information (in production, parse from Proxy-Authorization header)
    local function extract_user_info()
        local auth_header = ngx.var.http_proxy_authorization
        local user_info = {
            name = "alice", -- Default for testing
            authenticated = false,
            group = "guest",
            role = "user"
        }

        if auth_header then
            -- Parse Basic auth: "Basic base64(username:password)"
            local auth_type, credentials = auth_header:match("^(%S+)%s+(.+)$")
            if auth_type and auth_type:lower() == "basic" then
                local decoded = ngx.decode_base64(credentials)
                if decoded then
                    local username, password = decoded:match("^([^:]+):(.*)$")
                    if username then
                        user_info.name = username
                        user_info.authenticated = true

                        -- Determine group based on username (in production, query from database/LDAP)
                        if username == "alice" or username == "admin" then
                            user_info.group = "admin"
                            user_info.role = "admin"
                        elseif username == "bob" then
                            user_info.group = "user"
                            user_info.role = "user"
                        elseif username:match("^dev_") then
                            user_info.group = "developer"
                            user_info.role = "developer"
                        end
                    end
                end
            end
        end

        return user_info
    end

    -- Extract environment/context information
    local function extract_environment_info()
        local client_ip = ngx.var.remote_addr or ngx.var.http_x_forwarded_for or "unknown"
        local current_time = os.date("%H")

        return {
            ip = client_ip,
            time = tonumber(current_time),
            day_of_week = os.date("%w"),
            user_agent = ngx.var.http_user_agent or "",
            connection_type = "proxy"
        }
    end

    -- Extract resource/object information
    local function extract_object_info()
        local destination_host = ngx.var.host or ngx.var.http_host

        if not destination_host then
            return nil
        end

        local sanitized_host = destination_host:gsub(":%d+$", "")

        return {
            domain = sanitized_host,
            full_host = destination_host,
            port = destination_host:match(":(%d+)$") or "443",
            protocol = ngx.var.scheme or "https"
        }
    end

    -- Simple ABAC fallback function
    local function simple_abac_check(user_info, obj_info, env_info)
        -- Implement your simple access control rules here
        -- For now, allow alice to access httpbin.io, and admin group to access anything
        if user_info.group == "admin" then
            return true
        end

        if user_info.name == "alice" and obj_info.domain == "httpbin.io" then
            return true
        end

        if user_info.group == "user" and obj_info.domain == "httpbin.io" then
            return true
        end

        return false
    end

    -- Load Casbin
    local ok, casbin_result = get_casbin()
    if not ok then
        ngx.log(ngx.ERR, "Failed to load Casbin library: ", casbin_result)

        -- Fall back to simple ABAC
        local user_info = extract_user_info()
        local obj_info = extract_object_info()
        local env_info = extract_environment_info()

        if not obj_info then
            ngx.log(ngx.ERR, "Could not determine destination host")
            return ngx.exit(400)
        end

        -- if simple_abac_check(user_info, obj_info, env_info) then
        --     ngx.log(ngx.INFO, "Access GRANTED by simple ABAC (Casbin unavailable)")
        --     return
        -- else
        --     ngx.log(ngx.WARN, "Access DENIED by simple ABAC (Casbin unavailable)")
        --     return ngx.exit(403)
        -- end
        return ngx.exit(510)
    end

    -- Create the request attributes table
    local user_info = extract_user_info()
    local env_info = extract_environment_info()
    local obj_info = extract_object_info()

    if not obj_info then
        ngx.log(ngx.ERR, "Could not determine destination host")
        return ngx.exit(400)
    end

    -- Create ABAC request structure
    local abac_request = {
        sub = user_info,
        obj = obj_info,
        act = "connect",
        env = env_info
    }

    ngx.log(ngx.INFO, "ABAC Request: ", cjson.encode(abac_request))

    -- Try to create Casbin enforcer with enhanced approach
    local casbin = casbin_result
    ngx.log(ngx.INFO, "Attempting to create Casbin enforcer with model: ", model_path, " and policy: ", policy_path)

    local enforcer = create_enforcer_safe(casbin, model_path, policy_path)

    if not enforcer then
        ngx.log(ngx.ERR, "Failed to create Casbin enforcer with all approaches, using simple ABAC")

        -- if simple_abac_check(user_info, obj_info, env_info) then
        --     ngx.log(ngx.INFO, "Access GRANTED by simple ABAC fallback")
        --     return
        -- else
        --     ngx.log(ngx.WARN, "Access DENIED by simple ABAC fallback")
        --     return ngx.exit(403)
        -- end
        return ngx.exit(510)
    end

    ngx.log(ngx.INFO, "Successfully created Casbin enforcer")

    -- Perform ABAC check with Casbin
    local enforce_ok, allowed_or_error = pcall(function()
        return enforcer:enforce(abac_request.sub, abac_request.obj, abac_request.act, abac_request.env)
    end)

    if not enforce_ok then
        ngx.log(ngx.ERR, "Error during Casbin ABAC enforce: ", allowed_or_error)

        -- Fall back to simple ABAC
        --
        return ngx.exit(510)
    end

    local allowed = allowed_or_error
    if not allowed then
        ngx.log(ngx.WARN, "Access DENIED by Casbin ABAC for user=", user_info.name,
            " group=", user_info.group, " to domain=", obj_info.domain,
            " from IP=", env_info.ip)
        return ngx.exit(403)
    end

    ngx.log(ngx.INFO, "Access GRANTED by Casbin ABAC for user=", user_info.name,
        " group=", user_info.group, " to domain=", obj_info.domain,
        " from IP=", env_info.ip)
end

-- Execute the ABAC check
abac_check()
