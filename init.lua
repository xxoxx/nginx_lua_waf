require 'config'
local match = string.match
local ngxmatch=ngx.re.match
local unescape=ngx.unescape_uri
local get_headers = ngx.req.get_headers
local optionIsOn = function (options) return options == "on" and true or false end
logpath = logdir 
rulepath = RulePath
UrlDeny = optionIsOn(UrlDeny)
PostCheck = optionIsOn(postMatch)
CookieCheck = optionIsOn(cookieMatch)
WhiteCheck = optionIsOn(whiteModule)
PathInfoFix = optionIsOn(PathInfoFix)
attacklog = optionIsOn(attacklog)
CCDeny = optionIsOn(CCDeny)
Redirect=optionIsOn(Redirect)
function getClientIp()
        IP = ngx.req.get_headers()["X-Real-IP"]
        if IP == nil then
                IP  = ngx.var.remote_addr 
        end
        if IP == nil then
                IP  = "unknown"
        end
        return IP
end
function write(logfile,msg)
    local fd = io.open(logfile,"ab")
    if fd == nil then return end
    fd:write(msg)
    fd:flush()
    fd:close()
end
function log(method,url,data,ruletag)
    if attacklog then
	    local post_data_log=''
	    local realIp = getClientIp()
	local request_url="http://"..ngx.var.host..ngx.var.request_uri
	local a_rule=ruletag
	local servername=ngx.var.server_name
    	local time=ngx.localtime()
	local receive_headers = ngx.req.get_headers()
	a_rule=string.gsub(a_rule,"\\","")
	if method== "POST" then
        if string.sub(receive_headers["content-type"],1,20) == "multipart/form-data;" then
	post_data_log="multipart/form-data"
	else
        post_data_log = ngx.req.get_body_data()
        end
        if post_data_log==nil then
		post_data_log=''
	end
	end
		    line = realIp.." ["..time.."] \""..method.." "..request_url.."\" \"".."post_data:"..post_data_log.."\"  \""..a_rule.."\"\n"
	    local filename = logpath..'/'..servername.."_"..ngx.today().."_sec.log"
        write(filename,line)
    end
end
------------------------------------规则读取函数-------------------------------------------------------------------
function read_rule(var)
    file = io.open(rulepath..'/'..var,"r")
    if file==nil then
    	return
    end
    t = {}
    for line in file:lines() do
        table.insert(t,line)
    end
    file:close()
    return(t)
end

urlrules=read_rule('url')
argsrules=read_rule('args')
uarules=read_rule('user-agent')
wturlrules=read_rule('whiteurl')
postrules=read_rule('post')
ckrules=read_rule('cookie')
extrules=read_rule('ext')


function say_html()
    if Redirect then
        ngx.header.content_type = "text/html"
        ngx.say(html)
        ngx.exit(200)
    end
end

function whiteurl()
    if WhiteCheck then
    	if wturlrules ~=nil then
            for _,rule in pairs(wturlrules) do
                if ngxmatch(ngx.var.request_uri,rule,"isjo") then
                    return true 
                 end
            end
        end
    end
    return false
end

function args()
    for _,rule in pairs(argsrules) do
        local args = ngx.req.get_uri_args()
        for key, val in pairs(args) do
            if type(val)=='table' then
                data=table.concat(val, " ")
            else
                data=val
            end
            if data and type(data) ~= "boolean" and rule ~="" and ngxmatch(unescape(data),rule,"isjo") then
				log('GET',ngx.var.host,"-",rule)
                say_html()
                return true
            end
        end
    end
    return false
end


function url()
    if UrlDeny then
        for _,rule in pairs(urlrules) do
            if rule ~="" and ngxmatch(ngx.var.request_uri,rule,"isjo") then
                log('GET',ngx.var.request_uri,"-",rule)
                say_html()
                return true
            end
        end
    end
    return false
end

function ua()
    local ua = ngx.var.http_user_agent
    if ua ~= nil then
	    for _,rule in pairs(uarules) do
	        if rule ~="" and ngxmatch(ua,rule,"isjo") then
	            log('UA',ngx.var.request_uri,"-",rule)
	            say_html()
	        return true
	        end
	    end
    end
    return false
end
function body(data)
    for _,rule in pairs(postrules) do
        if rule ~="" and ngxmatch(unescape(data),rule,"isjo") then
            log('POST',ngx.var.request_uri,data,rule)
            say_html()
            return true
        end
    end
    return false
end
function cookie()
    local ck = ngx.var.http_cookie
    if CookieCheck and ck then
        for _,rule in pairs(ckrules) do
            if rule ~="" and ngxmatch(ck,rule,"isjo") then
                log('Cookie',ngx.var.request_uri,"-",rule)
                say_html()
            return true
            end
        end
    end
    return false
end

function denycc()
    if CCDeny then
    	local uri=ngx.var.uri
        CCcount=tonumber(string.match(CCrate,'(.*)/'))
        CCseconds=tonumber(string.match(CCrate,'/(.*)'))
        local token = getClientIp()..uri
        local limit = ngx.shared.limit
        local req,_=limit:get(token)
        if req then
            if req > CCcount then
                 ngx.exit(503)
                return true
            else
                 limit:incr(token,1)
            end
        else
            limit:set(token,1,CCseconds)
        end
    end
    return false
end

function get_boundary()
    local header = get_headers()["content-type"]
    if not header then
        return nil
    end

    if type(header) == "table" then
        header = header[1]
    end

    local m = match(header, ";%s*boundary=\"([^\"]+)\"")
    if m then
        return m
    end

    return match(header, ";%s*boundary=([^\",;]+)")
end

function whiteip()
    if next(ipWhitelist) ~= nil then
        for _,ip in pairs(ipWhitelist) do
            if getClientIp()==ip then
                return true
            end
        end
    end
        return false
end

function blockip()
     if next(ipBlocklist) ~= nil then
         for _,ip in pairs(ipBlocklist) do
             if getClientIp()==ip then
                 ngx.exit(403)
                 return true
             end
         end
     end
         return false
end
function check_ext(filename)
if filename==nil then
return true
end
if filename=="" then
return true
end
if type(filename)~="string" then
return true
end
local check_have_ext,_,_,_=string.find(filename,'%.')
if check_have_ext==nil then
return true
end
local ext=filename:match(".+%.(%w*)$")
            for _,rule in pairs(extrules) do
                if rule ~="" and ngxmatch(ext,rule,"isjo") then
                    log('EXT_upload',ngx.var.request_uri,"-","file_name:"..ext.."--reg:"..rule)
                    say_html()
                return true
                end
            end
--var_dump(ext)
local t =explode(filename,'.')
for aa,vv in pairs(t) do
if aa ~=1 then
            for _,rule in pairs(extrules) do
                if rule ~="" and ngxmatch(vv,rule,"isjo") then
                    log('EXT_upload',ngx.var.request_uri,"-","file_name:"..vv.."--reg:"..rule)
                    say_html()
                return true
                end
            end

end
end
--var_dump(t)
--ngx.exit(200)

end




    function var_dump(data, max_level, prefix)   
        if type(prefix) ~= "string" then   
            prefix = ""  
        end   
        if type(data) ~= "table" then   
            dump_html(prefix .. tostring(data))   
        else  
            dump_html(data)   
            if max_level ~= 0 then   
                local prefix_next = prefix .. "    "  
                dump_html(prefix .. "{")   
                for k,v in pairs(data) do  
                    io.stdout:write(prefix_next .. k .. " = ")   
                    if type(v) ~= "table" or (type(max_level) == "number" and max_level <= 1) then   
                        dump_html(v)   
                    else  
                        if max_level == nil then   
                            var_dump(v, nil, prefix_next)   
                        else  
                            var_dump(v, max_level - 1, prefix_next)   
                        end   
                    end   
                end   
                dump_html(prefix .. "}")   
            end   
        end   
    end  


function dump_html(str)
    if Redirect then
        --ngx.header.content_type = "text/html"
        ngx.say(str)
    end
end


function explode ( _str,seperator )  
    local pos, arr = 0, {}  
        for st, sp in function() return string.find( _str, seperator, pos, true ) end do  
            table.insert( arr, string.sub( _str, pos, st-1 ) )  
            pos = sp + 1  
        end  
    table.insert( arr, string.sub( _str, pos ) )  
    return arr  
end 


function post_check()
local args = {}
local file_args = {}
local is_have_file_param = false
local receive_headers = ngx.req.get_headers()
local request_method = ngx.var.request_method
if request_method == "POST" then
ngx.req.read_body()
if string.sub(receive_headers["content-type"],1,20) == "multipart/form-data;" then--判断是否是multipart/form-data类型的表单
is_have_file_param = true
content_type = receive_headers["content-type"]
body_data = ngx.req.get_body_data()--body_data可是符合http协议的请求体，不是普通的字符串
--请求体的size大于nginx配置里的client_body_buffer_size，则会导致请求体被缓冲到磁盘临时文件里，client_body_buffer_size默认是8k或者16k
if not body_data then
  local datafile = ngx.req.get_body_file()
  if not datafile then
       error_code = 1
       error_msg = "no request body found"
  else
       local fh, err = io.open(datafile, "r")
  if not fh then
       error_code = 1
       error_msg = "failed to open " .. tostring(datafile) .. "for reading: " .. tostring(err)
  else
       fh:seek("set")
       body_data = fh:read("*a")
       fh:close()
  if body_data == "" then
       error_code = 1
       error_msg = "request body is empty"
  end
  end
  end
  end
if error_code==1 then
return true
end
local boundary = "--" .. string.sub(receive_headers["content-type"],31)
local body_data_table = explode(tostring(body_data),boundary)
local first_string = table.remove(body_data_table,1)
local last_string = table.remove(body_data_table)
for i,v in ipairs(body_data_table) do
    local start_pos,end_pos,capture,capture2 = string.find(v,'Content%-Disposition: form%-data; name="(.+)"; filename="(.-)"')
    if not start_pos then--普通参数
        local t = explode(v,"\r\n\r\n")
        local temp_param_name = string.sub(t[1],41,-2)
        body(temp_param_name)
	local temp_param_value = string.sub(t[2],1,-3)
        body(temp_param_value)
    else --文件类型的参数，capture是参数名称，capture2是文件名
        check_ext(capture2)
    end
end
else
local args_post = ngx.req.get_post_args()
    for _,rule in pairs(argsrules) do
    local args_post = ngx.req.get_post_args()
        for key, val in pairs(args_post) do
            if type(val)=='table' then
                data=table.concat(val, " ")
            else
                data=val
            end
            if data and type(data) ~= "boolean" and rule ~="" and ngxmatch(unescape(data),rule,"isjo") then
                                log('POST',ngx.var.host,"-",rule)
                say_html()
                return true
            end
        end
    end

end
end
return true
end
