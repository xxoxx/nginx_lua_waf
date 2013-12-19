local content_length=tonumber(ngx.req.get_headers()['content-length'])
local method=ngx.req.get_method()
if whiteip() then
return
end
if blockip() then
return
end
if denycc() then
return
end
if ngx.var.http_Acunetix_Aspect then
    ngx.exit(444)
end
if ngx.var.http_X_Scan_Memo then
    ngx.exit(444)
end
if whiteurl() then
return
end
ua()
url()
args()
cookie()
post_check()
