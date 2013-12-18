local content_length=tonumber(ngx.req.get_headers()['content-length'])
--ngx.req.read_body()
local method=ngx.req.get_method()
whiteip()
blockip()
denycc()
if ngx.var.http_Acunetix_Aspect then
    ngx.exit(444)
end
if ngx.var.http_X_Scan_Memo then
    ngx.exit(444)
end
whiteurl()
ua()
url()
args()
cookie()
post_check()
