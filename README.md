## paddy 简介  
paddy是一款单进程的独立运行的web server，基于golang的标准库net/http实现。   
paddy提供以下功能：  
* 直接配置http响应
* 目录文件服务器（小文件采用LRU缓存，大文件采用sendfile零内存拷贝）
* proxy_pass代理
* http反向代理与负载均衡
* 支持HTTP请求和响应插件   
* TCP流量代理与负载均衡（支持零内存拷贝）
   
### 部署
#### 编译  
```
$ go build ./main/paddy.go
```
#### 运行  
```
$ ./paddy -configFile default.config
```
若不附带-configFile参数，则paddy默认从paddy执行程序文件所在目录查找并加载default.config  
#### 参数文件校验
```
$ ./paddy -t default.config
```
#### 热重启
热重启一般发生在修改配置之后需要使参数生效。  
```
$ kill -USR2 `cat paddy.pid`
```
   
### paddy配置文件
paddy配置文件基于json语法，支持双斜线开头的单行注释。配置格式请参考[默认配置文件](https://github.com/truexf/paddy/blob/master/default.config)   
paddy配置文件支持强大的"[json表达式](https://github.com/truexf/goutil/tree/master/jsonexp)"语法。  
paddy的location配置支持"正则表达式"和"jsonexp"两种方式。  通过在request_filter和response_filter中对请求和响应进行灵活的处理  
location配置中，优先级从高到低次序： 直接配置响应 > file_root > proxy_pass > backend   
   
### paddy的流量生命周期图  
![image](https://github.com/truexf/paddy/blob/master/lifetime.jpg)  
   
### 直接配置http响应  
可在location_regexp的request_filter和rewponse_filter，或location_jsonexp中直接写入http响应，json表达式变量$set_response=1表示直接响应。如：  
```
...
"location_regexp": [
			{
				"exp": "^\\/response_direct\\?.*",
				"response_filter": [
					[
						[
							// 表示直接响应
							["$set_response","=",1],
							// 设置响应的http status code = 200
							["$resp.status","=",200],
							// 设置响应的http body
							["$resp.body","=","response from {{$req.path}},{{$req_param.echo}}"]
						]
					]
				]
			}
            ...

```
   
### 目录文件服务器
paddy通过goutil.LRUFileCache以LRU策略执行文件缓存，并提供目录文件服务。配置目录文件的方式通过file_root参数进行，如下：  
```
...
"location_regexp": [			
			{
				"exp": "^/paddy/default\\.config$",
				// 返回本地目录 /tmp/paddy/default.config文件的内容
				"file_root": "/tmp"
			}
            ...
```
   
### proxy_pass
与nginx类似，proxy_pass指示一个url,服务器向该url请求获取响应，并响应给客户端。如下：  
```
...
"location_regexp": [
			{
				"exp": "^\\/proxy_pass.*",
				"proxy_pass": "http://192.168.0.1:80/real_path"
			}
...
```
   
### backend
backend主要用来支持paddy作为http反向代理。paddy预先定义后端服务器或服务器组，一个backend包含一组后端服务器地址，paddy支持对backend的多种负载策略：  
* roundrobin  轮询
* minpending  最低负载+轮询
* iphash 按客户端ip地址进行哈希分布
* uri_param 根据uri参数值进行哈希分布
* random 随机选择  
配置举例：   
```
...
"location_regexp": [
			{
				"exp": "^\\/backend.*",
				"backend": "login_server",
				// 负载策略
				"method": "roundrobin"
			}，
 ...
```
除了这上述负载策略以外， 可以通过json表达式(jsonexp)，以语义控制的方式选择后端服务器，达到非常灵活的负载能力。这也是"[json表达式](https://github.com/truexf/goutil/tree/master/jsonexp)"的强大之处，举例：
```
{
	"request_filter": [
		[
			// 如果url参数user_name是“bob,tom,franky”之一，则选择backend_engineer作为后端服务器
			["$req_param.user_name", "in", "bob,tom,franky"],
			[
				["$backend","=","backend_engineer"],
				["$break","=",1]
			]
		]，
		[
			// 如果url参数user_age > 18, 则选择向http://192.168.0.1/adult?{{params}}获取响应
			["$req_param.user_age", ">", 18],
			["$proxy_pass","=","http://192.168.0.1/adult?{{params}}"]
		]
	]
}
```
   
### http server插件管理  
paddy除了可以支持上述配置功能以外。如果需要非常个性化的处理，或希望减少流量转发而是直接处理请求，处理web socket...其他功能，则可以通过编写插件，然后将包含插件代码的整个代码完整编译部署。paddy插件提供最高的可控性。编写插件的方式： 编写支持插件接口的组件，并通过Paddy.RegisterPlugin注册即可。  
```
// 插件接口
type Plugin interface {
	// 唯一身份ID
	ID() string

	// 在http请求接收完成后介入
	// hijacked 是否劫持：true则必须实现respWriter写响应；false时不准向respWriter写响应，可以返回backend(此时框架直接去请求backend而不再走location匹配流程，否则框架执行location匹配)
	RequestHeaderCompleted(req *http.Request, respWriter http.ResponseWriter, context goutil.Context) (hijacked bool, proxyPass, backend string, err goutil.Error)

	// 框架在得到响应后，给客户端发送响应之前介入
	// hijacked 是否劫持：true则必须实现respWriter写响应；false时，不准向respWriter写响应，可以返回newResponse(此时框架以newResponse写响应，否则以originResponse写响应）
	ResponseHeaderCompleted(originResponse *http.Response, respWriter http.ResponseWriter, context goutil.Context) (hijacked bool, newResponse *http.Response, err goutil.Error)
}
```
   
### 宏与全局变量   
宏将在运行时被实际值替换，location的配置的proxy_pass参数支持如下宏：  
* {{backend}}  当前的backend，backend由一个或多个“服务器地址:端口”组成
* {{domain}} 当前请求url的host(domain:port)的domain部分
* {{port}} 当前请求url的host(domain:port)的port部分
* {{host}} 当前请求url的host(domain:port)
* {{uri}} 当前请求url\(http://domain:port/path?param1=xxx,...\)的/path?param1=xxx,...
* {{path}} 当前请求url\(http://domain:port/path?param1=xxx,...\)的/path
* {{params}} 当前请求url\(http://domain:port/path?param1=xxx,...\)的param1=xxx,...   
   
paddy的json表达式支持以下paddy专有jsonexp变量：   
* $proxy_pass  设置proxy_pass
* $backend  设置backend
* $file_root  设置file_root
* $set_response  设置set_response
  
以及paddy专有jsonexp对象：
* $req  当前http请求对象，支持属性:  ver,host,method,path,uri
* $req_param 当前http请求对象的url参数对象，可以通过.操作符读取或设置参数值，如 $req_param.arg1
* $req_header 当前http请求对象header对象，可以通过.操作符读取或设置header信息， 如 $req_header.content_type
* $resp 当前http响应对象，支持属性：status,body
* $resp_header 当前http响应对象的header对象，可用通过.操作符读取或设置header信息， 如\["$resp_header.Content_Encoding","=","gzip"\]    

### TCP流量代理与负载均衡    
paddy站在go-runtime这个巨人的肩膀上，支持内存零拷贝技术，尽可能减少流量转发带来的延迟以及降低负载。  
该功能通过upstream和tcp_server两个配置参数进行配置，[点击这里查看配置参考](https://github.com/truexf/paddy/blob/master/upstream.config)  




