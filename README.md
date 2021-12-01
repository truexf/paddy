## paddy 简介  
paddy是一款单进程的独立运行的web server，基于golang的标准库net/http实现。   
paddy提供以下功能：  
* 直接配置http响应
* 目录文件服务器
* proxy_pass代理
* http反向代理
* 支持请求和响应插件   

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

### 插件管理  
paddy除了可以支持上述配置功能以外。如果需要非常个性化的处理，或希望减少流量转发而是直接处理请求，等等其他功能，则可以通过编写插件，然后将包含插件代码的整个代码完整编译部署。paddy插件提供最高的可控性。编写插件的方式： 编写支持插件接口的组件，并通过Paddy.RegisterPlugin注册即可。  
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



