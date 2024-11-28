# SRUN_auto_connector
# 此应用针对校园网场景设计，可以自动选择有线网或无线网进行登录
## 运行逻辑
### ping 百度，检查是否连接到互联网
#### 没有连接到互联网，检查网线是否插上
##### 网线已插，自动拨号
##### 网线未插，连wifi自动登录
#### 已连接到互联网，检测是否是宽带连接
##### 是宽带连接，什么都不做
##### 不是宽带连接，检查网线是否插上
###### 网线已插，断开有线网，自动拨号
###### 网线未插，什么都不做

## 依赖
#### selenium模块
#### ping3模块
#### flask模块

### 值得注意的地方
#### 1.程序需要手动加入开机启动
#### 2.不可以直接断开网络，宽带需要先在系统里断开连接再拔网线，无线网需要先注销再断开连接，否则srun系统中用户依然在线，无法登录
#### 3.wifi开关必须打开，否则无法联网

### 11.26 更新，添加日志部分，优化连接速度
