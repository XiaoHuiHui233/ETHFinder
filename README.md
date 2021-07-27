# ETHFinder

使用python 3.9开发的简易以太坊客户端，提供以太坊devp2p网络的基本实现，包括节点发现协议（v4/v5）、rlpx协议以及eth协议(63/64/65)。  
本项目在网络实现的基础上同时实现了对链上数据的爬取、分析。  

## 使用方法

运行以下指令安装所需依赖（建议配合虚拟环境，如virtualenv/conda）：  

```shell
pip install -r requirements.txt
```

运行以下指令开启服务：  

```shell
python3 main.py
```

## 协议列表

|协议|是否实现|
| :----: | :----: |
|DNS节点发现协议|✅|
|节点发现协议v4|✅|
|节点发现协议v5|❌|
|rlpx协议|✅|
|以太坊线协议62|✅|
|以太坊线协议63|✅|
|以太坊线协议64|✅|
|以太坊线协议65|✅|
|以太坊线协议66|❌|
|轻量以太坊协议|❌|

## TODO列表

|内容|是否完成|
| :----: | :----: |
|节点发现协议v5|❌|
|节点发现和rlpx协议解耦|❌|
|区块数据获取和解析解耦|❌|
|支持带有类型的transaction的解析|❌|
|支持以太坊线协议66|❌|
|london升级|❌|

## 基本架构

![image](framework.png)

## 模块列表

`core` 核心模块，用于解析并处理接收到的以太坊链上消息。  
`nodedisc` 节点发现协议模块，处理节点发现协议并维护DPT。  
`nodedisc.dnsdisc` DNS节点发现协议，根据EIP-1459规范实现对以太坊DNS服务的解析。  
`nodedisc.discv4` 节点发现协议v4，提供节点发现服务.  
`nodedisc.discv5` 节点发现协议v5，提供节点发现服务的升级.  
`rlpx` rlpx协议，提供基于RLPx的基础网络通信接口。  
`rlpx.procotols` rlpx子协议，提供基于rlpx实现的高层协议实现，如以太坊线协议。  
`trickmath` 提供用于计算uniswap balance的`魔幻`数学接口。  

## 作者

[XiaoHuiHui233](https://github.com/XiaoHuiHui233)