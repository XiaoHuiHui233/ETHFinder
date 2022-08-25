# ETHFinder

使用python 3.10开发的简易以太坊客户端，提供以太坊devp2p网络的基本实现，包括节点发现协议（v4/v5）、rlpx协议以及eth协议(63/64/65/66)。  
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

- [x] 节点发现协议v4
- [x] EIP-778: 以太坊节点记录(ENR)
- [x] ENR "eth" 条目
- [x] EIP-868: 节点发现协议v4的ENR扩展
- [x] EIP-1459: 通过DNS发现节点
- [x] EIP-2124: 用于链兼容性检查的分叉标识符
- [ ] 节点发现协议v5
- [x] rlpx协议
- [x] 以太坊线协议62
- [x] 以太坊线协议63
- [x] 以太坊线协议64
- [x] 以太坊线协议65
- [x] 以太坊线协议66

## 基本架构

![image](framework.png)

## 模块列表

`core` 核心控制代码，用于调度各个不同的模块。  
`eth` 核心以太坊控制模块，用于维护宏观层面下的以太坊协议的行为和消息。  
`eth.datatypes` 以太坊协议角度的数据结构代码，支持EIP-2718、EIP-2930、EIP-1559。  
`services` 核心服务代码，用于对外提供链上信息获取服务、uniswap解析服务等。  
`dnsdisc` DNS发现协议模块，根据EIP-1459规范实现对以太坊DNS服务的解析。  
`nodedisc` 节点发现协议模块，包括协议通信和DPT。  
`nodedisc.discv4` 节点发现协议v4代码，提供节点发现服务。  
`rlpx` rlpx协议模块，提供基于RLPx的基础网络通信接口。  
`rlpx.procotols` rlpx子协议代码，提供基于rlpx实现的高层协议实现，如以太坊线协议。  
`store` 数据持久化模块，提供简单可用的数据持久化，用于保存某些基础状态，简单但不高效。  
`tests` 测试模块，有一些单元测试用例。  
`trickmath` 提供用于计算uniswap的`魔幻`数学模块。  

## 作者

[XiaoHuiHui](https://github.com/XiaoHuiHui233)
