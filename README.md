把用户令牌换成服务令牌之后，换成别的受众也能用，权限还被原样继承：主体校验只比较字符串前缀，相似主体被放行；受众校验用后缀比较，子域受众命中；权限求并集而不是取交集，权限被扩大；请求未声明的权限默认继承全部原权限；代理链不检查重复主体，同一主体可重复出现；代理链长度用大于而不是大于等于，允许深度多一层；交换令牌不标单次使用，可反复兑换；交换令牌有效期沿用原令牌，长令牌换出长令牌；策略校验不检查是否允许扩大权限；批量交换复用受众，第二个请求沿用第一个请求的受众。测试必须断言受众精确匹配、权限只能收窄不能扩大、代理链长度受限、交换令牌只能单次使用。exchange/swap.py 是核心，tests/test_swap.py 15个红。要修的是：按上面的顺序把 10 个缺陷逐个修掉。

## 运行方式

在仓库根目录执行：

```powershell
python -m pytest tests -q
```

初始状态恰好是：

```text
15 failed
```

15 条失败必须全部是 NotImplementedError，不允许出现导入错误、收集错误或语法错误。修完之后应当是 15 passed。项目不需要安装，也不需要联网。

## 字段

| 字段 | 值 |
| --- | --- |
| 方向 | 安全 |
| 题型 | 漏洞检测与攻防 |
| 任务类型 | Bugfix |
| 技术栈 | Python 3, pytest |
| 外部依赖 | 无外部依赖 |

## 不可修改项

tests/test_swap.py 是验收测试，不可修改。不要通过删除测试、跳过测试、放宽断言、改测试数据或捕获异常来让结果变绿。唯一需要修改的实现文件是 src/exchange/swap.py；该文件里恰好有 8 个桩，全部以 NotImplementedError 开始。

## pyproject 布局

项目采用 src 布局。pyproject.toml 中的 pytest 配置是：

```toml
[tool.pytest.ini_options]
pythonpath = ["src"]
testpaths = ["tests"]
```

因此测试可以从 exchange.swap 导入，不需要先执行 pip install，也不需要设置 PYTHONPATH。不要在 tests 目录里再放一份实现，也不要通过修改导入路径绕过 src/exchange/swap.py。

## 令牌与交换契约

令牌是字典，包含以下字段：

| 字段 | 类型 | 含义 |
| --- | --- | --- |
| subject | str | 令牌主体 |
| audience | str 或 list[str] | 允许的受众，parse_token 统一为 list[str] |
| scopes | list[str] | 已授权权限 |
| chain | list[str] | 代理链，按发生顺序排列 |
| expires_at | int | 绝对过期时间，Unix 秒 |
| jti | str | 令牌唯一标识 |
| single_use | bool | 是否只能兑换一次，缺省为 False |

parse_token 返回独立副本，不修改入参。audience 字符串归一化为单元素列表；audience 和 scopes 去重但保持首次出现顺序。缺少必需字段、类型错误或空受众时抛出 ValueError。

交换请求包含以下字段：

| 字段 | 类型 | 含义 |
| --- | --- | --- |
| subject | str | 本次请求的主体 |
| audience | str | 本次请求的精确受众 |
| scopes | list[str]，可省略 | 希望保留的权限；省略或为空表示不保留任何权限 |
| chain | list[str]，可省略 | 新的代理链；省略时沿用源令牌的 chain |

策略是字典，包含以下字段：

| 字段 | 类型 | 含义 |
| --- | --- | --- |
| allow_scope_escalation | bool | 必须为 False |
| max_chain_depth | int | 代理链的排他上限，链长度必须严格小于它 |
| max_ttl | int | 交换令牌最长有效秒数 |
| require_single_use | bool | 必须为 True |
| now | int，可省略 | 测试用的当前时间；省略时使用系统时间 |
| consumed_jti | set 或 list，可省略 | 已兑换的 single_use 令牌标识；由 swap 维护 |

## 8 个接口

parse_token：把令牌解析成规范字典，校验基本类型并归一化 audience 与 scopes。

subject_ok：只有在请求主体与令牌 subject 完全相等，或与 chain 中某一项完全相等时才返回 True。禁止前缀比较，禁止模糊匹配。

audience_ok：只有请求受众与令牌 audience 中的某一项完全相等时才返回 True。禁止后缀比较，禁止把子域当成命中。

narrow_scopes：请求权限必须是原权限的子集。返回请求中的权限，保持顺序并去重；请求省略、为 None 或为空时返回空列表，不能继承全部原权限；出现原权限之外的权限时抛出 ValueError。

chain_ok：chain 必须是非空字符串列表，不能有重复主体。max_depth 是排他上限，只有 len(chain) < max_depth 才合法；因此 max_depth 为 2 时，长度为 1 的链合法，长度为 2 的链非法。

swap：先检查策略，再解析源令牌，然后依次校验源令牌未过期、主体、精确受众、权限收窄、代理链深度与重复主体。签发结果必须包含 subject、audience、scopes、chain、expires_at、ttl、issued_at、single_use 和 jti。audience 是单元素列表；single_use 必须为 True；jti 必须新生成。expires_at 取源令牌过期时间与 now 加 max_ttl 的较小值，ttl 等于 expires_at 减 now。若源令牌 single_use 为 True，第一次成功兑换后把其 jti 写入策略的 consumed_jti；同一个 jti 第二次进入 swap 必须抛出 ValueError。失败的兑换不得消耗令牌。所有拒绝都使用 ValueError。

validate_policy：返回问题字符串列表，安全策略返回空列表。至少识别三类问题：允许扩大权限、缺少或非正数的代理链上限、未要求单次使用。字符串内容不限，但必须让调用方能识别对应问题。

swap_batch：requests 是列表，每项形如 token 与 request 两个键。返回 results 列表并保持顺序。每个请求都必须使用自己的 audience、subject、scopes 和 chain，不能复用上一项的字段。任何非法项都抛出 ValueError。

## 安全不变量

受众必须精确匹配，不能因为后缀或子域而放行。权限只能收窄，不能通过并集、缺省继承或批量复用而扩大。代理链必须有上限且不能重复主体。交换令牌必须标记为单次使用，并且有效期不能超过策略上限或源令牌的剩余寿命。批量交换的每一项都必须独立，两个请求使用不同受众时，结果必须各自绑定自己的受众。

## 自检

从仓库根目录运行 python -m pytest tests -q。初始应看到恰好 15 failed，且每个失败都是 NotImplementedError。完成后应看到 15 passed。不要执行 git init，不要提交，不要 push，也不要访问网络。

## 字段表

| 字段 | 取值 |
| --- | --- |
| 所属领域 | 安全 |
| 子方向 | 漏洞检测与攻防 |
| 任务类型 | Bugfix |
| 语言/框架 | Python 3, pytest |
| 环境可复现等级 | 无外部依赖 |

