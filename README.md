
FastKEngine is a knowledge base engine.

```
knowledge base format:

[[question]]
  question1
  question2
  ...

[[answer key1=value1 ...]]
    the answer can be multi-lines

Note:
  the charset is UTF-8.

  multi questions correspond to one answer, question matchs success
  when all requred keywords of a question are matched.

  You should segment Chinese words manually.

  the conditions like "key1=value1 key2=value2" in the answer is optional,
  eg. [[answer]] for no additional condition.

  question keywords:
    * with a pipe line (|) for match any one of them, eg.
      core-dump location | position

    * keywords quoted within  [ and ] are optional keywords, [...] must be
      the last part of the question. eg.
      file size descending [list|show]

    * the English words with a minus sign (-) for a whole,
      eg. "core-dump" matchs "core dump", "coredump" and "core-dump", but NOT match "dump core".

for example:

[[question]]
  如何 生成 core-dump
  core-dump 设置

[[answer]]
 1. ulimit -c 查看内核core dump文件的大小限制，输出为0表示不能生成core dump文件，此时需要进行如下设置：
 ulimit -c unlimited 

 [[answer uname=Linux]]
 如果ulimit -c unlimited  执行失败，需要设置系统文件/etc/security/limits.conf，注释掉如下行即可：
  *   soft    core            0
  *   hard    core            100000

 2. 通过sysctl检查和设置内核参数：
 kernel.core_pattern: 生成的core dump文件名，最好包含全路径
 fs.suid_dumpable：设置为1或2

 检查命令：
 @cmd@ sysctl kernel.core_pattern fs.suid_dumpable

 设置命令：
 @cmd@ sudo sysctl -w kernel.core_pattern=/tmp/core.%p
 @cmd@ sudo sysctl -w fs.suid_dumpable=1

 [[answer uname=Darwin]]
 2. 通过sysctl检查和设置内核参数：
 kern.corefile: 生成的core dump文件名，最好包含全路径，例如：/cores/core.%P
 kern.coredump：设置为1
 kern.sugid_coredump：设置为1

 检查命令：
 @cmd@ sysctl kern.corefile kern.coredump kern.sugid_coredump

 设置命令：
 @cmd@ sudo sysctl -w kern.corefile=/cores/core.%P
 @cmd@ sudo sysctl -w kern.coredump=1
 @cmd@ sudo sysctl -w kern.sugid_coredump=1


[[question]]
  core-dump 位置

[[answer]]
 执行命令：

 [[answer uname=Linux]]
 @cmd@ sysctl kernel.core_pattern

 [[answer uname=Darwin]]
 @cmd@ sysctl kern.corefile

[[answer]]
  输出的是core dump文件位置


[[question]]
  时间 降序 文件|目录|显示

[[answer]]
 ls 带上参数-t即可，例如：
 @cmd@ ls -lt $filename


[[question]]
  时间 升序 文件|目录|显示

[[answer]]
 ls 带上参数-rt即可，例如：
 @cmd@ ls -lrt $filename

[[question]]
  文件 大小 降序 [显示]

[[answer]]
 ls 带上参数-S即可，例如：
 @cmd@ ls -lS $filename


[[question]]
  文件 大小 升序 [显示]

[[answer]]
 ls 带上参数-rS即可，例如：
 @cmd@ ls -lrS $filename

```

```
上述知识库示例中对应的近义词列表：

文件 文档 file
目录 directory dir
时间 日期 time date datetime
显示 展示 列举 列出 排列 list ls
降序 倒序 倒排 descending descend desc
升序 正序 顺序 ascending ascend asc
如何 怎样 how how-to
生成 产生 产出 形成 generate produce
大小 尺寸 size
位置 地方 哪儿 哪里 那儿 那里 position  location place
设置 设定 配置 set setting config configure configuration

```

```
重要提示：
  question中的关键字如果存在多个近义词，使用近义词列表的第一列（第一个词）。
```
