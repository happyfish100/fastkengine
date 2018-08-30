
FastKEngine is a knowledge engine.

knowledge format:

[question]
  question1
  question2
  ...

[answer key1=value1 ...]
    the answer can be multi-lines

Note:
  condition in the answer is optional.

for example:

[question]
  如何|设置 生成 core-dump
  core-dump 设置 方法

[answer]
 1. ulimit -c 查看内核core dump文件的大小限制，输出为0表示不能生成core dump文件，此时需要进行如下设置：
 ulimit -c unlimited 

 [answer uname=Linux]
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

 [answer uname=Darwin]
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


[question]
  core-dump 位置|地方|哪儿

[answer]
 执行命令：

 [answer uname=Linux]
 @cmd@ sysctl kernel.core_pattern

 [answer uname=Darwin]
 @cmd@ sysctl kern.corefile

[answer]
  输出的是core dump文件位置

