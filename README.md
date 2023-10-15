# flb

## 环境依赖

```bash
ubuntu 20.04
最小内存 4G
```

## 升级内核

```bash
make upgrade-kernel
```

## 安装依赖包

```bash
make install-depends
```

## 安装工具包

```bash
make install-bpftool
make install-ftc
make install-golang
```

## 安装测试用工具包

```bash
make install-test-tools
```

## 编译

### 编译 eBPF & netlink

```bash
make subsys
```

### 编译 flb

```bash
make build
```

## 运行

```bash
make run
```

## 测试

### 部署测试网络

```bash
make -f Makefile.test.mk test-up
```

### 设置负载均衡策略

```bash
make -f Makefile.test.mk test-apply-lb
```

### 验证负载均衡效果

```bash
make -f Makefile.test.mk test
```

### 销毁测试网络

```bash
make -f Makefile.test.mk test-down
```

