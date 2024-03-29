# Lookup DNS IP

获取你的出口 DNS IP 地址

## 原理

基本的原理是通过自定义 DNS 服务，使用户访问域名时的 DNS 查询请求到自定义 DNS 服务时，自定义 DNS 服务会正常对域名进行解析的同时，将请求来源 IP 记录下来，注意，这个 IP 其实就是你的出口最终的 IP 服务器，一般来说是这样的。

为了避免 DNS 缓存，所以我们会通过 302 将用户请求重定向到一个随机的子域名上，对这个子域名来做解析检测，在得到 IP 后再返回结果。

## 部署

特别需要注意，由于自定义 DNS 服务直接记录 UDP 请求的来源 IP，所以此服务无法部署在代理之后，这将导致请求都来自代理的 IP

我们不建议你使用 `ContainerImage` 进行部署，因为一般容器环境都会有多层网络和代理，但我们有一个自动维护的镜像文件:

```bash
docker pull ghcr.io/yinxulai/lookup-dns-ip:latest
```
