# K8s Admin - Kubernetes 管理平台

基于 Go + Gin 的轻量级 K8s Web 管理界面。

## 功能

- 📊 **Dashboard** - 集群概览、统计信息、事件
- 📦 **Pods** - 查看日志、容器状态
- 🚀 **Deployments** - 创建、扩缩容、编辑、删除
- 🗄️ **StatefulSets** - 查看管理
- ⚙️ **DaemonSets** - 查看管理
- 🌐 **Services** - 创建、删除
- 🚪 **Ingresses** - 查看管理
- 🔧 **ConfigMaps** - 创建、编辑、删除
- 🔐 **Secrets** - 查看删除
- 💾 **PVCs** - 查看存储
- 📝 **Jobs** - 查看
- ⏰ **CronJobs** - 查看管理
- 🖥️ **Nodes** - 节点信息
- 📋 **Events** - 集群事件

## 快速启动

```bash
# 编译
go build -o k8s-admin ./cmd/server

# 运行 (使用默认 ~/.kube/config)
./k8s-admin

# 指定 kubeconfig
./k8s-admin -kubeconfig=/path/to/config

# 指定端口
./k8s-admin -addr=:9000
```

然后打开浏览器访问 http://localhost:8080

## 项目结构

```
k8s-admin/
├── cmd/server/main.go      # 入口
├── internal/
│   ├── api/handlers/      # HTTP handlers
│   ├── k8s/               # K8s client 封装
│   └── ui/                # 前端页面
└── pkg/utils/             # 工具函数
```

## API 端点

所有 API 在 `/api/v1` 下：

| 资源 | 端点 |
|------|------|
| 集群信息 | GET /api/v1/cluster |
| Namespaces | GET /api/v1/namespaces |
| Nodes | GET /api/v1/nodes |
| Pods | GET /api/v1/pods, GET /api/v1/namespaces/:ns/pods |
| Deployments | GET/POST/PUT/DELETE /api/v1/namespaces/:ns/deployments |
| Services | GET/POST/PUT/DELETE /api/v1/namespaces/:ns/services |
| ConfigMaps | GET/POST/PUT/DELETE /api/v1/namespaces/:ns/configmaps |
| ... | |

## 依赖

- Go 1.18+
- Kubernetes 集群
- kubeconfig 文件
