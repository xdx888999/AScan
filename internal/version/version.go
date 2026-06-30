package version

// Version 会在发布构建时通过 -ldflags 注入；本地开发默认使用 dev。
var Version = "dev"
